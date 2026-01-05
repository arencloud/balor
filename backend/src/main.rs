// Balor backend
// Author: Eduard Gevorkyan (egevorky@arencloud.com)
// License: Apache 2.0

use axum::{
    body::{to_bytes, Body},
    extract::{Path, State},
    http::{HeaderName, Request, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, get_service, post},
    Json, Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::task::JoinSet;
use tokio::{
    io,
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time,
};
use tokio_util::sync::CancellationToken;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::{error, info, warn};
use uuid::Uuid;

const BODY_LIMIT: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Protocol {
    Http,
    Tcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsConfig {
    cert_path: String,
    key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Upstream {
    id: Uuid,
    name: String,
    address: String,
    enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    healthy: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListenerConfig {
    id: Uuid,
    name: String,
    listen: String,
    protocol: Protocol,
    upstreams: Vec<Upstream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct ListenerPayload {
    name: String,
    listen: String,
    protocol: Protocol,
    upstreams: Vec<UpstreamPayload>,
    #[serde(default)]
    tls: Option<TlsPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpstreamPayload {
    name: String,
    address: String,
    enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsPayload {
    cert_path: String,
    key_path: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ConfigStore {
    listeners: HashMap<Uuid, ListenerConfig>,
}

struct AppContext {
    store: RwLock<ConfigStore>,
    supervisor: BalancerSupervisor,
    state_path: PathBuf,
    health: Arc<RwLock<HashMap<Uuid, bool>>>,
}

type AppState = Arc<AppContext>;

#[derive(Clone)]
struct BalancerSupervisor {
    tasks: Arc<RwLock<HashMap<Uuid, BalancerHandle>>>,
    health: Arc<RwLock<HashMap<Uuid, bool>>>,
}

struct BalancerHandle {
    cancel: CancellationToken,
    join: JoinHandle<()>,
}

#[derive(Debug, Serialize)]
struct StatsResponse {
    listener_count: usize,
    active_runtimes: usize,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("bad input: {0}")]
    BadRequest(String),
    #[error("internal error")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let message = self.to_string();
        (status, Json(serde_json::json!({ "error": message }))).into_response()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let state_path = resolve_state_path();
    let initial_store = load_store(&state_path).unwrap_or_default();
    let health_map = Arc::new(RwLock::new(HashMap::new()));
    let supervisor = BalancerSupervisor {
        tasks: Arc::new(RwLock::new(HashMap::new())),
        health: health_map.clone(),
    };

    let state: AppState = Arc::new(AppContext {
        store: RwLock::new(initial_store),
        supervisor,
        state_path,
        health: health_map.clone(),
    });

    let admin_dist = resolve_admin_dist();
    let admin_index = admin_dist.join("index.html");

    hydrate_supervisor(state.clone()).await?;
    spawn_health_monitor(state.clone());

    let api = Router::new()
        .route("/health", get(health))
        .route("/stats", get(stats))
        .route("/listeners", post(create_listener).get(list_listeners))
        .route(
            "/listeners/:id",
            get(get_listener)
                .put(update_listener)
                .delete(delete_listener),
        )
        .with_state(state.clone());

    let assets_dir = admin_dist.join("assets");
    let static_files =
        ServeDir::new(&admin_dist).not_found_service(ServeFile::new(admin_index.clone()));

    let app = Router::new()
        .nest("/api", api)
        .nest_service(
            "/assets",
            get_service(ServeDir::new(assets_dir))
                .handle_error(|_err| async move { StatusCode::INTERNAL_SERVER_ERROR }),
        )
        .fallback_service(static_files)
        .layer(
            CorsLayer::new()
                .allow_headers(Any)
                .allow_methods(Any)
                .allow_origin(Any),
        )
        .layer(TraceLayer::new_for_http());

    let addr: SocketAddr = std::env::var("BALOR_HTTP_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()?;
    info!("Admin API listening on http://{}", addr);
    info!("Serving admin UI assets from {}", admin_dist.display());

    let listener = TcpListener::bind(addr).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let store = state.store.read();
    let response = StatsResponse {
        listener_count: store.listeners.len(),
        active_runtimes: state.supervisor.active_runtimes(),
    };
    Json(response)
}

async fn list_listeners(State(state): State<AppState>) -> Json<Vec<ListenerConfig>> {
    let store = state.store.read();
    let list = store
        .listeners
        .values()
        .cloned()
        .map(|cfg| with_health(&state, cfg))
        .collect();
    Json(list)
}

async fn get_listener(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ListenerConfig>, ApiError> {
    let store = state.store.read();
    let Some(listener) = store.listeners.get(&id) else {
        return Err(ApiError::NotFound);
    };
    Ok(Json(with_health(&state, listener.clone())))
}

#[axum::debug_handler]
async fn create_listener(
    State(state): State<AppState>,
    Json(payload): Json<ListenerPayload>,
) -> Result<Json<ListenerConfig>, ApiError> {
    let id = Uuid::new_v4();
    let config = payload.into_config(id).map_err(ApiError::BadRequest)?;
    state
        .supervisor
        .upsert(config.clone())
        .await
        .map_err(|_| ApiError::Internal)?;

    {
        let mut store = state.store.write();
        store.listeners.insert(id, config.clone());
    }
    persist_store(&state).map_err(|_| ApiError::Internal)?;
    Ok(Json(config))
}

#[axum::debug_handler]
async fn update_listener(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Json(payload): Json<ListenerPayload>,
) -> Result<Json<ListenerConfig>, ApiError> {
    let config = payload.into_config(id).map_err(ApiError::BadRequest)?;
    {
        let mut store = state.store.write();
        if !store.listeners.contains_key(&id) {
            return Err(ApiError::NotFound);
        }
        store.listeners.insert(id, config.clone());
    }

    state
        .supervisor
        .upsert(config.clone())
        .await
        .map_err(|_| ApiError::Internal)?;
    persist_store(&state).map_err(|_| ApiError::Internal)?;

    Ok(Json(config))
}

#[axum::debug_handler]
async fn delete_listener(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    {
        let mut store = state.store.write();
        if store.listeners.remove(&id).is_none() {
            return Err(ApiError::NotFound);
        }
    }
    state.supervisor.remove(&id).await;
    persist_store(&state).map_err(|_| ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

impl ListenerPayload {
    fn into_config(self, id: Uuid) -> Result<ListenerConfig, String> {
        let Self {
            name,
            listen,
            protocol,
            upstreams,
            tls,
        } = self;

        validate_listen(&listen)?;
        let upstreams = upstreams
            .into_iter()
            .map(|u| u.into_upstream())
            .collect::<Result<Vec<_>, _>>()?;

        let tls = match (protocol.clone(), tls) {
            (Protocol::Http, tls @ Some(_)) => tls.map(|t| t.into_config()).transpose()?,
            (Protocol::Http, None) => None,
            (Protocol::Tcp, Some(_)) => {
                return Err("TLS is only supported for HTTP listeners".into())
            }
            (Protocol::Tcp, None) => None,
        };

        if upstreams.is_empty() {
            return Err("at least one upstream is required".into());
        }

        Ok(ListenerConfig {
            id,
            name,
            listen,
            protocol,
            upstreams,
            tls,
        })
    }
}

impl UpstreamPayload {
    fn into_upstream(self) -> Result<Upstream, String> {
        if self.address.trim().is_empty() {
            return Err("upstream address cannot be empty".into());
        }

        Ok(Upstream {
            id: Uuid::new_v4(),
            name: self.name,
            address: self.address,
            enabled: self.enabled,
            healthy: None,
        })
    }
}

impl TlsPayload {
    fn into_config(self) -> Result<TlsConfig, String> {
        if self.cert_path.trim().is_empty() || self.key_path.trim().is_empty() {
            return Err("TLS cert and key paths are required when TLS is enabled".into());
        }

        Ok(TlsConfig {
            cert_path: self.cert_path,
            key_path: self.key_path,
        })
    }
}

fn validate_listen(listen: &str) -> Result<(), String> {
    listen
        .parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|e| format!("invalid listen address {listen}: {e}"))
}

impl BalancerSupervisor {
    async fn upsert(&self, config: ListenerConfig) -> anyhow::Result<()> {
        let id = config.id;
        self.remove(&config.id).await;
        let handle = spawn_listener(config, self.health.clone()).await?;
        self.tasks.write().insert(id, handle);
        Ok(())
    }

    async fn remove(&self, id: &Uuid) {
        let handle = {
            let mut tasks = self.tasks.write();
            tasks.remove(id)
        };

        if let Some(handle) = handle {
            handle.cancel.cancel();
            if let Err(err) = handle.join.await {
                warn!("runtime for listener {id} exited abruptly: {err}");
            }
        }
    }

    fn active_runtimes(&self) -> usize {
        self.tasks.read().len()
    }
}

async fn spawn_listener(
    config: ListenerConfig,
    health: Arc<RwLock<HashMap<Uuid, bool>>>,
) -> anyhow::Result<BalancerHandle> {
    let cancel = CancellationToken::new();
    let cancel_for_task = cancel.clone();
    let protocol_for_task = config.protocol.clone();
    let id = config.id;

    let join = tokio::spawn(async move {
        let result = match protocol_for_task {
            Protocol::Http => run_http_listener(config, cancel_for_task, health).await,
            Protocol::Tcp => run_tcp_listener(config, cancel_for_task, health).await,
        };

        if let Err(err) = result {
            error!("listener {id} terminated with error: {err:?}");
        }
    });

    Ok(BalancerHandle { cancel, join })
}

#[derive(Clone)]
struct HttpProxyState {
    upstreams: Arc<Vec<Upstream>>,
    position: Arc<AtomicUsize>,
    client: reqwest::Client,
    health: Arc<RwLock<HashMap<Uuid, bool>>>,
}

impl HttpProxyState {
    fn new(upstreams: Vec<Upstream>, health: Arc<RwLock<HashMap<Uuid, bool>>>) -> Self {
        Self {
            upstreams: Arc::new(upstreams),
            position: Arc::new(AtomicUsize::new(0)),
            client: reqwest::Client::new(),
            health,
        }
    }

    fn next_upstream(&self) -> Option<Upstream> {
        let health = self.health.read();
        let enabled: Vec<_> = self
            .upstreams
            .iter()
            .filter(|u| u.enabled && *health.get(&u.id).unwrap_or(&true))
            .cloned()
            .collect();
        if enabled.is_empty() {
            return None;
        }

        let idx = self.position.fetch_add(1, Ordering::Relaxed) % enabled.len();
        enabled.get(idx).cloned()
    }
}

async fn run_http_listener(
    config: ListenerConfig,
    cancel: CancellationToken,
    health: Arc<RwLock<HashMap<Uuid, bool>>>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config.listen.parse()?;
    let state = HttpProxyState::new(config.upstreams.clone(), health);

    let router = Router::new().fallback(proxy_http).with_state(state);
    info!(
        "Starting HTTP balancer '{}' on {} -> {} upstreams",
        config.name,
        listen_addr,
        config.upstreams.len()
    );

    if let Some(tls) = config.tls.clone() {
        let tls_config =
            RustlsConfig::from_pem_file(tls.cert_path.clone(), tls.key_path.clone()).await?;
        info!(
            "TLS enabled for '{}' using cert={} key={}",
            config.name, tls.cert_path, tls.key_path
        );
        let handle = Handle::new();
        let server = axum_server::bind_rustls(listen_addr, tls_config)
            .handle(handle.clone())
            .serve(router.into_make_service());

        tokio::select! {
            res = server => {
                res?;
            }
            _ = cancel.cancelled() => {
                info!("Shutting down HTTP listener {}", config.name);
                handle.graceful_shutdown(Some(Duration::from_secs(5)));
            }
        }
    } else {
        let listener = TcpListener::bind(listen_addr).await?;
        let server = axum::serve(listener, router.into_make_service());

        server
            .with_graceful_shutdown(async move {
                cancel.cancelled().await;
                info!("Shutting down HTTP listener {}", config.name);
            })
            .await?;
    }
    Ok(())
}

async fn run_tcp_listener(
    config: ListenerConfig,
    cancel: CancellationToken,
    health: Arc<RwLock<HashMap<Uuid, bool>>>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config.listen.parse()?;
    let upstreams: Arc<Vec<_>> =
        Arc::new(config.upstreams.into_iter().filter(|u| u.enabled).collect());
    let cursor = Arc::new(AtomicUsize::new(0));

    if upstreams.is_empty() {
        warn!("TCP listener {} has no active upstreams", config.name);
    } else {
        info!(
            "Starting TCP balancer '{}' on {} -> {} upstreams",
            config.name,
            listen_addr,
            upstreams.len()
        );
    }

    let listener = TcpListener::bind(listen_addr).await?;
    loop {
        let (mut inbound, peer) = tokio::select! {
            res = listener.accept() => res?,
            _ = cancel.cancelled() => {
                info!("Shutting down TCP listener {}", config.name);
                break;
            }
        };

        let Some(upstream) = pick_round_robin(&upstreams, &cursor, &health) else {
            warn!(
                "No enabled upstreams for {}, closing connection from {}",
                config.name, peer
            );
            continue;
        };

        tokio::spawn(async move {
            match TcpStream::connect(&upstream.address).await {
                Ok(mut outbound) => {
                    let _ = io::copy_bidirectional(&mut inbound, &mut outbound).await;
                }
                Err(err) => {
                    warn!("Failed to connect to {}: {}", upstream.address, err);
                }
            }
        });
    }
    Ok(())
}

fn pick_round_robin(
    upstreams: &Arc<Vec<Upstream>>,
    cursor: &Arc<AtomicUsize>,
    health: &Arc<RwLock<HashMap<Uuid, bool>>>,
) -> Option<Upstream> {
    let health_map = health.read();
    let active: Vec<_> = upstreams
        .iter()
        .filter(|u| *health_map.get(&u.id).unwrap_or(&true))
        .cloned()
        .collect();
    if active.is_empty() {
        return None;
    }
    let idx = cursor.fetch_add(1, Ordering::Relaxed) % active.len();
    active.get(idx).cloned()
}

async fn proxy_http(
    State(state): State<HttpProxyState>,
    request: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let upstream = state.next_upstream().ok_or(StatusCode::BAD_GATEWAY)?;
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let target_url = format!("{}{}", upstream.address, path);

    let (parts, body) = request.into_parts();
    let body_bytes = to_bytes(body, BODY_LIMIT)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut builder = state.client.request(parts.method.clone(), target_url);
    for (key, value) in parts.headers.iter() {
        if !is_hop_by_hop(key) {
            builder = builder.header(key, value);
        }
    }

    let response = builder
        .body(body_bytes)
        .send()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .bytes()
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut resp_builder = Response::builder().status(status);
    for (key, value) in headers.iter() {
        if !is_hop_by_hop(key) {
            resp_builder = resp_builder.header(key, value);
        }
    }

    resp_builder
        .body(Body::from(bytes))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn is_hop_by_hop(name: &HeaderName) -> bool {
    matches!(
        name.as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailers"
            | "transfer-encoding"
            | "upgrade"
    )
}

fn resolve_admin_dist() -> PathBuf {
    if let Ok(dist) = std::env::var("BALOR_ADMIN_DIST") {
        let path = PathBuf::from(dist);
        if let Ok(canon) = path.canonicalize() {
            return canon;
        }
        warn!(
            "BALOR_ADMIN_DIST='{}' not found, falling back to workspace default",
            path.display()
        );
    }

    let default = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../admin/dist")
        .canonicalize()
        .unwrap_or_else(|_| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../admin/dist"));

    if !default.exists() {
        warn!(
            "Default admin dist '{}' not found; UI assets may be missing",
            default.display()
        );
    }
    default
}

fn resolve_state_path() -> PathBuf {
    std::env::var("BALOR_STATE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data/balor_state.json"))
}

fn load_store(path: &PathBuf) -> Option<ConfigStore> {
    std::fs::read_to_string(path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

fn persist_store(state: &AppState) -> Result<(), std::io::Error> {
    let store = state.store.read();
    if let Some(parent) = state.state_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(&*store)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    std::fs::write(&state.state_path, json)?;
    Ok(())
}

async fn hydrate_supervisor(state: AppState) -> anyhow::Result<()> {
    let listeners: Vec<ListenerConfig> = {
        let store = state.store.read();
        store.listeners.values().cloned().collect()
    };

    let mut tasks = JoinSet::new();
    for listener in listeners {
        let sup = state.supervisor.clone();
        tasks.spawn(async move {
            if let Err(err) = sup.upsert(listener.clone()).await {
                warn!("failed to start listener {}: {err:?}", listener.name);
            }
        });
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

fn with_health(state: &AppState, mut cfg: ListenerConfig) -> ListenerConfig {
    let health = state.health.read();
    for upstream in cfg.upstreams.iter_mut() {
        upstream.healthy = Some(*health.get(&upstream.id).unwrap_or(&false));
    }
    cfg
}

fn spawn_health_monitor(state: AppState) {
    tokio::spawn(async move {
        let client = reqwest::Client::new();
        run_health_cycle(&state, &client).await;
        let mut interval = time::interval(Duration::from_secs(5));
        loop {
            interval.tick().await;
            run_health_cycle(&state, &client).await;
        }
    });
}

async fn run_health_cycle(state: &AppState, client: &reqwest::Client) {
    let listeners: Vec<ListenerConfig> = {
        let store = state.store.read();
        store.listeners.values().cloned().collect()
    };

    for listener in listeners {
        for upstream in listener.upstreams {
            let ok = match listener.protocol {
                Protocol::Http => check_http(client, &upstream.address).await,
                Protocol::Tcp => check_tcp(&upstream.address).await,
            };
            state.health.write().insert(upstream.id, ok);
        }
    }
}

async fn check_http(client: &reqwest::Client, url: &str) -> bool {
    let fut = client.get(url).timeout(Duration::from_secs(2)).send();
    match fut.await {
        Ok(resp) => resp.status().is_success(),
        Err(err) => {
            warn!("HTTP health check failed for {url}: {err}");
            false
        }
    }
}

async fn check_tcp(addr: &str) -> bool {
    match time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
        Ok(Ok(_)) => true,
        Ok(Err(err)) => {
            warn!("TCP health check failed for {addr}: {err}");
            false
        }
        Err(_) => {
            warn!("TCP health check timed out for {addr}");
            false
        }
    }
}
