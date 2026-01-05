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
};
use tokio::{
    io,
    net::{TcpListener, TcpStream},
    task::JoinHandle,
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
struct Upstream {
    id: Uuid,
    name: String,
    address: String,
    enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListenerConfig {
    id: Uuid,
    name: String,
    listen: String,
    protocol: Protocol,
    upstreams: Vec<Upstream>,
}

#[derive(Debug, Clone, Deserialize)]
struct ListenerPayload {
    name: String,
    listen: String,
    protocol: Protocol,
    upstreams: Vec<UpstreamPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpstreamPayload {
    name: String,
    address: String,
    enabled: bool,
}

#[derive(Debug, Clone, Default)]
struct ConfigStore {
    listeners: HashMap<Uuid, ListenerConfig>,
}

struct AppContext {
    store: RwLock<ConfigStore>,
    supervisor: BalancerSupervisor,
}

type AppState = Arc<AppContext>;

#[derive(Clone, Default)]
struct BalancerSupervisor {
    tasks: Arc<RwLock<HashMap<Uuid, BalancerHandle>>>,
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

    let state: AppState = Arc::new(AppContext {
        store: RwLock::new(ConfigStore::default()),
        supervisor: BalancerSupervisor::default(),
    });

    let admin_dist = resolve_admin_dist();
    let admin_index = admin_dist.join("index.html");

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
    Json(store.listeners.values().cloned().collect())
}

async fn get_listener(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
) -> Result<Json<ListenerConfig>, ApiError> {
    let store = state.store.read();
    let Some(listener) = store.listeners.get(&id) else {
        return Err(ApiError::NotFound);
    };
    Ok(Json(listener.clone()))
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

    let mut store = state.store.write();
    store.listeners.insert(id, config.clone());
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
    Ok(StatusCode::NO_CONTENT)
}

impl ListenerPayload {
    fn into_config(self, id: Uuid) -> Result<ListenerConfig, String> {
        let Self {
            name,
            listen,
            protocol,
            upstreams,
        } = self;

        validate_listen(&listen)?;
        let upstreams = upstreams
            .into_iter()
            .map(|u| u.into_upstream())
            .collect::<Result<Vec<_>, _>>()?;

        if upstreams.is_empty() {
            return Err("at least one upstream is required".into());
        }

        Ok(ListenerConfig {
            id,
            name,
            listen,
            protocol,
            upstreams,
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
        let handle = spawn_listener(config).await?;
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

async fn spawn_listener(config: ListenerConfig) -> anyhow::Result<BalancerHandle> {
    let cancel = CancellationToken::new();
    let cancel_for_task = cancel.clone();
    let protocol_for_task = config.protocol.clone();
    let id = config.id;

    let join = tokio::spawn(async move {
        let result = match protocol_for_task {
            Protocol::Http => run_http_listener(config, cancel_for_task).await,
            Protocol::Tcp => run_tcp_listener(config, cancel_for_task).await,
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
}

impl HttpProxyState {
    fn new(upstreams: Vec<Upstream>) -> Self {
        Self {
            upstreams: Arc::new(upstreams),
            position: Arc::new(AtomicUsize::new(0)),
            client: reqwest::Client::new(),
        }
    }

    fn next_upstream(&self) -> Option<Upstream> {
        let enabled: Vec<_> = self
            .upstreams
            .iter()
            .filter(|u| u.enabled)
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
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config.listen.parse()?;
    let state = HttpProxyState::new(config.upstreams.clone());

    let router = Router::new().fallback(proxy_http).with_state(state);
    info!(
        "Starting HTTP balancer '{}' on {} -> {} upstreams",
        config.name,
        listen_addr,
        config.upstreams.len()
    );

    let listener = TcpListener::bind(listen_addr).await?;
    let server = axum::serve(listener, router.into_make_service());

    server
        .with_graceful_shutdown(async move {
            cancel.cancelled().await;
            info!("Shutting down HTTP listener {}", config.name);
        })
        .await?;
    Ok(())
}

async fn run_tcp_listener(config: ListenerConfig, cancel: CancellationToken) -> anyhow::Result<()> {
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

        let Some(upstream) = pick_round_robin(&upstreams, &cursor) else {
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

fn pick_round_robin(upstreams: &Arc<Vec<Upstream>>, cursor: &Arc<AtomicUsize>) -> Option<Upstream> {
    if upstreams.is_empty() {
        return None;
    }
    let idx = cursor.fetch_add(1, Ordering::Relaxed) % upstreams.len();
    upstreams.get(idx).cloned()
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
