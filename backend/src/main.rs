// Balor backend
// Author: Eduard Gevorkyan (egevorky@arencloud.com)
// License: Apache 2.0

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Path, State},
    http::{HeaderName, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, get_service, post, put},
    Extension, Json, Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use parking_lot::RwLock;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::hash_map::DefaultHasher,
    collections::HashMap,
    hash::{Hash, Hasher},
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
#[serde(rename_all = "snake_case")]
enum StickyStrategy {
    Cookie,
    IpHash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct TlsConfig {
    cert_path: String,
    key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StickyConfig {
    strategy: StickyStrategy,
    #[serde(default)]
    cookie_name: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sticky: Option<StickyConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct ListenerPayload {
    name: String,
    listen: String,
    protocol: Protocol,
    upstreams: Vec<UpstreamPayload>,
    #[serde(default)]
    tls: Option<TlsPayload>,
    #[serde(default)]
    sticky: Option<StickyPayload>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StickyPayload {
    strategy: StickyStrategy,
    #[serde(default)]
    cookie_name: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ConfigStore {
    listeners: HashMap<Uuid, ListenerConfig>,
    #[serde(default)]
    users: HashMap<Uuid, UserRecord>,
}

struct AppContext {
    store: RwLock<ConfigStore>,
    supervisor: BalancerSupervisor,
    state_path: PathBuf,
    health: Arc<RwLock<HashMap<Uuid, bool>>>,
    admin_token: Option<String>,
    sessions: RwLock<HashMap<String, Session>>,
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Role {
    Admin,
    Operator,
    Viewer,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct UserRecord {
    id: Uuid,
    username: String,
    role: Role,
    password_hash: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct UserPayload {
    username: String,
    role: Role,
    password: String,
}

#[derive(Debug, Serialize)]
struct UserResponse {
    id: Uuid,
    username: String,
    role: Role,
}

#[derive(Debug, Serialize, Deserialize)]
struct LoginPayload {
    username: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    token: String,
    username: String,
    role: Role,
}

#[derive(Debug, Deserialize)]
struct LogoutPayload {
    token: String,
}

#[derive(Debug, Clone)]
struct Session {
    role: Role,
}

#[derive(Clone)]
struct AuthContext {
    role: Role,
}

#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("not found")]
    NotFound,
    #[error("bad input: {0}")]
    BadRequest(String),
    #[error("forbidden")]
    Forbidden,
    #[error("internal error")]
    Internal,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self {
            ApiError::NotFound => StatusCode::NOT_FOUND,
            ApiError::BadRequest(_) => StatusCode::BAD_REQUEST,
            ApiError::Forbidden => StatusCode::FORBIDDEN,
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
    let mut initial_store = load_store(&state_path).unwrap_or_default();
    ensure_bootstrap_admin(&mut initial_store);
    let health_map = Arc::new(RwLock::new(HashMap::new()));
    let supervisor = BalancerSupervisor {
        tasks: Arc::new(RwLock::new(HashMap::new())),
        health: health_map.clone(),
    };
    let admin_token = std::env::var("BALOR_ADMIN_TOKEN").ok();

    let state: AppState = Arc::new(AppContext {
        store: RwLock::new(initial_store),
        supervisor,
        state_path,
        health: health_map.clone(),
        admin_token,
        sessions: RwLock::new(HashMap::new()),
    });

    let admin_dist = resolve_admin_dist();
    let admin_index = admin_dist.join("index.html");

    hydrate_supervisor(state.clone()).await?;
    spawn_health_monitor(state.clone());

    let api = Router::new()
        .route("/health", get(health))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .merge(
            Router::new()
                .route("/stats", get(stats))
                .route("/listeners", post(create_listener).get(list_listeners))
                .route(
                    "/listeners/:id",
                    get(get_listener)
                        .put(update_listener)
                        .delete(delete_listener),
                )
                .route("/users", get(list_users).post(create_user))
                .route("/users/:id", put(update_user).delete(delete_user))
                .layer(middleware::from_fn_with_state(
                    state.clone(),
                    admin_auth_guard,
                ))
                .with_state(state.clone()),
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

async fn list_users(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<UserResponse>>, StatusCode> {
    require_admin(&ctx)?;
    let store = state.store.read();
    let users = store
        .users
        .values()
        .map(|u| UserResponse {
            id: u.id,
            username: u.username.clone(),
            role: u.role.clone(),
        })
        .collect();

    Ok(Json(users))
}

async fn create_user(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(payload): Json<UserPayload>,
) -> Result<Json<UserResponse>, StatusCode> {
    require_admin(&ctx)?;
    let mut store = state.store.write();

    if store.users.values().any(|u| u.username == payload.username) {
        return Err(StatusCode::CONFLICT);
    }

    let password_hash = hash_password(&payload.password).map_err(|_| StatusCode::BAD_REQUEST)?;
    let record = UserRecord {
        id: Uuid::new_v4(),
        username: payload.username.clone(),
        role: payload.role.clone(),
        password_hash,
    };

    store.users.insert(record.id, record.clone());
    drop(store);
    persist_store(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(UserResponse {
        id: record.id,
        username: record.username,
        role: record.role,
    }))
}

async fn update_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Extension(ctx): Extension<AuthContext>,
    Json(payload): Json<UserPayload>,
) -> Result<Json<UserResponse>, StatusCode> {
    require_admin(&ctx)?;
    {
        let mut store = state.store.write();
        let Some(record) = store.users.get_mut(&id) else {
            return Err(StatusCode::NOT_FOUND);
        };

        record.username = payload.username.clone();
        record.role = payload.role.clone();
        record.password_hash =
            hash_password(&payload.password).map_err(|_| StatusCode::BAD_REQUEST)?;
    }
    persist_store(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let store = state.store.read();
    let record = store.users.get(&id).unwrap();
    Ok(Json(UserResponse {
        id: record.id,
        username: record.username.clone(),
        role: record.role.clone(),
    }))
}

async fn delete_user(
    State(state): State<AppState>,
    Path(id): Path<Uuid>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<StatusCode, StatusCode> {
    require_admin(&ctx)?;
    {
        let mut store = state.store.write();
        if store.users.remove(&id).is_none() {
            return Err(StatusCode::NOT_FOUND);
        }
    }
    persist_store(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn login(
    State(state): State<AppState>,
    Json(payload): Json<LoginPayload>,
) -> Result<Json<LoginResponse>, StatusCode> {
    if let Some(admin_token) = state.admin_token.as_ref() {
        if payload.password == *admin_token {
            let token = generate_token();
            state
                .sessions
                .write()
                .insert(token.clone(), Session { role: Role::Admin });
            return Ok(Json(LoginResponse {
                token,
                username: "admin".into(),
                role: Role::Admin,
            }));
        }
    }

    let store = state.store.read();
    let Some(user) = store
        .users
        .values()
        .find(|u| u.username == payload.username)
    else {
        return Err(StatusCode::UNAUTHORIZED);
    };
    let username = user.username.clone();
    let role = user.role.clone();
    let password_hash = user.password_hash.clone();
    drop(store);

    if !verify_password(&payload.password, &password_hash).unwrap_or(false) {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let token = generate_token();
    state
        .sessions
        .write()
        .insert(token.clone(), Session { role: role.clone() });

    Ok(Json(LoginResponse {
        token,
        username,
        role,
    }))
}

async fn logout(State(state): State<AppState>, Json(body): Json<LogoutPayload>) -> StatusCode {
    state.sessions.write().remove(&body.token);
    StatusCode::NO_CONTENT
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
    Extension(ctx): Extension<AuthContext>,
    Json(payload): Json<ListenerPayload>,
) -> Result<Json<ListenerConfig>, ApiError> {
    require_operator(&ctx)?;
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
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<ListenerPayload>,
) -> Result<Json<ListenerConfig>, ApiError> {
    require_operator(&ctx)?;
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
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_operator(&ctx)?;
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
            sticky,
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

        let sticky = match (protocol.clone(), sticky) {
            (Protocol::Http, sticky @ Some(_)) => sticky.map(|s| s.into_config()).transpose()?,
            (Protocol::Http, None) => None,
            (Protocol::Tcp, Some(_)) => {
                return Err("Sticky sessions are only supported for HTTP listeners".into())
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
            sticky,
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

impl StickyPayload {
    fn into_config(self) -> Result<StickyConfig, String> {
        let cookie_name = self
            .cookie_name
            .filter(|s| !s.trim().is_empty())
            .or_else(|| Some("BALOR_STICKY".to_string()));

        Ok(StickyConfig {
            strategy: self.strategy,
            cookie_name,
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
    sticky: Option<StickyConfig>,
}

impl HttpProxyState {
    fn new(
        upstreams: Vec<Upstream>,
        health: Arc<RwLock<HashMap<Uuid, bool>>>,
        sticky: Option<StickyConfig>,
    ) -> Self {
        Self {
            upstreams: Arc::new(upstreams),
            position: Arc::new(AtomicUsize::new(0)),
            client: reqwest::Client::new(),
            health,
            sticky,
        }
    }

    fn next_upstream(&self, req: &Request<Body>, peer: &SocketAddr) -> Option<UpstreamSelection> {
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

        match &self.sticky {
            Some(StickyConfig {
                strategy: StickyStrategy::Cookie,
                cookie_name,
            }) => {
                if let Some(cookie_upstream) =
                    sticky_from_cookie(req, cookie_name.as_deref().unwrap_or("BALOR_STICKY"))
                {
                    if let Some(found) = enabled.iter().find(|u| u.id == cookie_upstream) {
                        return Some(UpstreamSelection {
                            upstream: found.clone(),
                            set_cookie: None,
                        });
                    }
                }

                let idx = self.position.fetch_add(1, Ordering::Relaxed) % enabled.len();
                let upstream = enabled
                    .get(idx)
                    .cloned()
                    .unwrap_or_else(|| enabled[0].clone());

                let name = cookie_name.as_deref().unwrap_or("BALOR_STICKY").to_string();
                let value = upstream.id.to_string();

                Some(UpstreamSelection {
                    upstream: upstream.clone(),
                    set_cookie: Some((name, value)),
                })
            }
            Some(StickyConfig {
                strategy: StickyStrategy::IpHash,
                ..
            }) => {
                let addr = peer.ip();
                let mut hasher = DefaultHasher::new();
                Hash::hash(&addr, &mut hasher);
                let idx = (hasher.finish() as usize) % enabled.len();
                enabled.get(idx).cloned().map(|u| UpstreamSelection {
                    upstream: u,
                    set_cookie: None,
                })
            }
            None => {
                let idx = self.position.fetch_add(1, Ordering::Relaxed) % enabled.len();
                enabled.get(idx).cloned().map(|u| UpstreamSelection {
                    upstream: u,
                    set_cookie: None,
                })
            }
        }
    }
}

async fn run_http_listener(
    config: ListenerConfig,
    cancel: CancellationToken,
    health: Arc<RwLock<HashMap<Uuid, bool>>>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config.listen.parse()?;
    let state = HttpProxyState::new(config.upstreams.clone(), health, config.sticky.clone());

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
            .serve(router.into_make_service_with_connect_info::<SocketAddr>());

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
        let server = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        );

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
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let selection = state
        .next_upstream(&request, &peer)
        .ok_or(StatusCode::BAD_GATEWAY)?;
    let upstream = selection.upstream;
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

    if let Some((name, value)) = selection.set_cookie {
        let cookie = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax");
        resp_builder = resp_builder.header(axum::http::header::SET_COOKIE, cookie);
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

#[derive(Clone)]
struct UpstreamSelection {
    upstream: Upstream,
    set_cookie: Option<(String, String)>,
}

fn sticky_from_cookie(req: &Request<Body>, name: &str) -> Option<Uuid> {
    let header = req.headers().get(axum::http::header::COOKIE)?;
    let Ok(cookie_str) = header.to_str() else {
        return None;
    };
    for part in cookie_str.split(';') {
        let trimmed = part.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            if k.trim() == name {
                return Uuid::parse_str(v.trim()).ok();
            }
        }
    }
    None
}

async fn admin_auth_guard(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response<Body>, StatusCode> {
    let token = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string());

    let Some(token) = token else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    let mut role = None;

    if let Some(expected) = state.admin_token.as_ref() {
        if &token == expected {
            role = Some(Role::Admin);
        }
    }

    if role.is_none() {
        if let Some(session) = state.sessions.read().get(&token).cloned() {
            role = Some(session.role);
        }
    }

    let Some(role) = role else {
        return Err(StatusCode::UNAUTHORIZED);
    };

    req.extensions_mut().insert(AuthContext { role });

    Ok(next.run(req).await)
}

fn require_admin(ctx: &AuthContext) -> Result<(), StatusCode> {
    if ctx.role == Role::Admin {
        Ok(())
    } else {
        Err(StatusCode::FORBIDDEN)
    }
}

fn require_operator(ctx: &AuthContext) -> Result<(), ApiError> {
    match ctx.role {
        Role::Admin | Role::Operator => Ok(()),
        Role::Viewer => Err(ApiError::Forbidden),
    }
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

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
}

fn verify_password(password: &str, hash: &str) -> Result<bool, argon2::password_hash::Error> {
    let parsed = PasswordHash::new(hash)?;
    Ok(Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok())
}

fn generate_token() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(48)
        .map(char::from)
        .collect()
}

fn ensure_bootstrap_admin(store: &mut ConfigStore) {
    if !store.users.is_empty() {
        return;
    }

    let password = std::env::var("BALOR_DEFAULT_ADMIN_PASSWORD").unwrap_or_else(|_| {
        warn!("BALOR_DEFAULT_ADMIN_PASSWORD not set; using insecure default 'admin'");
        "admin".to_string()
    });

    let hash = match hash_password(&password) {
        Ok(h) => h,
        Err(err) => {
            warn!("Failed to hash default admin password: {err}");
            return;
        }
    };

    let record = UserRecord {
        id: Uuid::new_v4(),
        username: "admin".to_string(),
        role: Role::Admin,
        password_hash: hash,
    };

    store.users.insert(record.id, record);
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
