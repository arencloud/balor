// Balor backend
// Author: Eduard Gevorkyan (egevorky@arencloud.com)
// License: Apache 2.0

use acme_lib::{create_p384_key, persist::FilePersist, Directory, DirectoryUrl};
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    body::{to_bytes, Body},
    extract::{ConnectInfo, Path, State},
    http::HeaderValue,
    http::{header, HeaderName, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{delete, get, get_service, post, put},
    Extension, Json, Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::{SinkExt, StreamExt};
use hyper_util::rt::TokioIo;
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounterVec, Opts, Registry, TextEncoder,
};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rand_core::OsRng;
use rustls::crypto::ring::sign::any_supported_type;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;

use serde::{Deserialize, Serialize};
use sha1::{Digest, Sha1};
use std::{
    collections::hash_map::DefaultHasher,
    collections::{HashMap, VecDeque},
    fs::{File, OpenOptions},
    hash::{Hash, Hasher},
    io::Write,
    net::SocketAddr,
    path::{Path as FsPath, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use tokio::task::JoinSet;
use tokio::{
    fs, io,
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time,
};
use tokio_tungstenite::{connect_async, tungstenite::protocol::Role as WsRole, WebSocketStream};
use tokio_util::sync::CancellationToken;
use tower_http::{
    cors::{Any, CorsLayer},
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use tracing::{error, info, warn};
use tracing_subscriber::{
    layer::Context as TraceContext, layer::SubscriberExt, registry::LookupSpan,
    util::SubscriberInitExt, Layer,
};
use uuid::Uuid;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

const BODY_LIMIT: usize = 8 * 1024 * 1024;
fn default_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum AcmeChallenge {
    Http01,
    Dns01,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum DnsProvider {
    Cloudflare,
    Route53,
    Generic,
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
struct AcmeConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    directory_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cache_dir: Option<String>,
    #[serde(default = "default_acme_challenge")]
    challenge: AcmeChallenge,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
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
struct UpstreamPool {
    name: String,
    upstreams: Vec<Upstream>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ListenerConfig {
    id: Uuid,
    name: String,
    listen: String,
    protocol: Protocol,
    #[serde(default = "default_enabled")]
    enabled: bool,
    upstreams: Vec<Upstream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_routes: Option<Vec<HostRule>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<TlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sticky: Option<StickyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acme: Option<AcmeConfig>,
}

#[derive(Debug, Clone, Deserialize)]
struct ListenerPayload {
    name: String,
    listen: String,
    protocol: Protocol,
    #[serde(default = "default_enabled")]
    enabled: bool,
    upstreams: Vec<UpstreamPayload>,
    #[serde(default)]
    host_routes: Option<Vec<HostRulePayload>>,
    #[serde(default)]
    tls: Option<TlsPayload>,
    #[serde(default)]
    sticky: Option<StickyPayload>,
    #[serde(default)]
    acme: Option<AcmePayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpstreamPayload {
    name: String,
    address: String,
    enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct UpstreamPoolPayload {
    name: String,
    upstreams: Vec<UpstreamPayload>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostRulePayload {
    host: String,
    upstreams: Vec<UpstreamPayload>,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<TlsPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acme: Option<AcmePayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acme_status: Option<AcmeStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostRule {
    host: String,
    upstreams: Vec<Upstream>,
    #[serde(default = "default_enabled")]
    enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<TlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acme: Option<AcmeConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acme_status: Option<AcmeStatus>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AcmePayload {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    directory_url: Option<String>,
    #[serde(default)]
    cache_dir: Option<String>,
    #[serde(default = "AcmePayload::default_challenge")]
    challenge: AcmeChallenge,
    #[serde(default)]
    provider: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AcmeStatus {
    state: AcmeState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    not_after: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AcmeState {
    Pending,
    Issued,
    Failed,
}

impl AcmePayload {
    fn default_challenge() -> AcmeChallenge {
        AcmeChallenge::Http01
    }
}

fn default_acme_challenge() -> AcmeChallenge {
    AcmeChallenge::Http01
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AcmeProviderConfig {
    name: String,
    provider: DnsProvider,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    access_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    secret_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    zone: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    txt_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    api_base: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CertificateBundle {
    name: String,
    cert_path: String,
    key_path: String,
    #[serde(default = "default_cert_source")]
    source: String,
}

fn default_cert_source() -> String {
    "manual".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AcmeStandaloneJob {
    host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    acme: AcmeConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    status: Option<AcmeStatus>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<TlsConfig>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ConfigStore {
    #[serde(default)]
    admin_console: Option<AdminConsoleConfig>,
    listeners: HashMap<Uuid, ListenerConfig>,
    #[serde(default)]
    users: HashMap<Uuid, UserRecord>,
    #[serde(default)]
    acme_providers: Vec<AcmeProviderConfig>,
    #[serde(default)]
    acme_standalone: Vec<AcmeStandaloneJob>,
    #[serde(default)]
    certificates: Vec<CertificateBundle>,
    #[serde(default)]
    pools: Vec<UpstreamPool>,
}

struct AppContext {
    store: RwLock<ConfigStore>,
    supervisor: BalancerSupervisor,
    state_path: PathBuf,
    health: Arc<RwLock<HashMap<Uuid, bool>>>,
    admin_token: Option<String>,
    sessions: RwLock<HashMap<String, Session>>,
    metrics: Arc<Metrics>,
}

type AppState = Arc<AppContext>;

#[derive(Clone)]
struct BalancerSupervisor {
    tasks: Arc<RwLock<HashMap<Uuid, BalancerHandle>>>,
    health: Arc<RwLock<HashMap<Uuid, bool>>>,
    metrics: Arc<Metrics>,
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

#[derive(Clone)]
struct Metrics {
    registry: Registry,
    http_requests: IntCounterVec,
    http_latency: HistogramVec,
    tcp_connections: IntCounterVec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AdminConsoleConfig {
    #[serde(default = "default_admin_bind")]
    bind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<TlsConfig>,
}

fn default_admin_bind() -> String {
    "0.0.0.0:9443".to_string()
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
}

impl Metrics {
    fn new() -> Self {
        let registry = Registry::new();
        let http_requests = IntCounterVec::new(
            Opts::new("balor_http_requests_total", "HTTP requests per listener"),
            &["listener_id", "status"],
        )
        .expect("create http counter");
        let http_latency = HistogramVec::new(
            HistogramOpts::new(
                "balor_http_request_duration_seconds",
                "HTTP request duration per listener",
            )
            .buckets(vec![
                0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0,
            ]),
            &["listener_id"],
        )
        .expect("create latency histogram");
        let tcp_connections = IntCounterVec::new(
            Opts::new(
                "balor_tcp_connections_total",
                "TCP connections per listener",
            ),
            &["listener_id"],
        )
        .expect("create tcp counter");

        registry
            .register(Box::new(http_requests.clone()))
            .expect("register http counter");
        registry
            .register(Box::new(http_latency.clone()))
            .expect("register latency histogram");
        registry
            .register(Box::new(tcp_connections.clone()))
            .expect("register tcp counter");

        Self {
            registry,
            http_requests,
            http_latency,
            tcp_connections,
        }
    }

    fn observe_http(&self, listener: Uuid, status: StatusCode, latency: Duration) {
        let id = listener.to_string();
        self.http_requests
            .with_label_values(&[&id, status.as_str()])
            .inc();
        self.http_latency
            .with_label_values(&[&id])
            .observe(latency.as_secs_f64());
    }

    fn observe_tcp(&self, listener: Uuid) {
        let id = listener.to_string();
        self.tcp_connections.with_label_values(&[&id]).inc();
    }

    fn export(&self) -> Vec<u8> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        if encoder.encode(&metric_families, &mut buffer).is_err() {
            return b"# metrics encoding failed\n".to_vec();
        }
        buffer
    }
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

#[derive(Debug, Serialize, Deserialize)]
struct CertificatePayload {
    name: String,
    cert_pem: String,
    key_pem: String,
    #[serde(default = "default_cert_source")]
    source: String,
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

#[derive(Debug, Serialize)]
struct VersionResponse {
    api_version: String,
    ui_version: String,
    build: String,
}

#[derive(Debug, Serialize, Clone)]
struct LogEntry {
    timestamp: String,
    level: String,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    listener: Option<String>,
}

#[derive(Debug, Serialize)]
struct LogFileInfo {
    name: String,
    size: u64,
    modified: String,
}

const LOG_DIR: &str = "data/logs";
const LOG_BUFFER_CAP: usize = 1000;
const LOG_RETENTION_DAYS: i64 = 14;

static LOG_BUFFER: Lazy<RwLock<VecDeque<LogEntry>>> =
    Lazy::new(|| RwLock::new(VecDeque::with_capacity(LOG_BUFFER_CAP)));
static LOG_FILE: Lazy<Mutex<LogFileState>> = Lazy::new(|| Mutex::new(LogFileState::new()));

struct LogFileState {
    date: String,
    file: Option<File>,
}

impl LogFileState {
    fn new() -> Self {
        Self {
            date: String::new(),
            file: None,
        }
    }
}

fn append_log(entry: &LogEntry) {
    // In-memory buffer
    {
        let mut buf = LOG_BUFFER.write();
        buf.push_back(entry.clone());
        if buf.len() > LOG_BUFFER_CAP {
            buf.pop_front();
        }
    }

    // File append with daily rotation
    let today = Utc::now().format("%Y-%m-%d").to_string();
    let mut state = LOG_FILE.lock().unwrap();
    if state.date != today || state.file.is_none() {
        let _ = std::fs::create_dir_all(LOG_DIR);
        let path = FsPath::new(LOG_DIR).join(format!("balor-{today}.jsonl"));
        state.file = OpenOptions::new().create(true).append(true).open(path).ok();
        state.date = today.clone();
    }

    if let Some(file) = state.file.as_mut() {
        if let Ok(line) = serde_json::to_string(entry) {
            let _: std::io::Result<()> = writeln!(file, "{line}");
        }
    }
}

fn cleanup_old_logs() {
    if let Ok(entries) = std::fs::read_dir(LOG_DIR) {
        let cutoff = Utc::now() - ChronoDuration::days(LOG_RETENTION_DAYS);
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                if let Ok(modified) = meta.modified() {
                    if let Ok(time) = modified.duration_since(std::time::UNIX_EPOCH) {
                        if let Some(ts) = chrono::DateTime::<Utc>::from_timestamp(
                            time.as_secs() as i64,
                            time.subsec_nanos(),
                        ) {
                            if ts < cutoff {
                                let _ = std::fs::remove_file(entry.path());
                            }
                        }
                    }
                }
            }
        }
    }
}

struct LogCollectorLayer;

impl<S> Layer<S> for LogCollectorLayer
where
    S: tracing::Subscriber + for<'span> LookupSpan<'span>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: TraceContext<'_, S>) {
        let meta = event.metadata();
        let message = meta.name().to_string();
        let entry = LogEntry {
            timestamp: Utc::now().to_rfc3339(),
            level: meta.level().to_string(),
            message,
            target: Some(meta.target().to_string()),
            listener: None,
        };

        append_log(&entry);
    }
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
    if let Err(err) = rustls::crypto::ring::default_provider().install_default() {
        panic!("failed to install rustls crypto provider: {:?}", err);
    }

    cleanup_old_logs();

    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .with(LogCollectorLayer)
        .init();

    let state_path = resolve_state_path();
    let mut initial_store = load_store(&state_path).unwrap_or_default();
    ensure_bootstrap_admin(&mut initial_store);
    let health_map = Arc::new(RwLock::new(HashMap::new()));
    let metrics = Arc::new(Metrics::new());
    let supervisor = BalancerSupervisor {
        tasks: Arc::new(RwLock::new(HashMap::new())),
        health: health_map.clone(),
        metrics: metrics.clone(),
    };
    let admin_token = std::env::var("BALOR_ADMIN_TOKEN").ok();

    let state: AppState = Arc::new(AppContext {
        store: RwLock::new(initial_store),
        supervisor,
        state_path,
        health: health_map.clone(),
        admin_token,
        sessions: RwLock::new(HashMap::new()),
        metrics,
    });

    let admin_dist = resolve_admin_dist();
    let admin_index = admin_dist.join("index.html");

    hydrate_supervisor(state.clone()).await?;
    spawn_health_monitor(state.clone());
    spawn_acme_renewer(state.clone());

    let api = Router::new()
        .route("/health", get(health))
        .route("/version", get(version_info))
        .route("/login", post(login))
        .route("/logout", post(logout))
        .merge(
            Router::new()
                .route("/stats", get(stats))
                .route(
                    "/admin/console",
                    get(get_console_settings).put(update_console_settings),
                )
                .route("/logs", get(list_logs))
                .route("/logs/files", get(list_log_files))
                .route("/logs/files/:name", get(download_log_file))
                .route("/listeners", post(create_listener).get(list_listeners))
                .route(
                    "/listeners/:id",
                    get(get_listener)
                        .put(update_listener)
                        .delete(delete_listener),
                )
                .route("/users", get(list_users).post(create_user))
                .route("/users/:id", put(update_user).delete(delete_user))
                .route(
                    "/acme/providers",
                    get(list_acme_providers).post(upsert_acme_provider),
                )
                .route("/acme/providers/:name", delete(delete_acme_provider))
                .route("/acme/renew/:id", post(renew_acme_listener))
                .route("/acme/renew_all", post(renew_acme_all))
                .route("/acme/schedule", post(schedule_acme))
                .route("/acme/unschedule", post(unschedule_acme))
                .route("/acme/request", post(request_standalone_acme))
                .route("/acme/standalone", get(list_acme_standalone))
                .route("/acme/standalone/renew", post(renew_acme_standalone))
                .route("/acme/standalone/delete", post(delete_acme_standalone))
                .route("/pools", get(list_pools).post(upsert_pool))
                .route("/pools/:name", delete(delete_pool))
                .route("/certs", get(list_certs).post(upload_cert))
                .route("/certs/:name", get(get_cert).delete(delete_cert))
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
        .route("/metrics", get(metrics_handler))
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
        .layer(TraceLayer::new_for_http())
        .with_state(state.clone());

    let console_cfg = current_console_config(&state);
    let addr: SocketAddr = console_cfg.bind.parse()?;
    info!("Admin API listening on {}", addr);
    info!("Serving admin UI assets from {}", admin_dist.display());

    // If a console TLS config is stored, serve HTTPS; otherwise plain HTTP.
    if let Some(console_tls) = console_cfg.tls {
        info!("Admin console TLS enabled");
        let tls = load_rustls_config(&console_tls.cert_path, &console_tls.key_path).await?;
        axum_server::bind_rustls(addr, tls)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        let listener = TcpListener::bind(addr).await?;
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }
    Ok(())
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse { status: "ok" })
}

async fn metrics_handler(State(state): State<AppState>) -> Response<Body> {
    let body = state.metrics.export();
    let mut response = Response::new(Body::from(body));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        TextEncoder::new()
            .format_type()
            .parse()
            .unwrap_or_else(|_| header::HeaderValue::from_static("text/plain")),
    );
    response
}

async fn get_console_settings(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<AdminConsoleConfig>, StatusCode> {
    require_admin(&ctx)?;
    Ok(Json(current_console_config(&state)))
}

#[derive(Debug, Deserialize)]
struct ConsolePayload {
    bind: String,
    #[serde(default)]
    tls: Option<TlsPayload>,
}

#[derive(Debug, Deserialize)]
struct AcmeSchedulePayload {
    listener: Uuid,
    host: String,
    acme: AcmeConfig,
}

#[derive(Debug, Deserialize)]
struct AcmeUnschedulePayload {
    listener: Uuid,
    host: String,
}

#[derive(Debug, Deserialize)]
struct AcmeStandalonePayload {
    host: String,
    acme: AcmeConfig,
}

#[derive(Deserialize)]
struct AcmeStandaloneRenewPayload {
    host: String,
}

async fn update_console_settings(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(payload): Json<ConsolePayload>,
) -> Result<Json<AdminConsoleConfig>, ApiError> {
    require_admin(&ctx).map_err(|_| ApiError::Forbidden)?;
    let bind = payload.bind.trim();
    if bind.is_empty() {
        return Err(ApiError::BadRequest("bind address is required".into()));
    }
    bind.parse::<SocketAddr>()
        .map_err(|_| ApiError::BadRequest("invalid bind address".into()))?;

    let tls_cfg = match payload.tls {
        Some(tls) => Some(tls.into_config().map_err(ApiError::BadRequest)?),
        None => None,
    };

    let next = AdminConsoleConfig {
        bind: bind.to_string(),
        tls: tls_cfg,
    };

    {
        let mut store = state.store.write();
        store.admin_console = Some(next.clone());
    }
    persist_store(&state).map_err(|_| ApiError::Internal)?;
    Ok(Json(next))
}

async fn renew_acme_listener(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, ApiError> {
    require_admin(&ctx).map_err(|_| ApiError::Forbidden)?;
    ensure_acme_for_listener(state.clone(), id)
        .await
        .map_err(|_| ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn renew_acme_all(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<StatusCode, ApiError> {
    require_admin(&ctx).map_err(|_| ApiError::Forbidden)?;
    let listeners: Vec<Uuid> = {
        let store = state.store.read();
        store
            .listeners
            .iter()
            .filter_map(|(id, l)| {
                l.host_routes
                    .as_ref()
                    .map(|r| r.iter().any(|h| h.acme.is_some()))
                    .unwrap_or(false)
                    .then_some(*id)
            })
            .collect()
    };
    for id in listeners {
        if let Err(err) = ensure_acme_for_listener(state.clone(), id).await {
            warn!("ACME renew failed for {id}: {err:?}");
        }
    }
    Ok(StatusCode::NO_CONTENT)
}

async fn schedule_acme(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(payload): Json<AcmeSchedulePayload>,
) -> Result<StatusCode, ApiError> {
    require_admin(&ctx).map_err(|_| ApiError::Forbidden)?;

    {
        let store = state.store.read();
        validate_acme_config(&Some(payload.acme.clone()), &store).map_err(ApiError::BadRequest)?;
    }

    {
        let mut store = state.store.write();
        let listener = store
            .listeners
            .get_mut(&payload.listener)
            .ok_or(ApiError::NotFound)?;
        let routes = listener
            .host_routes
            .as_mut()
            .ok_or(ApiError::BadRequest("listener has no host routes".into()))?;
        if let Some(route) = routes.iter_mut().find(|r| r.host == payload.host) {
            route.acme = Some(payload.acme.clone());
        } else {
            return Err(ApiError::NotFound);
        }
    }

    persist_store(&state).map_err(|_| ApiError::Internal)?;
    ensure_acme_for_listener(state.clone(), payload.listener)
        .await
        .map_err(|_| ApiError::Internal)?;

    Ok(StatusCode::NO_CONTENT)
}

async fn unschedule_acme(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(payload): Json<AcmeUnschedulePayload>,
) -> Result<StatusCode, ApiError> {
    require_admin(&ctx).map_err(|_| ApiError::Forbidden)?;

    {
        let mut store = state.store.write();
        let listener = store
            .listeners
            .get_mut(&payload.listener)
            .ok_or(ApiError::NotFound)?;
        let routes = listener
            .host_routes
            .as_mut()
            .ok_or(ApiError::BadRequest("listener has no host routes".into()))?;
        if let Some(route) = routes.iter_mut().find(|r| r.host == payload.host) {
            route.acme = None;
            route.acme_status = None;
        } else {
            return Err(ApiError::NotFound);
        }
    }

    persist_store(&state).map_err(|_| ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn request_standalone_acme(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(payload): Json<AcmeStandalonePayload>,
) -> Result<StatusCode, ApiError> {
    info!(
        "ACME standalone request received for host {} (label {:?})",
        payload.host, payload.acme.label
    );
    require_admin(&ctx).map_err(|_| ApiError::Forbidden)?;
    validate_acme_config(&Some(payload.acme.clone()), &state.store.read())
        .map_err(ApiError::BadRequest)?;

    // Ensure a job entry exists before issuance so the UI can show it even if issuance fails.
    {
        let mut store = state.store.write();
        if let Some(job) = store.acme_standalone.iter_mut().find(|j| j.host == payload.host) {
            job.acme = payload.acme.clone();
            job.label = payload.acme.label.clone();
        } else {
            store.acme_standalone.push(AcmeStandaloneJob {
                host: payload.host.clone(),
                label: payload.acme.label.clone(),
                acme: payload.acme.clone(),
                status: Some(AcmeStatus {
                    state: AcmeState::Pending,
                    message: None,
                    not_after: None,
                }),
                tls: None,
            });
        }
    }
    persist_store(&state).map_err(|_| ApiError::Internal)?;

    // Kick off issuance asynchronously so we don't block the admin UI.
    let host = payload.host.clone();
    let acme = payload.acme.clone();
    tokio::spawn(async move {
        info!("ACME standalone issuance started for {host}");
        if let Err(err) = renew_standalone_job(state.clone(), host.clone(), Some(acme.clone())).await {
            warn!("Standalone ACME async job failed for {}: {err:?}", host);
        }
        info!("ACME standalone issuance finished for {}", host);
    });

    info!("ACME standalone request for {} acknowledged (202)", payload.host);
    Ok(StatusCode::ACCEPTED)
}

async fn list_acme_standalone(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<AcmeStandaloneJob>>, ApiError> {
    require_admin(&ctx).map_err(|_| ApiError::Forbidden)?;
    let store = state.store.read();
    Ok(Json(store.acme_standalone.clone()))
}

async fn renew_acme_standalone(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(payload): Json<AcmeStandaloneRenewPayload>,
) -> Result<StatusCode, ApiError> {
    require_admin(&ctx).map_err(|_| ApiError::Forbidden)?;
    match renew_standalone_job(state.clone(), payload.host.clone(), None).await {
        Ok(_) => Ok(StatusCode::NO_CONTENT),
        Err(err) => {
            warn!("Standalone ACME renew failed for {}: {err:?}", payload.host);
            Err(ApiError::Internal)
        }
    }
}

async fn delete_acme_standalone(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(payload): Json<AcmeStandaloneRenewPayload>,
) -> Result<StatusCode, ApiError> {
    require_admin(&ctx).map_err(|_| ApiError::Forbidden)?;
    let removed = {
        let mut store = state.store.write();
        let len = store.acme_standalone.len();
        store.acme_standalone.retain(|j| j.host != payload.host);
        store.acme_standalone.len() != len
    };
    if !removed {
        return Err(ApiError::NotFound);
    }
    persist_store(&state).map_err(|_| ApiError::Internal)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn renew_standalone_job(
    state: AppState,
    host: String,
    override_acme: Option<AcmeConfig>,
) -> anyhow::Result<()> {
    info!("ACME standalone renew/start for {}", host);
    let (acme_cfg, label) = {
        let store = state.store.read();
        if let Some(job) = store.acme_standalone.iter().find(|j| j.host == host) {
            (override_acme.unwrap_or_else(|| job.acme.clone()), job.label.clone())
        } else if let Some(acme) = override_acme.clone() {
            (acme, None)
        } else {
            return Err(anyhow::anyhow!("job not found"));
        }
    };

    let tls = obtain_cert(host.clone(), acme_cfg.clone(), state.clone()).await?;
    let not_after = cert_not_after(tls.cert_path.clone());
    let cert_name = label.unwrap_or_else(|| host.clone());
    register_certificate(&state, cert_name, &tls, "acme");
    {
        let mut store = state.store.write();
        if let Some(job) = store.acme_standalone.iter_mut().find(|j| j.host == host) {
            job.acme = acme_cfg.clone();
            job.tls = Some(tls.clone());
            job.status = Some(AcmeStatus {
                state: AcmeState::Issued,
                message: None,
                not_after,
            });
        } else {
            store.acme_standalone.push(AcmeStandaloneJob {
                host: host.clone(),
                label: None,
                acme: acme_cfg.clone(),
                status: Some(AcmeStatus {
                    state: AcmeState::Issued,
                    message: None,
                    not_after,
                }),
                tls: Some(tls.clone()),
            });
        }
    }
    persist_store(&state).map_err(|_| anyhow::anyhow!("persist failed"))?;
    info!("ACME standalone renew/start for {} completed", host);
    Ok(())
}

async fn stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let store = state.store.read();
    let response = StatsResponse {
        listener_count: store.listeners.len(),
        active_runtimes: state.supervisor.active_runtimes(),
    };
    Json(response)
}

async fn list_logs(
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<LogEntry>>, StatusCode> {
    require_admin(&ctx)?;
    let logs = LOG_BUFFER.read().iter().cloned().collect();
    Ok(Json(logs))
}

async fn list_log_files(
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<LogFileInfo>>, StatusCode> {
    require_admin(&ctx)?;
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(LOG_DIR) {
        for entry in entries.flatten() {
            if let Ok(meta) = entry.metadata() {
                let name = entry.file_name().to_string_lossy().to_string();
                let size = meta.len();
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|m| chrono::DateTime::<Utc>::from(m).to_rfc3339().into())
                    .unwrap_or_else(|| "-".into());
                files.push(LogFileInfo {
                    name,
                    size,
                    modified,
                });
            }
        }
    }
    files.sort_by(|a, b| b.modified.cmp(&a.modified));
    Ok(Json(files))
}

async fn download_log_file(
    Path(name): Path<String>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Response, StatusCode> {
    require_admin(&ctx)?;
    if name.contains('/') || name.contains("..") {
        return Err(StatusCode::BAD_REQUEST);
    }
    let path = FsPath::new(LOG_DIR).join(&name);
    let data = tokio::fs::read(&path)
        .await
        .map_err(|_| StatusCode::NOT_FOUND)?;
    let mut resp = Response::new(Body::from(data));
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    Ok(resp)
}

async fn version_info() -> Json<VersionResponse> {
    let api_version = env!("CARGO_PKG_VERSION").to_string();
    let ui_version = std::env::var("BALOR_UI_VERSION").unwrap_or_else(|_| api_version.clone());
    let build = std::env::var("BALOR_BUILD_ID").unwrap_or_else(|_| "dev".into());
    Json(VersionResponse {
        api_version,
        ui_version,
        build,
    })
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

async fn list_acme_providers(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<AcmeProviderConfig>>, StatusCode> {
    require_admin(&ctx)?;
    let store = state.store.read();
    Ok(Json(store.acme_providers.clone()))
}

async fn upsert_acme_provider(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(payload): Json<AcmeProviderConfig>,
) -> Result<Json<AcmeProviderConfig>, StatusCode> {
    require_admin(&ctx)?;
    if payload.name.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    {
        let mut store = state.store.write();
        if let Some(existing) = store
            .acme_providers
            .iter_mut()
            .find(|p| p.name == payload.name)
        {
            *existing = payload.clone();
        } else {
            store.acme_providers.push(payload.clone());
        }
    }
    persist_store(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(payload))
}

async fn delete_acme_provider(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    require_admin(&ctx)?;
    {
        let mut store = state.store.write();
        let len_before = store.acme_providers.len();
        store.acme_providers.retain(|p| p.name != name);
        if store.acme_providers.len() == len_before {
            return Err(StatusCode::NOT_FOUND);
        }
    }
    persist_store(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_pools(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<UpstreamPool>>, StatusCode> {
    require_admin(&ctx)?;
    let store = state.store.read();
    Ok(Json(store.pools.clone()))
}

async fn upsert_pool(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(payload): Json<UpstreamPoolPayload>,
) -> Result<Json<UpstreamPool>, StatusCode> {
    require_admin(&ctx)?;
    if payload.name.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let upstreams = payload
        .upstreams
        .clone()
        .into_iter()
        .map(|u| u.into_upstream())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if upstreams.is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let pool = UpstreamPool {
        name: payload.name.clone(),
        upstreams,
    };
    {
        let mut store = state.store.write();
        if let Some(existing) = store.pools.iter_mut().find(|p| p.name == payload.name) {
            *existing = pool.clone();
        } else {
            store.pools.push(pool.clone());
        }
    }
    persist_store(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(pool))
}

async fn delete_pool(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    require_admin(&ctx)?;
    {
        let mut store = state.store.write();
        let before = store.pools.len();
        store.pools.retain(|p| p.name != name);
        if before == store.pools.len() {
            return Err(StatusCode::NOT_FOUND);
        }
    }
    persist_store(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

async fn list_certs(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
) -> Result<Json<Vec<CertificateBundle>>, StatusCode> {
    require_admin(&ctx)?;
    let store = state.store.read();
    Ok(Json(store.certificates.clone()))
}

async fn upload_cert(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Json(payload): Json<CertificatePayload>,
) -> Result<Json<CertificateBundle>, StatusCode> {
    require_admin(&ctx)?;
    if payload.name.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let dir = std::env::var("BALOR_CERT_DIR").unwrap_or_else(|_| "data/certs".to_string());
    fs::create_dir_all(&dir)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let cert_path = format!("{}/{}.crt", dir, payload.name);
    let key_path = format!("{}/{}.key", dir, payload.name);
    fs::write(&cert_path, payload.cert_pem.as_bytes())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    fs::write(&key_path, payload.key_pem.as_bytes())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let bundle = CertificateBundle {
        name: payload.name.clone(),
        cert_path: cert_path.clone(),
        key_path: key_path.clone(),
        source: payload.source.clone(),
    };

    {
        let mut store = state.store.write();
        if let Some(existing) = store
            .certificates
            .iter_mut()
            .find(|c| c.name == payload.name)
        {
            *existing = bundle.clone();
        } else {
            store.certificates.push(bundle.clone());
        }
    }
    persist_store(&state).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(Json(bundle))
}

async fn get_cert(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(name): Path<String>,
) -> Result<Json<CertificatePayload>, StatusCode> {
    require_admin(&ctx)?;
    let bundle = {
        let store = state.store.read();
        let Some(bundle) = store.certificates.iter().find(|c| c.name == name) else {
            return Err(StatusCode::NOT_FOUND);
        };
        bundle.clone()
    };
    let cert_pem = fs::read_to_string(&bundle.cert_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let key_pem = fs::read_to_string(&bundle.key_path)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(CertificatePayload {
        name: bundle.name.clone(),
        cert_pem,
        key_pem,
        source: bundle.source.clone(),
    }))
}

async fn delete_cert(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    require_admin(&ctx)?;
    let removed_paths: Option<(String, String)> = {
        let mut store = state.store.write();
        if let Some(pos) = store.certificates.iter().position(|c| c.name == name) {
            let bundle = store.certificates.remove(pos);
            Some((bundle.cert_path, bundle.key_path))
        } else {
            None
        }
    };

    let Some((cert, key)) = removed_paths else {
        return Err(StatusCode::NOT_FOUND);
    };
    let _ = fs::remove_file(cert).await;
    let _ = fs::remove_file(key).await;
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
    let config = {
        let store_snapshot = state.store.read();
        payload
            .into_config(id, &store_snapshot)
            .map_err(ApiError::BadRequest)?
    };
    {
        let store = state.store.read();
        validate_acme_config(&config.acme, &store).map_err(ApiError::BadRequest)?;
    }
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
    trigger_acme_automation(state.clone(), id);
    Ok(Json(config))
}

fn trigger_acme_automation(state: AppState, listener_id: Uuid) {
    tokio::spawn(async move {
        if let Err(err) = ensure_acme_for_listener(state.clone(), listener_id).await {
            warn!("ACME automation for listener {listener_id} failed: {err:?}");
        }
    });
}

#[axum::debug_handler]
async fn update_listener(
    State(state): State<AppState>,
    Extension(ctx): Extension<AuthContext>,
    Path(id): Path<Uuid>,
    Json(payload): Json<ListenerPayload>,
) -> Result<Json<ListenerConfig>, ApiError> {
    require_operator(&ctx)?;
    let config = {
        let store_snapshot = state.store.read();
        payload
            .into_config(id, &store_snapshot)
            .map_err(ApiError::BadRequest)?
    };
    {
        let store = state.store.read();
        validate_acme_config(&config.acme, &store).map_err(ApiError::BadRequest)?;
    }
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
    trigger_acme_automation(state.clone(), id);

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
    fn into_config(self, id: Uuid, store: &ConfigStore) -> Result<ListenerConfig, String> {
        let Self {
            name,
            listen,
            protocol,
            enabled,
            upstreams,
            host_routes,
            tls,
            sticky,
            acme,
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

        let acme = match (protocol.clone(), acme) {
            (Protocol::Http, acme @ Some(_)) => acme.map(|a| a.into_config()).transpose()?,
            (Protocol::Http, None) => None,
            (Protocol::Tcp, Some(_)) => {
                return Err("ACME automation is only supported for HTTP listeners".into())
            }
            (Protocol::Tcp, None) => None,
        };

        if tls.is_some() && acme.is_some() {
            return Err("TLS paths and ACME cannot both be set; choose one".into());
        }

        let mut upstreams = if protocol == Protocol::Http {
            upstreams
                .into_iter()
                .map(|mut u| {
                    u.address = ensure_http_scheme(&u.address);
                    u
                })
                .collect()
        } else {
            upstreams
        };

        let host_routes = if protocol == Protocol::Http {
            host_routes
                .map(|routes| {
                    routes
                        .into_iter()
                        .map(|r| r.into_config(store))
                        .collect::<Result<Vec<_>, _>>()
                })
                .transpose()?
        } else {
            None
        };

        if protocol == Protocol::Tcp && upstreams.is_empty() {
            return Err("at least one upstream is required".into());
        }
        if protocol == Protocol::Http {
            let has_routes = host_routes.as_ref().map_or(false, |r| !r.is_empty());
            if !has_routes && upstreams.is_empty() {
                return Err("at least one host route or fallback upstream is required".into());
            }
            if has_routes {
                // Prefer host-routes only; clear fallback upstreams to avoid duplicate health checks.
                upstreams = Vec::new();
            }
        }

        Ok(ListenerConfig {
            id,
            name,
            listen,
            protocol,
            enabled,
            upstreams,
            host_routes,
            tls,
            sticky,
            acme,
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

impl HostRulePayload {
    fn into_config(self, store: &ConfigStore) -> Result<HostRule, String> {
        let Self {
            host,
            upstreams,
            enabled,
            pool,
            tls,
            acme,
            ..
        } = self;
        if host.trim().is_empty() {
            return Err("host value cannot be empty".into());
        }
        let mut upstreams = upstreams
            .into_iter()
            .map(|u| {
                let mut upstream = u.into_upstream()?;
                upstream.address = ensure_http_scheme(&upstream.address);
                Ok(upstream)
            })
            .collect::<Result<Vec<_>, String>>()?;
        if upstreams.is_empty() {
            if let Some(pool_name) = &pool {
                if let Some(pool) = store.pools.iter().find(|p| p.name == *pool_name) {
                    upstreams.extend(pool.upstreams.clone());
                }
            }
        }
        if upstreams.is_empty() && enabled {
            return Err("host route must include at least one upstream or pool".into());
        }
        Ok(HostRule {
            host: host.to_lowercase(),
            upstreams,
            enabled,
            pool: pool.clone(),
            tls: tls.map(|t| t.into_config()).transpose()?,
            acme: acme.map(|a| a.into_config()).transpose()?,
            acme_status: None,
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

impl AcmePayload {
    fn into_config(self) -> Result<AcmeConfig, String> {
        if self.challenge == AcmeChallenge::Dns01 && self.provider.is_none() {
            return Err("DNS-01 requires a DNS provider name".into());
        }

        Ok(AcmeConfig {
            email: self.email,
            directory_url: self.directory_url,
            cache_dir: self.cache_dir,
            challenge: self.challenge,
            provider: self.provider,
            label: None,
        })
    }
}

fn validate_listen(listen: &str) -> Result<(), String> {
    listen
        .parse::<SocketAddr>()
        .map(|_| ())
        .map_err(|e| format!("invalid listen address {listen}: {e}"))
}

fn ensure_http_scheme(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.to_string()
    } else {
        format!("http://{}", addr)
    }
}

fn ensure_ws_scheme(addr: &str) -> String {
    if addr.starts_with("ws://") || addr.starts_with("wss://") {
        addr.to_string()
    } else if addr.starts_with("http://") {
        addr.replacen("http://", "ws://", 1)
    } else if addr.starts_with("https://") {
        addr.replacen("https://", "wss://", 1)
    } else {
        format!("ws://{}", addr)
    }
}

fn validate_acme_config(acme: &Option<AcmeConfig>, store: &ConfigStore) -> Result<(), String> {
    if let Some(acme) = acme {
        if let AcmeChallenge::Dns01 = acme.challenge {
            let Some(provider_name) = &acme.provider else {
                return Err("DNS-01 requires a DNS provider reference".into());
            };
            let exists = store
                .acme_providers
                .iter()
                .any(|p| &p.name == provider_name);
            if !exists {
                return Err(format!(
                    "DNS provider '{}' not found. Create it first under /api/acme/providers.",
                    provider_name
                ));
            }
        }
        if acme.email.as_deref().unwrap_or("").trim().is_empty() {
            return Err("ACME requires a contact email".into());
        }
    }
    Ok(())
}

async fn ensure_acme_for_listener(state: AppState, listener_id: Uuid) -> anyhow::Result<()> {
    let mut updated: Option<ListenerConfig> = {
        let store = state.store.read();
        store.listeners.get(&listener_id).cloned()
    };
    let Some(mut config) = updated.take() else {
        return Ok(());
    };

    if !config.enabled {
        return Ok(());
    }

    let mut changed = false;

    if let Some(routes) = config.host_routes.as_mut() {
        for route in routes.iter_mut() {
            if !route.enabled {
                continue;
            }
            if let Some(acme) = &route.acme {
                let needs_cert = route
                    .tls
                    .as_ref()
                    .map(|t| {
                        let missing = !FsPath::new(&t.cert_path).exists();
                        let expiring = !is_cert_fresh_enough(&t.cert_path, 30);
                        missing || expiring
                    })
                    .unwrap_or(true);
                if needs_cert {
                    match obtain_cert(route.host.clone(), acme.clone(), state.clone()).await {
                        Ok(tls) => {
                            route.tls = Some(tls);
                            register_certificate(
                                &state,
                                acme.label.clone().unwrap_or_else(|| route.host.clone()),
                                route.tls.as_ref().unwrap(),
                                "acme",
                            );
                            route.acme_status = Some(AcmeStatus {
                                state: AcmeState::Issued,
                                message: None,
                                not_after: cert_not_after(
                                    route
                                        .tls
                                        .as_ref()
                                        .map(|t| t.cert_path.clone())
                                        .unwrap_or_default(),
                                ),
                            });
                            changed = true;
                        }
                        Err(err) => {
                            warn!("ACME issuance for host {} failed: {err:?}", route.host);
                            route.acme_status = Some(AcmeStatus {
                                state: AcmeState::Failed,
                                message: Some(err.to_string()),
                                not_after: None,
                            });
                        }
                    }
                } else if route.acme_status.is_none() {
                    route.acme_status = Some(AcmeStatus {
                        state: AcmeState::Pending,
                        message: None,
                        not_after: None,
                    });
                }
            }
        }
    }

    if changed {
        {
            let mut store = state.store.write();
            store.listeners.insert(listener_id, config.clone());
        }
        persist_store(&state)?;
        state.supervisor.upsert(config).await?;
    }

    Ok(())
}

async fn obtain_cert(host: String, acme: AcmeConfig, state: AppState) -> anyhow::Result<TlsConfig> {
    let host = host.split(':').next().unwrap_or("").to_string();
    let cert_dir = std::env::var("BALOR_CERT_DIR").unwrap_or_else(|_| "data/certs".into());
    let cache_dir = acme
        .cache_dir
        .clone()
        .unwrap_or_else(|| "data/acme-cache".into());
    let challenge_dir =
        std::env::var("BALOR_ACME_CHALLENGE_DIR").unwrap_or_else(|_| "data/acme-challenges".into());
    let email = acme
        .email
        .clone()
        .ok_or_else(|| anyhow::anyhow!("ACME email required"))?;

    let tls = tokio::task::spawn_blocking(move || -> anyhow::Result<TlsConfig> {
        let mut last_err: Option<anyhow::Error> = None;

        for attempt in 0..2 {
            let issue = || -> anyhow::Result<TlsConfig> {
                std::fs::create_dir_all(&cache_dir)?;
                std::fs::create_dir_all(&challenge_dir)?;

                let url = match acme.directory_url.as_deref() {
                    Some(url) if url.contains("staging") => DirectoryUrl::LetsEncryptStaging,
                    Some(url) if url.contains("letsencrypt") => DirectoryUrl::LetsEncrypt,
                    Some(url) => DirectoryUrl::Other(url),
                    None => DirectoryUrl::LetsEncrypt,
                };
                let persist = FilePersist::new(&cache_dir);
                let dir = Directory::from_url(persist, url)?;
                let acc = dir.account(&email)?;
                let mut ord_new = acc.new_order(&host, &[])?;

                let ord_csr = loop {
                    if let Some(ord_csr) = ord_new.confirm_validations() {
                        break ord_csr;
                    }

                    let mut auths = ord_new.authorizations()?;
                    for auth in auths.iter_mut() {
                        match acme.challenge {
                            AcmeChallenge::Http01 => {
                                let chall = auth.http_challenge();
                                let token = chall.http_token();
                                let proof = chall.http_proof();
                                let path = FsPath::new(&challenge_dir).join(token);
                                if let Some(parent) = path.parent() {
                                    std::fs::create_dir_all(parent)?;
                                }
                                std::fs::write(&path, proof)?;
                                chall.validate(5000)?;
                            }
                            AcmeChallenge::Dns01 => {
                                if let Some(provider_name) = &acme.provider {
                                    let chall = auth.dns_challenge();
                                    let proof = chall.dns_proof();
                                    perform_dns01(provider_name, &host, &proof, &state)?;
                                    // Give DNS a moment to propagate, then validate with a longer window.
                                    thread::sleep(Duration::from_secs(15));
                                    chall.validate(30000)?;
                                } else {
                                    return Err(anyhow::anyhow!(
                                        "DNS-01 requires provider configuration for {}",
                                        host
                                    ));
                                }
                            }
                        }
                    }

                    ord_new.refresh()?;
                    thread::sleep(Duration::from_secs(2));
                };

                let pkey_pri = create_p384_key();
                let ord_csr = ord_csr.finalize_pkey(pkey_pri, 5000)?;
                let cert = ord_csr.download_and_save_cert()?;

                let cert_path = FsPath::new(&cert_dir)
                    .join(format!("{}.crt", host.replace('*', "_wildcard")))
                    .to_string_lossy()
                    .to_string();
                let key_path = FsPath::new(&cert_dir)
                    .join(format!("{}.key", host.replace('*', "_wildcard")))
                    .to_string_lossy()
                    .to_string();
                std::fs::create_dir_all(&cert_dir)?;
                std::fs::write(&cert_path, cert.certificate())?;
                std::fs::write(&key_path, cert.private_key())?;

                Ok(TlsConfig {
                    cert_path,
                    key_path,
                })
            };

            match issue() {
                Ok(tls) => return Ok(tls),
                Err(err) => {
                    let msg = err.to_string();
                    if attempt == 0 && msg.contains("JWS verification error") {
                        warn!("ACME JWS verification failed; clearing cache at {} and retrying once", cache_dir);
                        let _ = std::fs::remove_dir_all(&cache_dir);
                        last_err = Some(err);
                        continue;
                    } else {
                        return Err(err);
                    }
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("ACME failed")))
    })
    .await??;

    Ok(tls)
}

fn perform_dns01(
    provider_name: &str,
    host: &str,
    proof: &str,
    state: &AppState,
) -> anyhow::Result<()> {
    let providers = {
        let store = state.store.read();
        store.acme_providers.clone()
    };
    let Some(provider) = providers.iter().find(|p| p.name == provider_name) else {
        return Err(anyhow::anyhow!(
            "DNS provider '{}' not configured",
            provider_name
        ));
    };

    match provider.provider {
        DnsProvider::Cloudflare => update_cloudflare_dns(provider, host, proof),
        DnsProvider::Route53 => update_route53_dns(provider, host, proof),
        DnsProvider::Generic => Err(anyhow::anyhow!(
            "Generic DNS provider automation not implemented"
        )),
    }
}

fn update_cloudflare_dns(
    provider: &AcmeProviderConfig,
    host: &str,
    proof: &str,
) -> anyhow::Result<()> {
    let zone_hint = provider
        .zone
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Cloudflare zone identifier or name required"))?;
    let token = provider
        .api_token
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Cloudflare API token required"))?;
    let api_base = provider
        .api_base
        .clone()
        .unwrap_or_else(|| "https://api.cloudflare.com/client/v4".into());
    let zone = resolve_cloudflare_zone_id(&api_base, &token, &zone_hint)?;

    let wildcard_fixed = host.trim_start_matches("*."); // ACME TXT uses base domain, not *.
    let name = format!(
        "{}.{}",
        provider
            .txt_prefix
            .clone()
            .unwrap_or_else(|| "_acme-challenge".into()),
        wildcard_fixed
    );
    let value = proof;
    let agent = ureq::agent();

    // Delete existing TXT records for this name (best effort).
    let list_url = format!(
        "{api_base}/zones/{zone}/dns_records?type=TXT&name={}",
        urlencoding::encode(&name)
    );
    if let Ok(resp) = agent
        .get(&list_url)
        .set("Authorization", &format!("Bearer {token}"))
        .call()
    {
        let val: serde_json::Value = resp.into_json().unwrap_or_default();
        if let Some(arr) = val.get("result").and_then(|r| r.as_array()) {
            for entry in arr {
                if let Some(id) = entry.get("id").and_then(|v| v.as_str()) {
                    let del_url = format!("{api_base}/zones/{zone}/dns_records/{id}");
                    let _ = agent
                        .delete(&del_url)
                        .set("Authorization", &format!("Bearer {token}"))
                        .call();
                }
            }
        }
    }

    // Create TXT record
    let create_url = format!("{api_base}/zones/{zone}/dns_records");
    let body = serde_json::json!({
        "type": "TXT",
        "name": name,
        "content": value,
        "ttl": 120
    });
    let resp = agent
        .post(&create_url)
        .set("Authorization", &format!("Bearer {token}"))
        .send_json(body)?;

    if !(200..300).contains(&resp.status()) {
        return Err(anyhow::anyhow!(
            "Cloudflare DNS update failed: {}",
            resp.into_string().unwrap_or_default()
        ));
    }
    Ok(())
}

fn update_route53_dns(
    provider: &AcmeProviderConfig,
    host: &str,
    proof: &str,
) -> anyhow::Result<()> {
    use rusoto_core::credential::StaticProvider;
    use rusoto_core::region::Region;
    use rusoto_core::request::HttpClient;
    use rusoto_route53::{
        Change, ChangeBatch, ChangeResourceRecordSetsRequest, ResourceRecord, ResourceRecordSet,
        Route53, Route53Client,
    };

    let access_key = provider
        .access_key
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Route53 access_key is required"))?;
    let secret_key = provider
        .secret_key
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Route53 secret_key is required"))?;
    let zone_id = provider
        .zone
        .clone()
        .ok_or_else(|| anyhow::anyhow!("Route53 hosted zone ID is required"))?;
    let region_name = provider
        .api_base
        .clone()
        .unwrap_or_else(|| "us-east-1".into());

    let wildcard_fixed = host.trim_start_matches("*.");
    let name = format!(
        "{}.{}",
        provider
            .txt_prefix
            .clone()
            .unwrap_or_else(|| "_acme-challenge".into()),
        wildcard_fixed
    );

    let region = Region::Custom {
        name: region_name.clone(),
        endpoint: "https://route53.amazonaws.com".into(),
    };
    let cred = StaticProvider::new_minimal(access_key, secret_key);
    let client = Route53Client::new_with(HttpClient::new()?, cred, region);

    let rrset = ResourceRecordSet {
        name: name.clone(),
        type_: "TXT".into(),
        ttl: Some(60),
        resource_records: Some(vec![ResourceRecord {
            value: format!("\"{}\"", proof),
        }]),
        ..Default::default()
    };

    let req = ChangeResourceRecordSetsRequest {
        hosted_zone_id: zone_id,
        change_batch: ChangeBatch {
            changes: vec![Change {
                action: "UPSERT".into(),
                resource_record_set: rrset,
            }],
            ..Default::default()
        },
    };

    // Run the async client in a lightweight runtime inside the blocking context.
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async { client.change_resource_record_sets(req).await })?;
    Ok(())
}

fn resolve_cloudflare_zone_id(
    api_base: &str,
    token: &str,
    zone_hint: &str,
) -> anyhow::Result<String> {
    // If the hint already looks like a 32-char hex ID, accept it.
    let is_hex_id = zone_hint.len() == 32 && zone_hint.chars().all(|c| c.is_ascii_hexdigit());
    if is_hex_id {
        return Ok(zone_hint.to_string());
    }

    let list_url = format!("{api_base}/zones?name={}", urlencoding::encode(zone_hint));
    let resp = ureq::agent()
        .get(&list_url)
        .set("Authorization", &format!("Bearer {token}"))
        .call()?;
    if !(200..300).contains(&resp.status()) {
        return Err(anyhow::anyhow!(
            "Cloudflare zone lookup failed: {}",
            resp.into_string().unwrap_or_default()
        ));
    }
    let val: serde_json::Value = resp.into_json().unwrap_or_default();
    let zones = val
        .get("result")
        .and_then(|r| r.as_array())
        .ok_or_else(|| anyhow::anyhow!("Unexpected Cloudflare response"))?;
    let zone_id = zones
        .iter()
        .find_map(|z| z.get("id").and_then(|v| v.as_str()))
        .ok_or_else(|| anyhow::anyhow!("Zone {} not found in Cloudflare", zone_hint))?;
    Ok(zone_id.to_string())
}

fn cert_not_after(path: String) -> Option<String> {
    let data = std::fs::read(path).ok()?;
    let mut reader = std::io::Cursor::new(data);
    let mut iter = rustls_pemfile::certs(&mut reader);
    let first = match iter.next()? {
        Ok(c) => c,
        Err(_) => return None,
    };
    let (_rem, parsed) = X509Certificate::from_der(first.as_ref()).ok()?;
    let not_after = parsed.validity().not_after.to_datetime();
    let dt = DateTime::<Utc>::from_timestamp(not_after.unix_timestamp(), not_after.nanosecond())?;
    Some(dt.to_rfc3339())
}

fn is_cert_fresh_enough(path: &str, days: i64) -> bool {
    if let Some(na) = cert_not_after(path.to_string()) {
        if let Ok(dt) = DateTime::parse_from_rfc3339(&na) {
            let dt = dt.with_timezone(&Utc);
            let cutoff = Utc::now() + chrono::Duration::days(days);
            return dt > cutoff;
        }
    }
    false
}

fn register_certificate(state: &AppState, name: String, tls: &TlsConfig, source: &str) {
    let mut store = state.store.write();
    let bundle = CertificateBundle {
        name: name.clone(),
        cert_path: tls.cert_path.clone(),
        key_path: tls.key_path.clone(),
        source: source.to_string(),
    };
    if let Some(existing) = store.certificates.iter_mut().find(|c| c.name == name) {
        *existing = bundle;
    } else {
        store.certificates.push(bundle);
    }
}

impl BalancerSupervisor {
    async fn upsert(&self, config: ListenerConfig) -> anyhow::Result<()> {
        let id = config.id;
        self.remove(&config.id).await;
        if !config.enabled {
            info!("listener {} is disabled; runtime not started", config.name);
            return Ok(());
        }
        let handle = spawn_listener(config, self.health.clone(), self.metrics.clone()).await?;
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
    metrics: Arc<Metrics>,
) -> anyhow::Result<BalancerHandle> {
    let cancel = CancellationToken::new();
    let cancel_for_task = cancel.clone();
    let protocol_for_task = config.protocol.clone();
    let id = config.id;

    let join = tokio::spawn(async move {
        let result = match protocol_for_task {
            Protocol::Http => run_http_listener(config, cancel_for_task, health, metrics).await,
            Protocol::Tcp => run_tcp_listener(config, cancel_for_task, health, metrics).await,
        };

        if let Err(err) = result {
            error!("listener {id} terminated with error: {err:?}");
        }
    });

    Ok(BalancerHandle { cancel, join })
}

#[derive(Clone)]
struct HttpProxyState {
    listener_id: Uuid,
    upstreams: Arc<Vec<Upstream>>,
    host_routes: Arc<Vec<HostRule>>,
    position: Arc<AtomicUsize>,
    client: reqwest::Client,
    health: Arc<RwLock<HashMap<Uuid, bool>>>,
    sticky: Option<StickyConfig>,
    metrics: Arc<Metrics>,
}

impl HttpProxyState {
    fn new(
        listener_id: Uuid,
        upstreams: Vec<Upstream>,
        host_routes: Vec<HostRule>,
        health: Arc<RwLock<HashMap<Uuid, bool>>>,
        sticky: Option<StickyConfig>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            listener_id,
            upstreams: Arc::new(upstreams),
            host_routes: Arc::new(host_routes),
            position: Arc::new(AtomicUsize::new(0)),
            client: reqwest::Client::new(),
            health,
            sticky,
            metrics,
        }
    }

    fn next_upstream(&self, req: &Request<Body>, peer: &SocketAddr) -> Option<UpstreamSelection> {
        let health = self.health.read();
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(|h| h.to_lowercase())
            .map(|h| h.split(':').next().unwrap_or("").to_string());
        let enabled: Vec<_> = if let Some(h) = host {
            if let Some(rule) = select_route(&h, &self.host_routes) {
                rule.upstreams
                    .iter()
                    .filter(|u| u.enabled && *health.get(&u.id).unwrap_or(&true))
                    .cloned()
                    .collect()
            } else {
                self.upstreams
                    .iter()
                    .filter(|u| u.enabled && *health.get(&u.id).unwrap_or(&true))
                    .cloned()
                    .collect()
            }
        } else {
            self.upstreams
                .iter()
                .filter(|u| u.enabled && *health.get(&u.id).unwrap_or(&true))
                .cloned()
                .collect()
        };
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
    metrics: Arc<Metrics>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config.listen.parse()?;

    let active_routes: Vec<HostRule> = config
        .host_routes
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.enabled)
        .collect();

    let state = HttpProxyState::new(
        config.id,
        config.upstreams.clone(),
        active_routes.clone(),
        health,
        config.sticky.clone(),
        metrics.clone(),
    );

    let router = Router::new().fallback(proxy_http).with_state(state);
    if let Some(acme) = config.acme.clone() {
        let dir = std::env::var("BALOR_ACME_CHALLENGE_DIR")
            .unwrap_or_else(|_| "data/acme-challenges".to_string());
        match acme.challenge {
            AcmeChallenge::Http01 => info!(
                "ACME HTTP-01 responder active for '{}' (challenge dir: {})",
                config.name, dir
            ),
            AcmeChallenge::Dns01 => info!(
                "ACME DNS-01 configured for '{}' using provider {:?} (challenge dir still serves HTTP-01 tokens if present at {})",
                config.name,
                acme.provider,
                dir
            ),
        }
    }
    info!(
        "Starting HTTP balancer '{}' on {} -> {} upstreams",
        config.name,
        listen_addr,
        config.upstreams.len()
    );

    // Build SNI-aware rustls config from listener + host routes.
    let tls_available = config.tls.is_some() || active_routes.iter().any(|r| r.tls.is_some());

    if tls_available {
        let mut tls_source = config.clone();
        tls_source.host_routes = Some(active_routes.clone());
        let tls_config = build_sni_rustls_config(&tls_source).await?;
        info!("TLS enabled for '{}' (SNI resolver active)", config.name);
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
    metrics: Arc<Metrics>,
) -> anyhow::Result<()> {
    let listen_addr: SocketAddr = config.listen.parse()?;
    let listener_id = config.id;
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

        metrics.observe_tcp(listener_id);
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

#[axum::debug_handler]
async fn proxy_http(
    State(state): State<HttpProxyState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Result<Response<Body>, StatusCode> {
    let path_for_acme = request.uri().path().to_string();
    if let Some(resp) = try_acme_challenge(&path_for_acme).await {
        return Ok(resp);
    }

    let start = Instant::now();
    let selection = match state.next_upstream(&request, &peer) {
        Some(sel) => sel,
        None => {
            state
                .metrics
                .observe_http(state.listener_id, StatusCode::BAD_GATEWAY, start.elapsed());
            return Err(StatusCode::BAD_GATEWAY);
        }
    };
    let upstream = selection.upstream;
    if is_websocket(&request) {
        return proxy_websocket(request, upstream, peer).await;
    }
    let path = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let (raw_base, upstream_prefix, upstream_host) = split_upstream(&upstream.address);
    let upstream_base = ensure_http_scheme(&raw_base);
    let suffix = if !upstream_prefix.is_empty() && path.starts_with(&upstream_prefix) {
        path.strip_prefix(&upstream_prefix).unwrap_or(path)
    } else {
        path
    };
    let target_url = format!("{}{}", upstream_base, suffix);

    let (parts, body) = request.into_parts();
    let body_bytes = to_bytes(body, BODY_LIMIT)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut builder = state.client.request(parts.method.clone(), target_url);
    let client_ip = peer.ip().to_string();
    let client_proto = if upstream.address.starts_with("https") {
        "https"
    } else {
        "http"
    };
    let client_host = parts
        .headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    for (key, value) in parts.headers.iter() {
        if !is_hop_by_hop(key) && key != &header::HOST {
            builder = builder.header(key, value);
        }
    }
    let forward_host = if !upstream_host.is_empty() {
        upstream_host.clone()
    } else {
        client_host.clone().unwrap_or_default()
    };
    if !forward_host.is_empty() {
        builder = builder.header(header::HOST, forward_host);
    }
    builder = builder
        .header("x-forwarded-for", client_ip)
        .header("x-forwarded-proto", client_proto)
        .header(
            "x-forwarded-host",
            client_host
                .as_ref()
                .cloned()
                .unwrap_or_else(|| upstream_host.clone()),
        );

    let response = match builder.body(body_bytes).send().await {
        Ok(resp) => resp,
        Err(_) => {
            state
                .metrics
                .observe_http(state.listener_id, StatusCode::BAD_GATEWAY, start.elapsed());
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    let status = response.status();
    let headers = response.headers().clone();
    let bytes = match response.bytes().await {
        Ok(b) => b,
        Err(_) => {
            state
                .metrics
                .observe_http(state.listener_id, StatusCode::BAD_GATEWAY, start.elapsed());
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    let mut resp_builder = Response::builder().status(status);
    for (key, value) in headers.iter() {
        if is_hop_by_hop(key) {
            continue;
        }
        if key == &header::SET_COOKIE {
            if let Some(rewritten) = rewrite_set_cookie(value, &upstream_host, &client_host) {
                resp_builder = resp_builder.header(key, rewritten);
            }
            continue;
        }
        resp_builder = resp_builder.header(key, value);
    }

    if let Some((name, value)) = selection.set_cookie {
        let cookie = format!("{name}={value}; Path=/; HttpOnly; SameSite=Lax");
        resp_builder = resp_builder.header(axum::http::header::SET_COOKIE, cookie);
    }

    let body = resp_builder
        .body(Body::from(bytes))
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    state
        .metrics
        .observe_http(state.listener_id, status, start.elapsed());

    Ok(body)
}

async fn proxy_websocket(
    mut request: Request<Body>,
    upstream: Upstream,
    peer: SocketAddr,
) -> Result<Response<Body>, StatusCode> {
    let path_str = request
        .uri()
        .path_and_query()
        .map(|p| p.as_str())
        .unwrap_or("/");
    let (raw_base, upstream_prefix, upstream_host) = split_upstream(&upstream.address);
    let upstream_base = ensure_ws_scheme(&raw_base);
    let suffix = if !upstream_prefix.is_empty() && path_str.starts_with(&upstream_prefix) {
        path_str.strip_prefix(&upstream_prefix).unwrap_or(path_str)
    } else {
        path_str
    };
    let ws_target = format!("{}{}", upstream_base, suffix);

    let upgrade = hyper::upgrade::on(&mut request);
    let _client_ip_ws = peer.ip().to_string();
    let accept_key = request
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok())
        .map(|k| websocket_accept(k));

    let mut response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header(header::CONNECTION, "upgrade")
        .header(header::UPGRADE, "websocket");
    if let Some(key) = accept_key {
        response = response.header(header::SEC_WEBSOCKET_ACCEPT, key);
    }
    let response = response
        .body(Body::empty())
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    tokio::spawn(async move {
        let upgraded = match upgrade.await {
            Ok(up) => up,
            Err(err) => {
                warn!("websocket upgrade failed: {err}");
                return;
            }
        };

        let upgraded = TokioIo::new(upgraded);
        let client_ws: WebSocketStream<_> =
            WebSocketStream::from_raw_socket(upgraded, WsRole::Server, None).await;

        let mut req_builder = Request::builder().method("GET").uri(&ws_target);
        for (key, value) in request.headers().iter() {
            if key == header::HOST {
                continue;
            }
            if key == header::SEC_WEBSOCKET_EXTENSIONS {
                // Avoid negotiating compression; pass-through without RSV bits issues.
                continue;
            }
            req_builder = req_builder.header(key, value);
        }
        req_builder = req_builder.header(header::HOST, upstream_host);
        let request = req_builder.body(()).unwrap_or_else(|_| Request::new(()));

        let upstream_ws = connect_async(request).await;
        let (upstream_ws, _) = match upstream_ws {
            Ok(res) => res,
            Err(err) => {
                warn!("upstream websocket connect failed: {err}");
                return;
            }
        };

        let (mut client_write, mut client_read) = client_ws.split();
        let (mut upstream_write, mut upstream_read) = upstream_ws.split();

        let c_to_u = async {
            while let Some(msg) = client_read.next().await {
                match msg {
                    Ok(msg) => {
                        if let Err(err) = upstream_write.send(msg).await {
                            warn!("ws forward client->upstream failed: {err}");
                            break;
                        }
                    }
                    Err(err) => {
                        warn!("ws read client error: {err}");
                        break;
                    }
                }
            }
        };

        let u_to_c = async {
            while let Some(msg) = upstream_read.next().await {
                match msg {
                    Ok(msg) => {
                        if let Err(err) = client_write.send(msg).await {
                            warn!("ws forward upstream->client failed: {err}");
                            break;
                        }
                    }
                    Err(err) => {
                        warn!("ws read upstream error: {err}");
                        break;
                    }
                }
            }
        };

        tokio::select! {
            _ = c_to_u => (),
            _ = u_to_c => (),
        }
    });

    Ok(response)
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

fn is_websocket(req: &Request<Body>) -> bool {
    let upgrade = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let connection = req
        .headers()
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase())
        .unwrap_or_default();
    upgrade || connection.contains("upgrade")
}

fn split_upstream(address: &str) -> (String, String, String) {
    let trimmed = address.trim_end_matches('/');
    let host: String;
    let mut base = trimmed.to_string();
    let mut prefix = String::new();

    if let Some(idx) = trimmed.find("://") {
        let rest = &trimmed[idx + 3..];
        if let Some(slash) = rest.find('/') {
            host = rest[..slash].to_string();
            let path_part = &rest[slash + 1..];
            prefix = format!("/{}", path_part);
            base = format!("{}://{}", &trimmed[..idx], host);
        } else {
            host = rest.to_string();
            base = trimmed.to_string();
        }
    } else if let Some(slash) = trimmed.find('/') {
        host = trimmed[..slash].to_string();
        let path_part = &trimmed[slash + 1..];
        prefix = format!("/{}", path_part);
        base = host.clone();
    } else {
        host = trimmed.to_string();
    }

    (base, prefix, host)
}

fn websocket_accept(key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    let digest = hasher.finalize();
    BASE64_STD.encode(digest)
}

#[allow(dead_code)]
async fn load_rustls_config(cert_path: &str, key_path: &str) -> anyhow::Result<RustlsConfig> {
    let mut cert_chain: Vec<CertificateDer<'static>> = Vec::new();
    let mut private_key: Option<PrivateKeyDer<'static>> = None;

    let cert_bytes = fs::read(cert_path).await?;
    let mut reader = cert_bytes.as_slice();
    while let Some(item) = rustls_pemfile::read_one(&mut reader)? {
        match item {
            rustls_pemfile::Item::X509Certificate(cert) => {
                cert_chain.push(cert);
            }
            _ => {}
        }
    }
    if cert_chain.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path);
    }

    let key_bytes = fs::read(key_path).await?;
    let mut key_reader = key_bytes.as_slice();
    while let Some(item) = rustls_pemfile::read_one(&mut key_reader)? {
        match item {
            rustls_pemfile::Item::Pkcs8Key(k) => {
                private_key = Some(PrivateKeyDer::from(k));
                break;
            }
            rustls_pemfile::Item::Sec1Key(k) => {
                private_key = Some(PrivateKeyDer::from(k));
                break;
            }
            rustls_pemfile::Item::Pkcs1Key(k) => {
                private_key = Some(PrivateKeyDer::from(k));
                break;
            }
            _ => {}
        }
    }

    let key =
        private_key.ok_or_else(|| anyhow::anyhow!("no usable private key in {}", key_path))?;
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    Ok(RustlsConfig::from_config(std::sync::Arc::new(
        server_config,
    )))
}

async fn load_certified_key(cert_path: &str, key_path: &str) -> anyhow::Result<CertifiedKey> {
    let mut cert_chain: Vec<CertificateDer<'static>> = Vec::new();
    let mut private_key: Option<PrivateKeyDer<'static>> = None;

    let cert_bytes = fs::read(cert_path).await?;
    let mut reader = cert_bytes.as_slice();
    while let Some(item) = rustls_pemfile::read_one(&mut reader)? {
        if let rustls_pemfile::Item::X509Certificate(cert) = item {
            cert_chain.push(cert);
        }
    }
    if cert_chain.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path);
    }

    let key_bytes = fs::read(key_path).await?;
    let mut key_reader = key_bytes.as_slice();
    while let Some(item) = rustls_pemfile::read_one(&mut key_reader)? {
        match item {
            rustls_pemfile::Item::Pkcs8Key(k) => {
                private_key = Some(PrivateKeyDer::from(k));
                break;
            }
            rustls_pemfile::Item::Sec1Key(k) => {
                private_key = Some(PrivateKeyDer::from(k));
                break;
            }
            rustls_pemfile::Item::Pkcs1Key(k) => {
                private_key = Some(PrivateKeyDer::from(k));
                break;
            }
            _ => {}
        }
    }

    let key =
        private_key.ok_or_else(|| anyhow::anyhow!("no usable private key in {}", key_path))?;
    let signing_key = any_supported_type(&key)
        .map_err(|_| anyhow::anyhow!("unsupported key type in {}", key_path))?;

    Ok(CertifiedKey::new(cert_chain, signing_key))
}

async fn build_sni_rustls_config(listener: &ListenerConfig) -> anyhow::Result<RustlsConfig> {
    let mut hosts: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut wildcards: Vec<(String, Arc<CertifiedKey>)> = Vec::new();
    let mut default_key: Option<Arc<CertifiedKey>> = None;

    if let Some(tls) = &listener.tls {
        let key = Arc::new(load_certified_key(&tls.cert_path, &tls.key_path).await?);
        default_key = Some(key.clone());
        hosts.insert("default".into(), key);
    }

    if let Some(routes) = &listener.host_routes {
        for route in routes {
            if let Some(tls) = &route.tls {
                let key = Arc::new(load_certified_key(&tls.cert_path, &tls.key_path).await?);
                let hostname = route.host.split(':').next().unwrap_or("").to_lowercase();
                if hostname.starts_with("*.") {
                    wildcards.push((hostname.trim_start_matches("*.").to_string(), key.clone()));
                } else {
                    hosts.insert(hostname, key.clone());
                }
                if default_key.is_none() {
                    default_key = Some(key);
                }
            }
        }
    }

    let Some(default_key) = default_key else {
        anyhow::bail!("no TLS certificates configured");
    };

    let sni_resolver = Arc::new(ManualSniResolver {
        hosts,
        wildcards,
        default_key,
    });

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(sni_resolver);
    Ok(RustlsConfig::from_config(Arc::new(server_config)))
}

#[derive(Debug)]
struct ManualSniResolver {
    hosts: HashMap<String, Arc<CertifiedKey>>,
    wildcards: Vec<(String, Arc<CertifiedKey>)>,
    default_key: Arc<CertifiedKey>,
}

impl ResolvesServerCert for ManualSniResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        if let Some(name) = client_hello.server_name() {
            let name = name.to_lowercase();
            if let Some(key) = self.hosts.get(&name) {
                return Some(key.clone());
            }
            for (suffix, key) in self.wildcards.iter() {
                if name.ends_with(suffix) && name.len() > suffix.len() {
                    return Some(key.clone());
                }
            }
        }
        // Fallback to default cert.
        self.default_key.clone().into()
    }
}

fn select_route<'a>(host: &str, routes: &'a [HostRule]) -> Option<&'a HostRule> {
    if let Some(exact) = routes
        .iter()
        .filter(|r| r.enabled)
        .find(|r| !r.host.starts_with("*.") && r.host == host)
    {
        return Some(exact);
    }
    let mut wildcard_match: Option<&HostRule> = None;
    for route in routes
        .iter()
        .filter(|r| r.enabled)
        .filter(|r| r.host.starts_with("*."))
    {
        let suffix = route.host.trim_start_matches("*.");
        if host.ends_with(suffix) && host.len() > suffix.len() {
            wildcard_match = match wildcard_match {
                Some(current) => {
                    let curr_suf = current.host.trim_start_matches("*.");
                    if suffix.len() > curr_suf.len() {
                        Some(route)
                    } else {
                        Some(current)
                    }
                }
                None => Some(route),
            };
        }
    }
    wildcard_match
}

async fn try_acme_challenge(path: &str) -> Option<Response<Body>> {
    const PREFIX: &str = "/.well-known/acme-challenge/";
    if !path.starts_with(PREFIX) {
        return None;
    }
    let token = path.trim_start_matches(PREFIX);
    if token.is_empty() {
        return Some(
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .ok()?,
        );
    }
    let dir = std::env::var("BALOR_ACME_CHALLENGE_DIR")
        .unwrap_or_else(|_| "data/acme-challenges".to_string());
    let challenge_path = FsPath::new(&dir).join(token);
    match fs::read_to_string(&challenge_path).await {
        Ok(body) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(Body::from(body))
            .ok(),
        Err(err) => {
            warn!("ACME challenge token {} not found: {}", token, err);
            Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Body::empty())
                .ok()
        }
    }
}

fn rewrite_set_cookie(
    value: &HeaderValue,
    upstream_host: &str,
    client_host: &Option<String>,
) -> Option<HeaderValue> {
    let Ok(raw) = value.to_str() else {
        return Some(value.clone());
    };
    if upstream_host.is_empty() {
        return Some(value.clone());
    }
    let replacement = client_host.clone().unwrap_or_default();
    let mut out = raw.to_string();
    if !replacement.is_empty() {
        out = out.replace(
            &format!("Domain={}", upstream_host),
            &format!("Domain={}", replacement),
        );
    } else {
        out = out.replace(&format!("Domain={}", upstream_host), "Domain");
    }
    HeaderValue::from_str(&out)
        .ok()
        .or_else(|| Some(value.clone()))
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

fn current_console_config(state: &AppState) -> AdminConsoleConfig {
    let store = state.store.read();
    store
        .admin_console
        .clone()
        .unwrap_or_else(|| AdminConsoleConfig {
            bind: std::env::var("BALOR_HTTP_ADDR").unwrap_or_else(|_| default_admin_bind()),
            tls: None,
        })
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

    let password = std::env::var("BALOR_DEFAULT_ADMIN_PASSWORD")
        .ok()
        .filter(|p| !p.trim().is_empty())
        .unwrap_or_else(|| {
            let generated = generate_strong_password();
            let path = bootstrap_secret_path();
            if let Err(err) = persist_bootstrap_secret(&path, &generated) {
                warn!(
                    "Generated bootstrap admin password but failed to persist to {}: {err}",
                    path.display()
                );
            } else {
                info!(
                    "Generated bootstrap admin password and wrote it to {} (mode 600). Please rotate and remove after first login.",
                    path.display()
                );
            }
            generated
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

fn generate_strong_password() -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(32)
        .map(char::from)
        .collect()
}

fn bootstrap_secret_path() -> PathBuf {
    std::env::var("BALOR_BOOTSTRAP_SECRET_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("data/admin-bootstrap.txt"))
}

fn persist_bootstrap_secret(path: &PathBuf, password: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, format!("username=admin\npassword={password}\n"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(path, perms)?;
    }
    Ok(())
}

async fn hydrate_supervisor(state: AppState) -> anyhow::Result<()> {
    let listeners: Vec<ListenerConfig> = {
        let store = state.store.read();
        store.listeners.values().cloned().collect()
    };

    let mut tasks = JoinSet::new();
    for listener in listeners {
        if !listener.enabled {
            info!("skipping disabled listener '{}' at startup", listener.name);
            continue;
        }
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
    if let Some(routes) = cfg.host_routes.as_mut() {
        for route in routes.iter_mut() {
            for upstream in route.upstreams.iter_mut() {
                upstream.healthy = Some(*health.get(&upstream.id).unwrap_or(&false));
            }
            if route.acme.is_some() && route.acme_status.is_none() {
                route.acme_status = Some(AcmeStatus {
                    state: AcmeState::Pending,
                    message: None,
                    not_after: None,
                });
            }
        }
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

fn spawn_acme_renewer(state: AppState) {
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(12 * 60 * 60)); // twice a day
        loop {
            interval.tick().await;
            run_acme_renewal(&state).await;
        }
    });
}

async fn run_acme_renewal(state: &AppState) {
    let listeners: Vec<Uuid> = {
        let store = state.store.read();
        store.listeners.keys().cloned().collect()
    };
    for id in listeners {
        let config = {
            let store = state.store.read();
            store.listeners.get(&id).cloned()
        };
        if let Some(cfg) = config {
            let mut needs = false;
            if let Some(routes) = cfg.host_routes.as_ref() {
                for route in routes {
                    if route.acme.is_some() {
                        if route
                            .acme_status
                            .as_ref()
                            .and_then(|s| s.not_after.as_ref())
                            .and_then(|na| DateTime::parse_from_rfc3339(na).ok())
                            .map(|exp| {
                                let exp_utc = exp.with_timezone(&Utc);
                                (exp_utc - Utc::now()).num_days() <= 15
                            })
                            .unwrap_or(true)
                        {
                            needs = true;
                            break;
                        }
                    }
                }
            }
            if needs {
                if let Err(err) = ensure_acme_for_listener(state.clone(), id).await {
                    warn!("ACME renewal for listener {id} failed: {err:?}");
                }
            }
        }
    }
    // Standalone jobs
    let standalone_hosts: Vec<String> = {
        let store = state.store.read();
        store
            .acme_standalone
            .iter()
            .filter(|j| {
                j.status
                    .as_ref()
                    .and_then(|s| s.not_after.as_ref())
                    .and_then(|na| DateTime::parse_from_rfc3339(na).ok())
                    .map(|exp| {
                        let exp_utc = exp.with_timezone(&Utc);
                        (exp_utc - Utc::now()).num_days() <= 15
                    })
                    .unwrap_or(true)
            })
            .map(|j| j.host.clone())
            .collect()
    };
    for host in standalone_hosts {
        if let Err(err) = renew_standalone_job(state.clone(), host.clone(), None).await {
            warn!("ACME renewal for standalone host failed: {err:?}");
        }
    }
}

async fn run_health_cycle(state: &AppState, client: &reqwest::Client) {
    let listeners: Vec<ListenerConfig> = {
        let store = state.store.read();
        store.listeners.values().cloned().collect()
    };

    for listener in listeners {
        if !listener.enabled {
            continue;
        }
        let mut all_upstreams = listener.upstreams.clone();
        if let Some(routes) = &listener.host_routes {
            for r in routes.iter().filter(|r| r.enabled) {
                all_upstreams.extend(r.upstreams.clone());
            }
        }
        for upstream in all_upstreams {
            let ok = match listener.protocol {
                Protocol::Http => check_http(client, &ensure_http_scheme(&upstream.address)).await,
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
