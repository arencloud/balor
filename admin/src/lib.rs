// Balor admin UI
// Author: Eduard Gevorkyan (egevorky@arencloud.com)
// License: Apache 2.0

use gloo_net::http::Request;
use gloo_timers::callback::Interval;
use js_sys::Array;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_yaml;
use std::collections::HashSet;
use std::f64;
use std::{cell::RefCell, rc::Rc};
use uuid::Uuid;
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::spawn_local;
use web_sys::{Blob, BlobPropertyBag, HtmlAnchorElement, Url};
use yew::prelude::*;

fn default_true() -> bool {
    true
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Protocol {
    Http,
    Tcp,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum StickyStrategy {
    Cookie,
    IpHash,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
enum AcmeChallenge {
    Http01,
    Dns01,
}

impl Default for AcmeChallenge {
    fn default() -> Self {
        AcmeChallenge::Http01
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
enum DnsProvider {
    Cloudflare,
    Route53,
    Generic,
}

impl Default for DnsProvider {
    fn default() -> Self {
        DnsProvider::Cloudflare
    }
}

fn default_provider_url(provider: &DnsProvider) -> String {
    match provider {
        DnsProvider::Cloudflare => "https://api.cloudflare.com/client/v4".to_string(),
        DnsProvider::Route53 => "https://route53.amazonaws.com".to_string(),
        DnsProvider::Generic => String::new(),
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Role {
    Admin,
    Operator,
    Viewer,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct Session {
    token: String,
    username: String,
    role: Role,
}

thread_local! {
    static SESSION_CACHE: RefCell<Option<Session>> = RefCell::new(None);
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct StickyConfig {
    strategy: StickyStrategy,
    #[serde(default)]
    cookie_name: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct TlsConfig {
    cert_path: String,
    key_path: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct AcmeConfig {
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    directory_url: Option<String>,
    #[serde(default)]
    cache_dir: Option<String>,
    #[serde(default)]
    challenge: AcmeChallenge,
    #[serde(default)]
    provider: Option<String>,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum AcmeState {
    Pending,
    Issued,
    Failed,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct AcmeStatus {
    state: AcmeState,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    not_after: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct AcmeProviderConfig {
    name: String,
    provider: DnsProvider,
    #[serde(default)]
    api_token: Option<String>,
    #[serde(default)]
    access_key: Option<String>,
    #[serde(default)]
    secret_key: Option<String>,
    #[serde(default)]
    zone: Option<String>,
    #[serde(default)]
    txt_prefix: Option<String>,
    #[serde(default)]
    api_base: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct CertificateBundle {
    name: String,
    cert_path: String,
    key_path: String,
    #[serde(default)]
    source: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct StandaloneAcmeJob {
    host: String,
    #[serde(default)]
    label: Option<String>,
    acme: AcmeConfig,
    #[serde(default)]
    status: Option<AcmeStatus>,
    #[serde(default)]
    tls: Option<TlsConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
struct CertificatePayload {
    name: String,
    cert_pem: String,
    key_pem: String,
    #[serde(default)]
    source: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Default)]
struct AdminConsoleConfig {
    #[serde(default = "default_admin_bind")]
    bind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<TlsConfig>,
}

fn default_admin_bind() -> String {
    "0.0.0.0:9443".to_string()
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct Upstream {
    id: Uuid,
    name: String,
    address: String,
    enabled: bool,
    #[serde(default)]
    healthy: Option<bool>,
    #[serde(default)]
    weight: Option<u32>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct UpstreamPool {
    name: String,
    upstreams: Vec<Upstream>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct HostRule {
    host: String,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rate_limit: Option<RateLimitConfig>,
    upstreams: Vec<Upstream>,
    #[serde(default)]
    pool: Option<String>,
    #[serde(default)]
    tls: Option<TlsConfig>,
    #[serde(default)]
    acme: Option<AcmeConfig>,
    #[serde(default)]
    acme_status: Option<AcmeStatus>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct Listener {
    id: Uuid,
    name: String,
    listen: String,
    protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    health_probe: Option<HealthProbePayload>,
    #[serde(default = "default_true")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rate_limit: Option<RateLimitConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
struct UpstreamPayload {
    name: String,
    address: String,
    enabled: bool,
    #[serde(default = "default_weight")]
    weight: u32,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct RateLimitConfig {
    rps: u32,
    burst: u32,
}

const fn default_weight() -> u32 {
    1
}

#[derive(Clone, Serialize, Deserialize)]
struct UpstreamPoolPayload {
    name: String,
    upstreams: Vec<UpstreamPayload>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct HealthProbePayload {
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    headers: Vec<(String, String)>,
    #[serde(default)]
    script: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct HostRulePayload {
    host: String,
    #[serde(default = "default_true")]
    enabled: bool,
    upstreams: Vec<UpstreamPayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rate_limit: Option<RateLimitConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pool: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<TlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acme: Option<AcmeConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acme_status: Option<AcmeStatus>,
}

#[derive(Clone, Serialize, Deserialize)]
struct ListenerPayload {
    name: String,
    listen: String,
    protocol: Protocol,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    health_probe: Option<HealthProbePayload>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    rate_limit: Option<RateLimitConfig>,
    #[serde(default = "default_true")]
    enabled: bool,
    upstreams: Vec<UpstreamPayload>,
    #[serde(default)]
    host_routes: Option<Vec<HostRulePayload>>,
    #[serde(default)]
    tls: Option<TlsConfig>,
    #[serde(default)]
    sticky: Option<StickyConfig>,
    #[serde(default)]
    acme: Option<AcmeConfig>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct User {
    id: Uuid,
    username: String,
    role: Role,
}

#[derive(Clone, Serialize, Deserialize)]
struct UserPayload {
    username: String,
    role: Role,
    password: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct HostRuleForm {
    host: String,
    enabled: bool,
    tls_enabled: bool,
    rate_rps: String,
    rate_burst: String,
    upstreams_text: String,
    pool: String,
    selected_cert: String,
    cert_path: String,
    key_path: String,
    acme: Option<AcmeConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
struct UpstreamPoolForm {
    name: String,
    upstreams_text: String,
}

#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
struct Stats {
    listener_count: usize,
    active_runtimes: usize,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct TraceSettings {
    sample_permyriad: u64,
}

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
    yew::Renderer::<App>::new().render();
}

#[function_component(App)]
fn app() -> Html {
    let listeners = use_state(Vec::<Listener>::new);
    let form = use_state(ListenerForm::default);
    let status = use_state(StatusLine::default);
    let loading = use_state(|| false);
    let editing = use_state(|| None::<Uuid>);
    let stats = use_state(Stats::default);
    let metrics_text = use_state(|| String::new());
    let metrics_rows = use_state(Vec::<MetricRow>::new);
    let latency_rows = use_state(Vec::<LatencyRow>::new);
    let session = use_state(load_session);
    let tab = use_state(|| Tab::Listeners);
    let users = use_state(Vec::<User>::new);
    let user_form = use_state(UserForm::default);
    let login_form = use_state(LoginForm::default);
    let acme_providers = use_state(Vec::<AcmeProviderConfig>::new);
    let acme_form = use_state(AcmeProviderForm::default);
    let acme_schedule = use_state(AcmeScheduleForm::default);
    let acme_standalone = use_state(AcmeScheduleForm::default);
    let acme_status = use_state(StatusLine::default);
    let acme_jobs = use_state(Vec::<StandaloneAcmeJob>::new);
    let certs = use_state(Vec::<CertificateBundle>::new);
    let cert_form = use_state(CertificateForm::default);
    let cert_status = use_state(StatusLine::default);
    let console_cfg = use_state(AdminConsoleConfig::default);
    let console_status = use_state(StatusLine::default);
    let pools = use_state(Vec::<UpstreamPool>::new);
    let pool_form = use_state(UpstreamPoolForm::default);
    let pool_status = use_state(StatusLine::default);
    let version_info = use_state(|| None::<VersionInfo>);
    let logs = use_state(Vec::<LogEntry>::new);
    let log_filter = use_state(|| "all".to_string());
    let _log_files = use_state(Vec::<LogFileInfo>::new);
    let _log_file_view = use_state(|| None::<(String, String)>);
    let log_files = use_state(Vec::<LogFileInfo>::new);
    let log_file_view = use_state(|| None::<(String, String)>);
    let bulk_json = use_state(|| String::new());
    let bulk_status = use_state(StatusLine::clear);
    let bulk_busy = use_state(|| false);
    let bulk_format = use_state(|| "json".to_string());
    let listener_filter = use_state(|| String::new());
    let listener_page = use_state(|| 1usize);
    let trace_settings = use_state(|| TraceSettings {
        sample_permyriad: 10_000,
    });
    let trace_status = use_state(StatusLine::clear);
    let trace_loading = use_state(|| false);

    let handle_error = {
        let status = status.clone();
        Rc::new(move |err: String| {
            if err.contains("401") || err.to_lowercase().contains("unauthorized") {
                status.set(StatusLine::error("Unauthorized. Please log in again."));
                // Keep current state to avoid bouncing back to the login view in Firefox; user can manually log out if needed.
            } else {
                status.set(StatusLine::error(err));
            }
        })
    };

    {
        let metrics_text = metrics_text.clone();
        let tab = tab.clone();
        let session = session.clone();
        let handle_error = handle_error.clone();
        let metrics_rows = metrics_rows.clone();
        let acme_providers_state = acme_providers.clone();
        let handle_error_acme = handle_error.clone();
        let acme_schedule_state = acme_schedule.clone();
        let acme_standalone_state = acme_standalone.clone();
        let certs_effect = certs.clone();
        let handle_error_cert = handle_error.clone();
        let pools_state = pools.clone();
        let handle_error_pools = handle_error.clone();
        let acme_jobs_state = acme_jobs.clone();
        let version_state = version_info.clone();
        let console_cfg_state = console_cfg.clone();
        let console_status_state = console_status.clone();
        let logs_state = logs.clone();
        let log_files_state = log_files.clone();
        let latency_rows_tab = latency_rows.clone();
        let trace_settings_state = trace_settings.clone();
        let trace_status_state = trace_status.clone();
        let trace_loading_state = trace_loading.clone();
        use_effect_with((*tab).clone(), move |current_tab: &Tab| {
            let metrics_text = metrics_text.clone();
            let metrics_rows = metrics_rows.clone();
            let latency_rows = latency_rows_tab.clone();
            let session = session.clone();
            let acme_providers = acme_providers_state.clone();
            let handle_error_acme = handle_error_acme.clone();
            let acme_schedule_state = acme_schedule_state.clone();
            let certs_state = certs_effect.clone();
            let handle_error_cert = handle_error_cert.clone();
            let pools_state = pools_state.clone();
            let handle_error_pools = handle_error_pools.clone();
            let version_state = version_state.clone();
            let console_cfg_state = console_cfg_state.clone();
            let console_status_state = console_status_state.clone();
            if *current_tab == Tab::Metrics {
                spawn_local(async move {
                    if session.is_none() {
                        return;
                    }
                    match api_metrics().await {
                        Ok(body) => {
                            metrics_rows.set(parse_metrics_summary(&body));
                            latency_rows.set(parse_latency_summary(&body));
                            metrics_text.set(body);
                        }
                        Err(err) => handle_error(err),
                    }
                });
            } else if *current_tab == Tab::Acme {
                spawn_local(async move {
                    if let Some(sess) = session.as_ref() {
                        if sess.role == Role::Admin {
                            match api_acme_providers().await {
                                Ok(list) => acme_providers.set(list),
                                Err(err) => handle_error_acme(err),
                            }
                            match api_certs().await {
                                Ok(list) => certs_state.set(list),
                                Err(err) => handle_error_cert(err),
                            }
                            if let Ok(jobs) = api_acme_jobs().await {
                                acme_jobs_state.set(jobs);
                            }
                            // Reset schedule form defaults when entering the ACME tab.
                            acme_schedule_state.set(AcmeScheduleForm::default());
                            acme_standalone_state.set(AcmeScheduleForm::default());
                        }
                    }
                });
            } else if *current_tab == Tab::Pools {
                spawn_local(async move {
                    if let Some(sess) = session.as_ref() {
                        if sess.role == Role::Admin {
                            match api_pools().await {
                                Ok(list) => pools_state.set(list),
                                Err(err) => handle_error_pools(err),
                            }
                        }
                    }
                });
            } else if version_state.is_none() {
                spawn_local(async move {
                    match api_version().await {
                        Ok(ver) => version_state.set(Some(ver)),
                        Err(err) => handle_error(err),
                    }
                });
            } else if *current_tab == Tab::Listeners {
                spawn_local(async move {
                    if let Ok(console) = api_console().await {
                        console_cfg_state.set(console);
                        console_status_state.set(StatusLine::clear());
                    }
                });
            } else if *current_tab == Tab::Logs {
                let trace_settings = trace_settings_state.clone();
                let trace_status = trace_status_state.clone();
                let trace_loading = trace_loading_state.clone();
                spawn_local(async move {
                    match api_logs().await {
                        Ok(entries) => logs_state.set(entries),
                        Err(err) => handle_error(err),
                    }
                    match api_log_files().await {
                        Ok(files) => log_files_state.set(files),
                        Err(err) => handle_error(err),
                    }
                    trace_loading.set(true);
                    match api_trace_settings().await {
                        Ok(cfg) => {
                            trace_settings.set(cfg);
                            trace_status.set(StatusLine::clear());
                        }
                        Err(err) => trace_status.set(StatusLine::error(err)),
                    }
                    trace_loading.set(false);
                });
            }
            || ()
        });
    }

    {
        let listeners = listeners.clone();
        let stats = stats.clone();
        let loading = loading.clone();
        let session = session.clone();
        let users = users.clone();
        let acme_providers = acme_providers.clone();
        let certs = certs.clone();
        let pools = pools.clone();
        let version_state = version_info.clone();
        let latency_rows_state = latency_rows.clone();
        let metrics_rows_state = metrics_rows.clone();
        let metrics_text_state = metrics_text.clone();
        let log_files_state = log_files.clone();
        let logs_state = logs.clone();
        let handle_error = handle_error.clone();
        let status = status.clone();
        let acme_jobs_handle = acme_jobs.clone();
        use_effect_with((*session).clone(), move |current: &Option<Session>| {
            if let Some(session) = current.clone() {
                loading.set(true);
                spawn_local(async move {
                    match api_listeners().await {
                        Ok(items) => {
                            listeners.set(items);
                            status.set(StatusLine::clear());
                        }
                        Err(err) => handle_error(err),
                    }
                    match api_stats().await {
                        Ok(s) => stats.set(s),
                        Err(err) => handle_error(err),
                    }
                    if let Ok(body) = api_metrics().await {
                        metrics_rows_state.set(parse_metrics_summary(&body));
                        latency_rows_state.set(parse_latency_summary(&body));
                        metrics_text_state.set(body);
                    }
                    if let Ok(files) = api_log_files().await {
                        log_files_state.set(files);
                    }
                    if let Ok(entries) = api_logs().await {
                        logs_state.set(entries);
                    }
                    if session.role == Role::Admin {
                        if let Ok(u) = api_users().await {
                            users.set(u);
                        }
                        if let Ok(p) = api_acme_providers().await {
                            acme_providers.set(p);
                        }
                        if let Ok(c) = api_certs().await {
                            certs.set(c);
                        }
                        if let Ok(pools_resp) = api_pools().await {
                            pools.set(pools_resp);
                        }
                        if let Ok(jobs) = api_acme_jobs().await {
                            acme_jobs_handle.set(jobs);
                        }
                    }
                    if version_state.is_none() {
                        if let Ok(ver) = api_version().await {
                            version_state.set(Some(ver));
                        }
                    }
                    loading.set(false);
                });
            }
            || ()
        });
    }

    {
        let listeners = listeners.clone();
        let stats = stats.clone();
        let users = users.clone();
        let logs_state = logs.clone();
        let handle_error = handle_error.clone();
        use_effect_with((*session).clone(), move |current: &Option<Session>| {
            let current = current.clone();
            let interval = current.as_ref().map(|sess| {
                let listeners = listeners.clone();
                let stats = stats.clone();
                let users = users.clone();
                let logs_state = logs_state.clone();
                let handle_error = handle_error.clone();
                let session_clone = Some(sess.clone());
                Interval::new(5000, move || {
                    let listeners = listeners.clone();
                    let stats = stats.clone();
                    let users = users.clone();
                    let logs_state = logs_state.clone();
                    let handle_error = handle_error.clone();
                    let session_clone = session_clone.clone();
                    spawn_local(async move {
                        match api_listeners().await {
                            Ok(items) => listeners.set(items),
                            Err(err) => handle_error(err),
                        }
                        match api_stats().await {
                            Ok(s) => stats.set(s),
                            Err(err) => handle_error(err),
                        }
                        if let Some(session) = session_clone {
                            if session.role == Role::Admin {
                                if let Ok(u) = api_users().await {
                                    users.set(u);
                                }
                                if let Ok(l) = api_logs().await {
                                    logs_state.set(l);
                                }
                            }
                        }
                    });
                })
            });
            move || {
                if let Some(interval) = interval {
                    drop(interval);
                }
            }
        });
    }

    let on_login = {
        let login_form = login_form.clone();
        let session = session.clone();
        let status = status.clone();
        let listeners = listeners.clone();
        let stats = stats.clone();
        let users = users.clone();
        let tab = tab.clone();
        let handle_error = handle_error.clone();
        Callback::from(move |event: SubmitEvent| {
            event.prevent_default();
            let creds = (*login_form).clone();
            let session = session.clone();
            let status = status.clone();
            let listeners = listeners.clone();
            let stats = stats.clone();
            let users = users.clone();
            let tab = tab.clone();
            let handle_error = handle_error.clone();
            spawn_local(async move {
                match api_login(creds.username, creds.password).await {
                    Ok(sess) => {
                        save_session(&sess);
                        session.set(Some(sess.clone()));
                        tab.set(Tab::Listeners);
                        if let Ok(items) = api_listeners().await {
                            listeners.set(items);
                        }
                        if let Ok(s) = api_stats().await {
                            stats.set(s);
                        }
                        if sess.role == Role::Admin {
                            if let Ok(u) = api_users().await {
                                users.set(u);
                            }
                        }
                        status.set(StatusLine::success("Logged in"));
                    }
                    Err(err) => handle_error(err),
                }
            });
        })
    };

    let on_logout = {
        let session = session.clone();
        let status = status.clone();
        let listeners = listeners.clone();
        let users = users.clone();
        let stats = stats.clone();
        Callback::from(move |_| {
            let session = session.clone();
            let status = status.clone();
            let listeners = listeners.clone();
            let users = users.clone();
            let stats = stats.clone();
            spawn_local(async move {
                if let Some(sess) = (*session).clone() {
                    let _ = api_logout(&sess.token).await;
                }
                clear_session_storage();
                session.set(None);
                listeners.set(vec![]);
                users.set(vec![]);
                stats.set(Stats::default());
                status.set(StatusLine::success("Logged out"));
            });
        })
    };

    let on_submit = {
        let form = form.clone();
        let listeners = listeners.clone();
        let status = status.clone();
        let loading = loading.clone();
        let editing = editing.clone();
        let handle_error = handle_error.clone();
        let pools = pools.clone();
        Callback::from(move |event: SubmitEvent| {
            event.prevent_default();
            let mut working = (*form).clone();
            if working.protocol == Protocol::Tcp && !working.tcp_pool.trim().is_empty() {
                if let Some(pool) = pools.iter().find(|p| p.name == working.tcp_pool) {
                    working.upstreams_text = pool
                        .upstreams
                        .iter()
                        .map(|u| format!("{}={}", u.name, u.address))
                        .collect::<Vec<_>>()
                        .join("\n");
                }
            }
            let payload = match working.to_payload() {
                Ok(payload) => payload,
                Err(msg) => {
                    status.set(StatusLine::error(msg));
                    return;
                }
            };

            let listeners = listeners.clone();
            let status = status.clone();
            let form = form.clone();
            let loading = loading.clone();
            let editing = editing.clone();
            let handle_error = handle_error.clone();
            spawn_local(async move {
                loading.set(true);
                let result = if let Some(id) = *editing {
                    api_update_listener(id, payload).await
                } else {
                    api_create_listener(payload).await
                };

                match result {
                    Ok(listener) => {
                        let mut next = (*listeners).clone();
                        if let Some(idx) = next.iter().position(|l| l.id == listener.id) {
                            next[idx] = listener.clone();
                        } else {
                            next.push(listener.clone());
                        }
                        listeners.set(next);
                        form.set(ListenerForm::default());
                        editing.set(None);
                        status.set(StatusLine::success("Saved listener"));
                    }
                    Err(err) => handle_error(err),
                }
                loading.set(false);
            });
        })
    };

    if session.is_none() {
        return html! {
            <div class="login-shell">
                <div class="login-card">
                    <div style="text-align:center;">
                        <img src="assets/balor.png" alt="Balor logo" class="logo" />
                        <p class="eyebrow">{"Balor Control"}</p>
                        <h1>{"Welcome back"}</h1>
                        <p class="muted">{"Sign in to manage listeners and users."}</p>
                    </div>
                    <form class="form-grid" onsubmit={on_login.clone()}>
                        <label class="field">
                            <span>{"Username"}</span>
                            <input
                                value={login_form.username.clone()}
                                oninput={{
                                    let login_form = login_form.clone();
                                    Callback::from(move |e: InputEvent| {
                                        let mut next = (*login_form).clone();
                                        next.username = event_value(&e);
                                        login_form.set(next);
                                    })
                                }}
                                placeholder="admin"
                                autocomplete="username"
                            />
                        </label>
                        <label class="field">
                            <span>{"Password"}</span>
                            <input
                                type="password"
                                value={login_form.password.clone()}
                                oninput={{
                                    let login_form = login_form.clone();
                                    Callback::from(move |e: InputEvent| {
                                        let mut next = (*login_form).clone();
                                        next.password = event_value(&e);
                                        login_form.set(next);
                                    })
                                }}
                                placeholder="••••••••"
                                autocomplete="current-password"
                            />
                        </label>
                        <div class="actions">
                            <button class="primary" type="submit">{"Login"}</button>
                            <StatusBadge status={(*status).clone()} />
                        </div>
                        <p class="muted">{"Default admin/password comes from BALOR_DEFAULT_ADMIN_PASSWORD (fallback 'admin'). Token is set automatically after login."}</p>
                    </form>
                </div>
            </div>
        };
    }

    let on_delete = {
        let listeners = listeners.clone();
        let status = status.clone();
        let handle_error = handle_error.clone();
        Callback::from(move |id: Uuid| {
            let listeners = listeners.clone();
            let status = status.clone();
            let handle_error = handle_error.clone();
            spawn_local(async move {
                if let Err(err) = api_delete_listener(id).await {
                    handle_error(err);
                    return;
                }
                status.set(StatusLine::success("Deleted listener"));
                let filtered: Vec<_> = listeners.iter().cloned().filter(|l| l.id != id).collect();
                listeners.set(filtered);
            });
        })
    };

    let current_session = session.as_ref().cloned().unwrap();
    let acme_cert_names: HashSet<String> = certs
        .iter()
        .filter(|c| c.source.to_lowercase().contains("acme"))
        .map(|c| c.cert_path.rsplit('/').next().unwrap_or("").to_string())
        .collect();
    let acme_routes: Vec<(Uuid, String, HostRule)> = listeners
        .iter()
        .flat_map(|l| {
            let acme_cert_names = acme_cert_names.clone();
            l.host_routes
                .clone()
                .unwrap_or_default()
                .into_iter()
                .filter_map(move |r| {
                    let cert_match = r
                        .tls
                        .as_ref()
                        .and_then(|t| t.cert_path.rsplit('/').next())
                        .map(|b| acme_cert_names.contains(b))
                        .unwrap_or(false);
                    if r.acme.is_some() || cert_match {
                        Some((l.id, l.name.clone(), r))
                    } else {
                        None
                    }
                })
        })
        .collect();
    let acme_job_cards: Vec<(
        Option<Uuid>,
        String,
        Option<String>,
        Option<AcmeConfig>,
        Option<AcmeStatus>,
        Option<TlsConfig>,
    )> = {
        let mut cards = Vec::new();
        for (lid, _lname, route) in acme_routes.clone() {
            cards.push((
                Some(lid),
                route.host.clone(),
                route.pool.clone(),
                route.acme.clone(),
                route.acme_status.clone(),
                route.tls.clone(),
            ));
        }
        for job in (*acme_jobs).iter() {
            cards.push((
                None,
                job.host.clone(),
                None,
                Some(job.acme.clone()),
                job.status.clone(),
                job.tls.clone(),
            ));
        }
        cards
    };
    let acme_schedule_form = (*acme_schedule).clone();
    let acme_hosts_for_schedule: Vec<String> =
        if let Ok(id) = Uuid::parse_str(&acme_schedule_form.listener) {
            listeners
                .iter()
                .find(|l| l.id == id)
                .and_then(|l| l.host_routes.clone())
                .unwrap_or_default()
                .into_iter()
                .map(|r| r.host)
                .collect()
        } else {
            Vec::new()
        };
    let acme_standalone_form = (*acme_standalone).clone();

    html! {
        <div class="page">
            <header class="hero">
                <div class="brand">
                    <img src="assets/balor.png" alt="Balor logo" class="logo" />
                    <div>
                        <p class="eyebrow">{"Load Balancer L4-L7"}</p>
                        <h1>{"Balor Control"}</h1>
                    </div>
                </div>
                <div class="meta">
                    <div class="pill-row">
                        <button type="button" class={classes!("ghost", if *tab == Tab::Listeners { "pill-on" } else { "" })} onclick={{
                            let tab = tab.clone();
                            Callback::from(move |_| tab.set(Tab::Listeners))
                        }}>{"Listeners"}</button>
                        <button type="button" class={classes!("ghost", if *tab == Tab::Metrics { "pill-on" } else { "" })} onclick={{
                            let tab = tab.clone();
                            Callback::from(move |_| tab.set(Tab::Metrics))
                        }}>{"Metrics"}</button>
                        {
                            if current_session.role == Role::Admin {
                                let tab = tab.clone();
                                html!{
                                    <>
                                        <button
                                            type="button"
                                            class={classes!("ghost", if *tab == Tab::Logs { "pill-on" } else { "" })}
                                            onclick={{
                                                let tab = tab.clone();
                                                Callback::from(move |_| tab.set(Tab::Logs))
                                            }}
                                            aria-label="Logs"
                                        >{"Logs"}</button>
                                        <button
                                            type="button"
                                            class={classes!("ghost", if *tab == Tab::Users { "pill-on" } else { "" })}
                                            onclick={{
                                                let tab = tab.clone();
                                                Callback::from(move |_| tab.set(Tab::Users))
                                            }}
                                            aria-label="Users"
                                        >{"Users"}</button>
                                        <button
                                            type="button"
                                            class={classes!("ghost", if *tab == Tab::Acme { "pill-on" } else { "" })}
                                            onclick={{
                                                let tab = tab.clone();
                                                Callback::from(move |_| tab.set(Tab::Acme))
                                            }}
                                            aria-label="ACME"
                                        >{"ACME"}</button>
                                        <button
                                            type="button"
                                            class={classes!("ghost", if *tab == Tab::Certs { "pill-on" } else { "" })}
                                            onclick={{
                                                let tab = tab.clone();
                                                Callback::from(move |_| tab.set(Tab::Certs))
                                            }}
                                            aria-label="Certificates"
                                        >{"Certificates"}</button>
                                        <button
                                            type="button"
                                            class={classes!("ghost", if *tab == Tab::Pools { "pill-on" } else { "" })}
                                            onclick={{
                                                let tab = tab.clone();
                                                Callback::from(move |_| tab.set(Tab::Pools))
                                            }}
                                            aria-label="Pools"
                                        >{"Pools"}</button>
                                    </>
                                }
                            } else { html!{} }
                        }
                    </div>
                    <div class="auth">
                        <span class="pill">{format!("{} ({:?})", current_session.username, current_session.role)}</span>
                        <button class="ghost" type="button" onclick={on_logout}>{"Logout"}</button>
                    </div>
                </div>
            </header>
            <section class="stat-grid">
                <div class="stat">
                    <p class="eyebrow">{"Listeners"}</p>
                    <h2 class="stat-value">{ (*stats).listener_count }</h2>
                </div>
                <div class="stat">
                    <p class="eyebrow">{"Active runtimes"}</p>
                    <h2 class="stat-value">{ (*stats).active_runtimes }</h2>
                </div>
                <div class="stat">
                    <p class="eyebrow">{"Version"}</p>
                    {
                        if let Some(ver) = (*version_info).clone() {
                            let ui = ver.ui_version.clone();
                            let api = ver.api_version.clone();
                            let build = ver.build.clone();
                            html!{ <h2 class="stat-value">{format!("UI {ui} • API {api} • {build}")}</h2> }
                        } else {
                            html!{ <h2 class="stat-value">{"Loading..."}</h2> }
                        }
                    }
                </div>
            </section>

            <main class="content" style="position:relative; isolation:isolate; min-height:0; overflow:auto;">
                {
                    match *tab {
                        Tab::Listeners => html!{
                            <>
                            <section class="panel">
                                <div class="panel-head">
                                    <div>
                                        <p class="eyebrow">{"Console"}</p>
                                        <h2>{"Admin Console Settings"}</h2>
                                        <p class="muted">{"Port and TLS for the Balor control plane. Requires admin role."}</p>
                                    </div>
                                    <StatusBadge status={(*console_status).clone()} />
                                </div>
                                <div class="form-grid">
                                    <label class="field">
                                        <span>{"Bind address (host:port)"}</span>
                                        <input
                                            value={console_cfg.bind.clone()}
                                            oninput={{
                                                let console_cfg = console_cfg.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*console_cfg).clone();
                                                    next.bind = event_value(&e);
                                                    console_cfg.set(next);
                                                })
                                            }}
                                            placeholder="0.0.0.0:9443"
                                        />
                                    </label>
                                    <label class="field">
                                        <span>{"Console TLS"}</span>
                                        <div class="inline">
                                            <input
                                                type="checkbox"
                                                checked={console_cfg.tls.is_some()}
                                                onchange={{
                                                    let console_cfg = console_cfg.clone();
                                                    Callback::from(move |e: Event| {
                                                        let mut next = (*console_cfg).clone();
                                                        if checkbox_checked(&e) {
                                                            if next.tls.is_none() {
                                                                next.tls = Some(TlsConfig{ cert_path: String::new(), key_path: String::new() });
                                                            }
                                                        } else {
                                                            next.tls = None;
                                                        }
                                                        console_cfg.set(next);
                                                    })
                                                }}
                                            />
                                            <span class="muted">{ if console_cfg.tls.is_some() { "TLS enabled" } else { "TLS disabled" } }</span>
                                        </div>
                                    </label>
                                    {
                                        if let Some(tls) = console_cfg.tls.clone() {
                                            html!{
                                                <>
                                                <label class="field">
                                                    <span>{"Certificate"}</span>
                                                    <select
                                                        onchange={{
                                                            let console_cfg = console_cfg.clone();
                                                            let certs = certs.clone();
                                                            Callback::from(move |e: Event| {
                                                                let mut next = (*console_cfg).clone();
                                                                let name = select_value(&e).unwrap_or_default();
                                                                if let Some(bundle) = certs.iter().find(|c| c.name == name) {
                                                                    if let Some(ref mut cfg) = next.tls {
                                                                        cfg.cert_path = bundle.cert_path.clone();
                                                                        cfg.key_path = bundle.key_path.clone();
                                                                    }
                                                                }
                                                                console_cfg.set(next);
                                                            })
                                                        }}
                                                    >
                                                        <option value="">{"Select certificate"}</option>
                                                        { for certs.iter().map(|c| {
                                                            let selected = match console_cfg.tls.as_ref() {
                                                                Some(t) => t.cert_path == c.cert_path,
                                                                None => false
                                                            };
                                                            html!{ <option value={c.name.clone()} selected={selected}>{format!("{} ({})", c.name, c.source)}</option> }
                                                        })}
                                                    </select>
                                                </label>
                                                {
                                                    if !tls.cert_path.is_empty() {
                                                        html!{
                                                            <div class="pill-row">
                                                                <span class="pill pill-ghost mono">{tls.cert_path}</span>
                                                            </div>
                                                        }
                                                    } else {
                                                        html!{}
                                                    }
                                                }
                                                </>
                                            }
                                        } else { html!{} }
                                    }
                                </div>
                                <div class="actions">
                                    <button type="button" class="primary" onclick={{
                                        let cfg_state = console_cfg.clone();
                                        let console_status = console_status.clone();
                                        let handle_error = handle_error.clone();
                                        Callback::from(move |_| {
                                            let payload = (*cfg_state).clone();
                                            let console_status = console_status.clone();
                                            let handle_error = handle_error.clone();
                                            let cfg_state_inner = cfg_state.clone();
                                            spawn_local(async move {
                                                match api_save_console(payload.clone()).await {
                                                    Ok(updated) => {
                                                        console_status.set(StatusLine::success("Console settings saved. Restart required."));
                                                        cfg_state_inner.set(updated);
                                                    }
                                                    Err(err) => handle_error(err),
                                                }
                                            });
                                        })
                                    }}>{"Save console settings"}</button>
                                    <StatusBadge status={(*console_status).clone()} />
                                </div>
                            </section>
                            <section class="panel">
                                <div class="panel-head">
                                    <div>
                                        <p class="eyebrow">{"Listeners"}</p>
                                        <h2>{"Create Listener"}</h2>
                                        <p class="muted">{"Choose protocol and upstreams; add routing or TLS only if required."}</p>
                                    </div>
                                </div>
                                <form class="form-grid" onsubmit={on_submit}>
                                    <label class="field">
                                        <span>{"Name"}</span>
                                        <input
                                            value={form.name.clone()}
                                            oninput={{
                                                let form = form.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*form).clone();
                                                    next.name = event_value(&e);
                                                    form.set(next);
                                                })
                                            }}
                                            placeholder="Edge HTTP East"
                                        />
                                    </label>
                                    <label class="field">
                                        <span>{"Listen Address"}</span>
                                        <input
                                            value={form.listen.clone()}
                                            oninput={{
                                                let form = form.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*form).clone();
                                                    next.listen = event_value(&e);
                                                    form.set(next);
                                                })
                                            }}
                                            placeholder="0.0.0.0:9000"
                                        />
                                    </label>
                                    <label class="field">
                                        <span>{"Protocol"}</span>
                                        <select
                                            onchange={{
                                                let form = form.clone();
                                                Callback::from(move |e: Event| {
                                                    let mut next = (*form).clone();
                                                    let value = select_value(&e).unwrap_or_else(|| "http".into());
                                                    next.protocol = if value == "tcp" { Protocol::Tcp } else { Protocol::Http };
                                                    if next.protocol == Protocol::Tcp {
                                                        next.tls_enabled = false;
                                                        next.cert_path.clear();
                                                        next.key_path.clear();
                                                        next.acme_enabled = false;
                                                        next.acme_email.clear();
                                                        next.acme_directory.clear();
                                                        next.acme_challenge = AcmeChallenge::Http01;
                                                        next.acme_provider.clear();
                                                        next.sticky = StickyMode::None;
                                                        next.tcp_pool.clear();
                                                    } else {
                                                        next.upstreams_text.clear();
                                                        if next.host_rules.is_empty() {
                                                            next.host_rules.push(HostRuleForm::default());
                                                        }
                                                    }
                                                    form.set(next);
                                                })
                                            }}
                                        >
                                            <option value="http" selected={form.protocol == Protocol::Http}>{"HTTP (L7)"}</option>
                                            <option value="tcp" selected={form.protocol == Protocol::Tcp}>{"TCP (L4)"}</option>
                                        </select>
                                    </label>
                                    {
                                        if form.protocol == Protocol::Http {
                                            html!{
                                                <>
                                                    <label class="field">
                                                        <span>{"Health check path"}</span>
                                                        <input
                                                            value={form.health_path.clone()}
                                                            oninput={{
                                                                let form = form.clone();
                                                                Callback::from(move |e: InputEvent| {
                                                                    let mut next = (*form).clone();
                                                                    next.health_path = event_value(&e);
                                                                    form.set(next);
                                                                })
                                                            }}
                                                            placeholder="/health"
                                                        />
                                                    </label>
                                                    <label class="field span-12">
                                                        <span>{"Health check headers (optional, one per line: Key: Value)"}</span>
                                                        <textarea
                                                            value={form.health_headers.clone()}
                                                            oninput={{
                                                                let form = form.clone();
                                                                Callback::from(move |e: InputEvent| {
                                                                    let mut next = (*form).clone();
                                                                    next.health_headers = textarea_value(&e);
                                                                    form.set(next);
                                                                })
                                                            }}
                                                            placeholder={"User-Agent: Balor-Health\nHost: example.com"}
                                                        />
                                                    </label>
                                                    <label class="field span-12">
                                                        <span>{"Health check script (optional, runs instead of HTTP probe; env TARGET/PROTO set)"}</span>
                                                        <textarea
                                                            value={form.health_script.clone()}
                                                            oninput={{
                                                                let form = form.clone();
                                                                Callback::from(move |e: InputEvent| {
                                                                    let mut next = (*form).clone();
                                                                    next.health_script = textarea_value(&e);
                                                                    form.set(next);
                                                                })
                                                            }}
                                                            placeholder={"curl -fsSL \"$BALOR_HEALTH_TARGET\" -o /dev/null"}
                                                        />
                                                    </label>
                                                </>
                                            }
                                        } else { html!{} }
                                    }
                                    <label class="field">
                                        <span>{"Session affinity"}</span>
                                        <select
                                            disabled={form.protocol == Protocol::Tcp}
                                            onchange={{
                                                let form = form.clone();
                                                Callback::from(move |e: Event| {
                                                    let mut next = (*form).clone();
                                                    let value = select_value(&e).unwrap_or_else(|| "none".into());
                                                    next.sticky = match value.as_str() {
                                                        "cookie" => StickyMode::Cookie,
                                                        "ip_hash" => StickyMode::IpHash,
                                                        _ => StickyMode::None,
                                                    };
                                                    form.set(next);
                                                })
                                            }}
                                        >
                                            <option value="none" selected={form.sticky == StickyMode::None}>{"None (round robin)"}</option>
                                            <option value="cookie" selected={form.sticky == StickyMode::Cookie}>{"Cookie (per upstream)"}</option>
                                            <option value="ip_hash" selected={form.sticky == StickyMode::IpHash}>{"Client IP hash"}</option>
                                        </select>
                                    </label>
                                    <label class="field">
                                        <span>{"Enabled"}</span>
                                        <div style="display:flex; align-items:center; gap:10px;">
                                            <span class={classes!("pill", if form.enabled { "pill-on" } else { "pill-error" })}>
                                                { if form.enabled { "On" } else { "Off" } }
                                            </span>
                                            <input
                                                type="checkbox"
                                                aria-label="Toggle listener enabled"
                                                checked={form.enabled}
                                                onchange={{
                                                    let form = form.clone();
                                                    Callback::from(move |e: Event| {
                                                        let mut next = (*form).clone();
                                                        next.enabled = checkbox_checked(&e);
                                                        form.set(next);
                                                    })
                                                }}
                                                style="width:18px; height:18px; accent-color:#2563eb;"
                                            />
                                        </div>
                                    </label>
                                    {
                                        if form.protocol == Protocol::Tcp {
                                            html!{
                                                <div class="panel compact span-12">
                                                    <div class="panel-head">
                                                        <span>{"Upstream pool (TCP)"}</span>
                                                        <p class="hint">{"Pick a pool; its endpoints will be used automatically."}</p>
                                                    </div>
                                                    <label class="field">
                                                        <span>{"Pool (required)"}</span>
                                                        <select
                                                            onchange={{
                                                                let form = form.clone();
                                                                let pools = pools.clone();
                                                                Callback::from(move |e: Event| {
                                                                    let mut next = (*form).clone();
                                                                    let val = select_value(&e).unwrap_or_default();
                                                                    next.tcp_pool = val.clone();
                                                                    if !val.is_empty() {
                                                                        if let Some(pool) = pools.iter().find(|p| p.name == val) {
                                                                            next.upstreams_text = pool
                                                                                .upstreams
                                                                                .iter()
                                                                            .map(|u| format!("{}={} {}", u.name, u.address, u.weight.unwrap_or(1)))
                                                                                .collect::<Vec<_>>()
                                                                                .join("\n");
                                                                        }
                                                                    } else {
                                                                        next.upstreams_text.clear();
                                                                    }
                                                                    form.set(next);
                                                                })
                                                            }}
                                                        >
                                                            <option value="" selected={form.tcp_pool.is_empty()}>{"Select pool"}</option>
                                                            { for pools.iter().map(|p| {
                                                                html!{ <option value={p.name.clone()} selected={form.tcp_pool == p.name}>{&p.name}</option> }
                                                            }) }
                                                        </select>
                                                    </label>
                                                </div>
                                            }
                                        } else { html!{} }
                                    }
                                    {
                                        if form.protocol == Protocol::Http {
                                            html!{
                                                <div class="panel compact span-12 host-routes-only tall" style="grid-column: 1 / -1; width: 100%;">
                                                    <div class="panel-head inline-head">
                                                        <div>
                                                            <span>{"Host-based routes"}</span>
                                                            <p class="hint">{"Provide at least one host. Add more routes if you need separate pools or certs."}</p>
                                                        </div>
                                                        <div class="pill-row">
                                                            <button class="primary pill" type="button" onclick={{
                                                                let form = form.clone();
                                                                Callback::from(move |_| {
                                                                    let mut next = (*form).clone();
                                                                    next.host_rules.push(HostRuleForm::default());
                                                                    form.set(next);
                                                                })
                                                            }}>{"Add host route"}</button>
                                                            <span class="pill pill-ghost">{format!("{} route(s)", form.host_rules.len())}</span>
                                                        </div>
                                                    </div>
                                                    <div class="host-routes-grid wide roomy">
                                                        { for form.host_rules.iter().enumerate().map(|(idx, rule)| {
                                                            let form = form.clone();
                                                            html!{
                                                                <div class="host-route-card" style="border: 1px solid #e5e7eb; border-radius: 16px; padding: 16px; box-shadow: 0 10px 24px rgba(15,23,42,0.05); background: #fff; display: grid; grid-template-columns: repeat(12, 1fr); gap: 12px;">
                                                                    <div class="route-head" style="grid-column: 1 / -1; display: flex; align-items: center; gap: 12px;">
                                                                        <label class="field grow" style="flex: 1;">
                                                                            <span>{"Hostname"}</span>
                                                                            <input
                                                                                value={rule.host.clone()}
                                                                                placeholder="app.example.com"
                                                                                oninput={{
                                                                                    let form = form.clone();
                                                                                    Callback::from(move |e: InputEvent| {
                                                                                        let mut next = (*form).clone();
                                                                                        if let Some(r) = next.host_rules.get_mut(idx) {
                                                                                            r.host = event_value(&e);
                                                                                        }
                                                                                        form.set(next);
                                                                                    })
                                                                                }}
                                                                            />
                                                                        </label>
                                                                        <span class="pill pill-ghost">{format!("Route {}", idx + 1)}</span>
                                                                        <div style="display:flex; align-items:center; gap:10px;">
                                                                            <label style="display:flex; align-items:center; gap:8px; padding:6px 12px; border-radius:12px; background:linear-gradient(120deg,#eef2ff,#f8fafc); box-shadow:0 6px 18px rgba(15,23,42,0.08);">
                                                                                <span class="muted">{"Enabled"}</span>
                                                                                <span class={classes!("pill", if rule.enabled { "pill-on" } else { "pill-error" })}>
                                                                                    { if rule.enabled { "On" } else { "Off" } }
                                                                                </span>
                                                                                <input
                                                                                    type="checkbox"
                                                                                    aria-label="Toggle host route enabled"
                                                                                    checked={rule.enabled}
                                                                                    onchange={{
                                                                                        let form = form.clone();
                                                                                        Callback::from(move |e: Event| {
                                                                                            let mut next = (*form).clone();
                                                                                            if let Some(r) = next.host_rules.get_mut(idx) {
                                                                                                r.enabled = checkbox_checked(&e);
                                                                                            }
                                                                                            form.set(next);
                                                                                        })
                                                                                    }}
                                                                                    style="width:16px; height:16px; accent-color:#2563eb;"
                                                                                />
                                                                            </label>
                                                                            <label style="display:flex; align-items:center; gap:8px; padding:6px 12px; border-radius:12px; background:linear-gradient(120deg,#e7f5ff,#f0fbff); box-shadow:0 6px 18px rgba(15,23,42,0.08);">
                                                                                <span class="muted">{"TLS"}</span>
                                                                                <span class={classes!("pill", if rule.tls_enabled { "pill-on" } else { "pill-error" })}>
                                                                                    { if rule.tls_enabled { "On" } else { "Off" } }
                                                                                </span>
                                                                                <input
                                                                                    type="checkbox"
                                                                                    aria-label="Toggle TLS for host"
                                                                                    checked={rule.tls_enabled}
                                                                                    onchange={{
                                                                                        let form = form.clone();
                                                                                    Callback::from(move |e: Event| {
                                                                                        let mut next = (*form).clone();
                                                                                        if let Some(r) = next.host_rules.get_mut(idx) {
                                                                                            r.tls_enabled = checkbox_checked(&e);
                                                                                        }
                                                                                        form.set(next);
                                                                                    })
                                                                                }}
                                                                                    style="width:16px; height:16px; accent-color:#2563eb;"
                                                                                />
                                                                            </label>
                                                                        </div>
                                                                        <button class="ghost pill" type="button" disabled={form.host_rules.len() == 1} onclick={{
                                                                            let form = form.clone();
                                                                            Callback::from(move |_| {
                                                                                let mut next = (*form).clone();
                                                                                next.host_rules.remove(idx);
                                                                                form.set(next);
                                                                            })
                                                                        }}>{"Remove"}</button>
                                                                    </div>
                                                                    {
                                                                        if rule.tls_enabled {
                                                                            html!{
                                                                                <>
                                                                                <label class="field" style="grid-column: span 6;">
                                                                                    <span>{"Pool"}</span>
                                                                                    <select
                                                                                        onchange={{
                                                                                            let form = form.clone();
                                                                                            Callback::from(move |e: Event| {
                                                                                                let mut next = (*form).clone();
                                                                                                if let Some(r) = next.host_rules.get_mut(idx) {
                                                                                                    r.pool = select_value(&e).unwrap_or_default();
                                                                                                }
                                                                                                form.set(next);
                                                                                            })
                                                                                        }}
                                                                                    >
                                                                                        <option value="" selected={rule.pool.is_empty()}>{"Select pool (required)"}</option>
                                                                                        { for pools.iter().map(|p| {
                                                                                            html!{ <option value={p.name.clone()} selected={rule.pool == p.name}>{&p.name}</option> }
                                                                                        })}
                                                                                    </select>
                                                                                </label>
                                                                                <label class="field" style="grid-column: span 6;">
                                                                                    <span>{"Dedicated certificate (optional)"}</span>
                                                                                    <select
                                                                                        onchange={{
                                                                                            let form = form.clone();
                                                                                            let certs = certs.clone();
                                                                                            Callback::from(move |e: Event| {
                                                                                                let mut next = (*form).clone();
                                                                                                if let Some(r) = next.host_rules.get_mut(idx) {
                                                                                                    let name = select_value(&e).unwrap_or_default();
                                                                                                    r.selected_cert = name.clone();
                                                                                                    if let Some(bundle) = certs.iter().find(|c| c.name == name) {
                                                                                                        r.cert_path = bundle.cert_path.clone();
                                                                                                        r.key_path = bundle.key_path.clone();
                                                                                                    } else {
                                                                                                        r.cert_path.clear();
                                                                                                        r.key_path.clear();
                                                                                                    }
                                                                                                }
                                                                                                form.set(next);
                                                                                            })
                                                                                        }}
                                                                                    >
                                                                                        <option value="" selected={rule.selected_cert.is_empty()}>{"Use listener/default"}</option>
                                                                                        { for certs.iter().map(|c| {
                                                                                            html!{ <option value={c.name.clone()} selected={rule.selected_cert == c.name}>{format!("{} ({})", c.name, c.source)}</option> }
                                                                                        }) }
                                                                                    </select>
                                                                                </label>
                                                                                <label class="field" style="grid-column: span 3;">
                                                                                    <span>{"Rate limit RPS"}</span>
                                                                                    <input
                                                                                        type="number"
                                                                                        min="0"
                                                                                        value={rule.rate_rps.clone()}
                                                                                        oninput={{
                                                                                            let form = form.clone();
                                                                                            Callback::from(move |e: InputEvent| {
                                                                                                let mut next = (*form).clone();
                                                                                                if let Some(r) = next.host_rules.get_mut(idx) {
                                                                                                    r.rate_rps = event_value(&e);
                                                                                                }
                                                                                                form.set(next);
                                                                                            })
                                                                                        }}
                                                                                        placeholder="e.g. 50"
                                                                                    />
                                                                                </label>
                                                                                <label class="field" style="grid-column: span 3;">
                                                                                    <span>{"Burst"}</span>
                                                                                    <input
                                                                                        type="number"
                                                                                        min="0"
                                                                                        value={rule.rate_burst.clone()}
                                                                                        oninput={{
                                                                                            let form = form.clone();
                                                                                            Callback::from(move |e: InputEvent| {
                                                                                                let mut next = (*form).clone();
                                                                                                if let Some(r) = next.host_rules.get_mut(idx) {
                                                                                                    r.rate_burst = event_value(&e);
                                                                                                }
                                                                                                form.set(next);
                                                                                            })
                                                                                        }}
                                                                                        placeholder="e.g. 100"
                                                                                    />
                                                                                </label>
                                                                                </>
                                                                            }
                                                                        } else {
                                                                            html!{
                                                                                <>
                                                                                    <label class="field" style="grid-column: span 12;">
                                                                                        <span>{"Pool"}</span>
                                                                                        <select
                                                                                            onchange={{
                                                                                                let form = form.clone();
                                                                                                Callback::from(move |e: Event| {
                                                                                                    let mut next = (*form).clone();
                                                                                                    if let Some(r) = next.host_rules.get_mut(idx) {
                                                                                                        r.pool = select_value(&e).unwrap_or_default();
                                                                                                    }
                                                                                                    form.set(next);
                                                                                                })
                                                                                            }}
                                                                                        >
                                                                                            <option value="" selected={rule.pool.is_empty()}>{"Select pool (required)"}</option>
                                                                                            { for pools.iter().map(|p| {
                                                                                                html!{ <option value={p.name.clone()} selected={rule.pool == p.name}>{&p.name}</option> }
                                                                                            })}
                                                                                        </select>
                                                                                    </label>
                                                                                    <label class="field" style="grid-column: span 3;">
                                                                                        <span>{"Rate limit RPS"}</span>
                                                                                        <input
                                                                                            type="number"
                                                                                            min="0"
                                                                                            value={rule.rate_rps.clone()}
                                                                                            oninput={{
                                                                                                let form = form.clone();
                                                                                                Callback::from(move |e: InputEvent| {
                                                                                                    let mut next = (*form).clone();
                                                                                                    if let Some(r) = next.host_rules.get_mut(idx) {
                                                                                                        r.rate_rps = event_value(&e);
                                                                                                    }
                                                                                                    form.set(next);
                                                                                                })
                                                                                            }}
                                                                                            placeholder="e.g. 50"
                                                                                        />
                                                                                    </label>
                                                                                    <label class="field" style="grid-column: span 3;">
                                                                                        <span>{"Burst"}</span>
                                                                                        <input
                                                                                            type="number"
                                                                                            min="0"
                                                                                            value={rule.rate_burst.clone()}
                                                                                            oninput={{
                                                                                                let form = form.clone();
                                                                                                Callback::from(move |e: InputEvent| {
                                                                                                    let mut next = (*form).clone();
                                                                                                    if let Some(r) = next.host_rules.get_mut(idx) {
                                                                                                        r.rate_burst = event_value(&e);
                                                                                                    }
                                                                                                    form.set(next);
                                                                                                })
                                                                                            }}
                                                                                            placeholder="e.g. 100"
                                                                                        />
                                                                                    </label>
                                                                                </>
                                                                            }
                                                                        }
                                                                    }
                                                                    <div class="route-row" style="grid-column: 1 / -1;">
                                                                        <p class="muted">{"Upstreams come from the selected pool."}</p>
                                                                    </div>
                                                                </div>
                                                            }
                                                        }) }
                                                        { if form.host_rules.is_empty() { html!{<p class="muted">{"No host rules yet. Add at least one host to save."}</p>} } else { html!{} } }
                                                    </div>
                                                </div>
                                            }
                                        } else { html!{} }
                                    }
                                    <div class={classes!("actions", "span-12")}>
                                        <div class="actions-left">
                                            <button class="primary" type="submit" disabled={*loading}>
                                                { if editing.is_some() { "Update listener" } else { "Save listener" } }
                                            </button>
                                            {
                                                if editing.is_some() {
                                                    let form = form.clone();
                                                    let editing = editing.clone();
                                                    let status = status.clone();
                                                    html!{
                                                        <button class="ghost" type="button" onclick={Callback::from(move |_| {
                                                            form.set(ListenerForm::default());
                                                            editing.set(None);
                                                            status.set(StatusLine::clear());
                                                        })}>{"Cancel edit"}</button>
                                                    }
                                                } else { html!{} }
                                            }
                                        </div>
                                        <StatusBadge status={(*status).clone()} />
                                    </div>
                                </form>
                            </section>

                            <section class="panel">
                                <div class="panel-head">
                                    <div>
                                        <p class="eyebrow">{"Bulk import / export"}</p>
                                        <h2>{"Share listener configs"}</h2>
                                        <p class="muted">{"Export listeners as JSON or YAML, edit offline, then import to recreate them."}</p>
                                    </div>
                                    <StatusBadge status={(*bulk_status).clone()} />
                                </div>
                                <div class="pill-row wrap" style="margin-bottom:12px;">
                                    <span class="pill pill-ghost">{"Format"}</span>
                                    {
                                        for ["json","yaml"].iter().map(|fmt| {
                                            let bulk_format = bulk_format.clone();
                                            let active = *fmt == bulk_format.as_str();
                                            html!{
                                                <button type="button" class={classes!("ghost", if active { "pill-on" } else { "" })} onclick={{
                                                    let bulk_format = bulk_format.clone();
                                                    let fmt = (*fmt).to_string();
                                                    Callback::from(move |_| bulk_format.set(fmt.clone()))
                                                }}>{fmt.to_uppercase()}</button>
                                            }
                                        })
                                    }
                                    <button type="button" class="ghost" disabled={*bulk_busy} onclick={{
                                        let bulk_json = bulk_json.clone();
                                        let bulk_status = bulk_status.clone();
                                        let bulk_busy = bulk_busy.clone();
                                        let bulk_format = bulk_format.clone();
                                        let handle_error = handle_error.clone();
                                        Callback::from(move |_| {
                                            let bulk_json = bulk_json.clone();
                                            let bulk_status = bulk_status.clone();
                                            let bulk_busy = bulk_busy.clone();
                                            let bulk_format = bulk_format.clone();
                                            let handle_error = handle_error.clone();
                                            spawn_local(async move {
                                                bulk_busy.set(true);
                                                match api_listeners().await {
                                                    Ok(list) => {
                                                        let serialized: Result<String, String> = if bulk_format.as_str() == "yaml" {
                                                            serde_yaml::to_string(&list).map_err(|e| e.to_string())
                                                        } else {
                                                            serde_json::to_string_pretty(&list).map_err(|e| e.to_string())
                                                        };
                                                        match serialized {
                                                            Ok(text) => {
                                                                bulk_json.set(text);
                                                                bulk_status.set(StatusLine::success("Exported current listeners"));
                                                            }
                                                            Err(e) => bulk_status.set(StatusLine::error(format!("Serialize failed: {e}"))),
                                                        }
                                                    }
                                                    Err(err) => {
                                                        handle_error(err.clone());
                                                        bulk_status.set(StatusLine::error(err));
                                                    }
                                                }
                                                bulk_busy.set(false);
                                            });
                                        })
                                    }}>{"Export"}</button>
                                    <button type="button" class="ghost" disabled={*bulk_busy} onclick={{
                                        let bulk_format = bulk_format.clone();
                                        let handle_error = handle_error.clone();
                                        Callback::from(move |_| {
                                            let fmt = bulk_format.as_str().to_string();
                                            let handle_error = handle_error.clone();
                                            spawn_local(async move {
                                                match api_listeners().await {
                                                    Ok(list) => {
                                                        if fmt == "yaml" {
                                                            match serde_yaml::to_string(&list) {
                                                                Ok(body) => download_text_file("listeners.yaml", &body, "application/x-yaml"),
                                                                Err(e) => handle_error(format!("Download failed: {e}")),
                                                            }
                                                        } else {
                                                            match serde_json::to_string_pretty(&list) {
                                                                Ok(body) => download_text_file("listeners.json", &body, "application/json"),
                                                                Err(e) => handle_error(format!("Download failed: {e}")),
                                                            }
                                                        }
                                                    }
                                                    Err(err) => handle_error(err),
                                                }
                                            });
                                        })
                                    }}>{"Download file"}</button>
                                    <button type="button" class="primary" disabled={*bulk_busy} onclick={{
                                        let bulk_json = bulk_json.clone();
                                        let bulk_status = bulk_status.clone();
                                        let bulk_busy = bulk_busy.clone();
                                        let listeners = listeners.clone();
                                        let handle_error = handle_error.clone();
                                        Callback::from(move |_| {
                                            let bulk_json = (*bulk_json).clone();
                                            let bulk_status = bulk_status.clone();
                                            let bulk_busy = bulk_busy.clone();
                                            let listeners = listeners.clone();
                                            let handle_error = handle_error.clone();
                                            spawn_local(async move {
                                                bulk_busy.set(true);
                                                let payloads: Result<Vec<ListenerPayload>, String> = (|| {
                                                    if bulk_json.trim().is_empty() {
                                                        return Err("Paste listener JSON before importing".into());
                                                    }
                                                    if let Ok(p) = serde_json::from_str::<Vec<ListenerPayload>>(&bulk_json) {
                                                        return Ok(p);
                                                    }
                                                    if let Ok(p) = serde_yaml::from_str::<Vec<ListenerPayload>>(&bulk_json) {
                                                        return Ok(p);
                                                    }
                                                    if let Ok(list) = serde_json::from_str::<Vec<Listener>>(&bulk_json) {
                                                        let mut payloads = Vec::new();
                                                        for l in list {
                                                            let form = ListenerForm::from_listener(&l);
                                                            payloads.push(form.to_payload()?);
                                                        }
                                                        return Ok(payloads);
                                                    }
                                                    if let Ok(list) = serde_yaml::from_str::<Vec<Listener>>(&bulk_json) {
                                                        let mut payloads = Vec::new();
                                                        for l in list {
                                                            let form = ListenerForm::from_listener(&l);
                                                            payloads.push(form.to_payload()?);
                                                        }
                                                        return Ok(payloads);
                                                    }
                                                    Err("Could not parse payload. Expect an array of listeners (JSON or YAML).".into())
                                                })();

                                                match payloads {
                                                    Err(msg) => {
                                                        bulk_status.set(StatusLine::error(msg));
                                                        bulk_busy.set(false);
                                                    }
                                                    Ok(payloads) => {
                                                        let mut names = HashSet::new();
                                                        let mut binds = HashSet::new();
                                                        for p in &payloads {
                                                            if !names.insert(p.name.clone()) {
                                                                bulk_status.set(StatusLine::error(format!("Duplicate listener name in import: {}", p.name)));
                                                                bulk_busy.set(false);
                                                                return;
                                                            }
                                                            if !binds.insert(p.listen.clone()) {
                                                                bulk_status.set(StatusLine::error(format!("Duplicate listen address in import: {}", p.listen)));
                                                                bulk_busy.set(false);
                                                                return;
                                                            }
                                                        }
                                                        if let Some(dup) = payloads.iter().find(|p| listeners.iter().any(|e| e.name == p.name || e.listen == p.listen)) {
                                                            bulk_status.set(StatusLine::error(format!("Listener already exists (name or bind): {}", dup.name)));
                                                            bulk_busy.set(false);
                                                            return;
                                                        }
                                                        let mut imported = 0usize;
                                                        for payload in payloads {
                                                            match api_create_listener(payload).await {
                                                                Ok(_) => imported += 1,
                                                                Err(err) => {
                                                                    handle_error(err.clone());
                                                                    bulk_status.set(StatusLine::error(format!("Stopped at listener {imported}: {err}")));
                                                                    bulk_busy.set(false);
                                                                    return;
                                                                }
                                                            }
                                                        }
                                                        match api_listeners().await {
                                                            Ok(updated) => listeners.set(updated),
                                                            Err(err) => handle_error(err),
                                                        }
                                                        bulk_status.set(StatusLine::success(format!("Imported {imported} listener(s)")));
                                                        bulk_busy.set(false);
                                                    }
                                                }
                                            });
                                        })
                                    }}>{"Import"}</button>
                                    <span class="pill pill-ghost">{ if *bulk_busy { "Working..." } else { "Paste array of listeners and click Import" } }</span>
                                </div>
                                <label class="field span-3">
                                    <span>{"Buffer (JSON or YAML)"}</span>
                                    <textarea
                                        rows="6"
                                        placeholder="[ { \"name\": \"edge\", ... } ]"
                                        value={(*bulk_json).clone()}
                                        oninput={{
                                            let bulk_json = bulk_json.clone();
                                            Callback::from(move |e: InputEvent| {
                                                bulk_json.set(textarea_value(&e));
                                            })
                                        }}
                                    />
                                </label>
                            </section>

                            <section class="panel">
                                <div class="panel-head">
                                    <h2>{"Active Listeners"}</h2>
                                    { if *loading { html!{<span class="pill pill-ghost">{"Loading..."}</span>} } else { html!{} } }
                                </div>
                                <div class="pill-row wrap" style="margin-bottom:12px;">
                                    <label class="field" style="min-width:220px;">
                                        <span class="muted">{"Search listeners"}</span>
                                        <input
                                            placeholder="Filter by name or host"
                                            value={listener_filter.as_str().to_string()}
                                            oninput={{
                                                let listener_filter = listener_filter.clone();
                                                let listener_page = listener_page.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    listener_filter.set(event_value(&e));
                                                    listener_page.set(1);
                                                })
                                            }}
                                        />
                                    </label>
                                    <span class="pill pill-ghost">{ format!("Total: {}", listeners.len()) }</span>
                                </div>
                                {
                                    {
                                        let filter = listener_filter.as_str().to_lowercase();
                                        let filtered: Vec<_> = listeners.iter().cloned().filter(|l| {
                                            if filter.is_empty() { return true; }
                                            let mut haystack = l.name.to_lowercase();
                                            haystack.push_str(&l.listen.to_lowercase());
                                            if let Some(routes) = &l.host_routes {
                                                for r in routes {
                                                    haystack.push_str(&r.host.to_lowercase());
                                                }
                                            }
                                            haystack.contains(&filter)
                                        }).collect();
                                        let page_size = 6usize;
                                        let total_pages = (filtered.len() + page_size - 1).max(1) / page_size;
                                        let current = listener_page.max(1).min(total_pages);
                                        let start = (current - 1) * page_size;
                                        let slice = filtered.iter().skip(start).take(page_size).cloned().collect::<Vec<_>>();
                                        html!{
                                            <>
                                                <div class="pill-row wrap" style="margin-bottom:12px;">
                                                    <span class="pill pill-ghost">{ format!("Page {}/{}", current, total_pages.max(1)) }</span>
                                                    <button type="button" class="ghost" disabled={current <= 1} onclick={{
                                                        let listener_page = listener_page.clone();
                                                        Callback::from(move |_| listener_page.set(current.saturating_sub(1)))
                                                    }}>{"Prev"}</button>
                                                    <button type="button" class="ghost" disabled={current >= total_pages} onclick={{
                                                        let listener_page = listener_page.clone();
                                                        let total = total_pages;
                                                        Callback::from(move |_| listener_page.set((current + 1).min(total)))
                                                    }}>{"Next"}</button>
                                                    <span class="pill pill-ghost">{ format!("Showing {} of {}", slice.len(), filtered.len()) }</span>
                                                </div>
                                                {
                                                    if filtered.is_empty() {
                                                        html!{<p class="muted">{"No listeners match your search."}</p>}
                                                    } else {
                                                        html!{
                                                            <div class="cards">
                                                                { for slice.iter().map(|l| render_listener(l.clone(), on_delete.clone(), {
                                                                    let form = form.clone();
                                                                    let editing = editing.clone();
                                                                    Callback::from(move |listener: Listener| {
                                                                        form.set(ListenerForm::from_listener(&listener));
                                                                        editing.set(Some(listener.id));
                                                                    })
                                                                })) }
                                                            </div>
                                                        }
                                                    }
                                                }
                                            </>
                                        }
                                    }
                                }
                            </section>
                            </>
                        },
                        Tab::Metrics => html!{
                            <section class="panel metrics-panel">
                                <div class="panel-head">
                                    <div>
                                        <p class="eyebrow">{"Prometheus"}</p>
                                        <h2>{"Metrics snapshot"}</h2>
                                        <p class="muted">{"Live /metrics output for dashboards and scraping."}</p>
                                    </div>
                                    <div class="pill-row">
                                        <button type="button" class="ghost" onclick={{
                                            let status = status.clone();
                                            let metrics_text = metrics_text.clone();
                                            let metrics_rows = metrics_rows.clone();
                                            let handle_error = handle_error.clone();
                                            Callback::from(move |_| {
                                                let status = status.clone();
                                                let metrics_text = metrics_text.clone();
                                                let metrics_rows = metrics_rows.clone();
                                                let handle_error = handle_error.clone();
                                                spawn_local(async move {
                                                    match api_metrics().await {
                                                        Ok(body) => {
                                                            metrics_rows.set(parse_metrics_summary(&body));
                                                            metrics_text.set(body);
                                                            status.set(StatusLine::success("Metrics refreshed (preview)"));
                                                        }
                                                        Err(err) => handle_error(err),
                                                    }
                                                });
                                            })
                                        }} aria-label="Refresh metrics">{"Refresh"}</button>
                                        <button type="button" class="ghost" onclick={Callback::from(move |_| {
                                            if let Some(win) = web_sys::window() {
                                                let _ = win.open_with_url_and_target("/metrics", "_blank");
                                            }
                                        })} aria-label="Open metrics in new tab">{"Open /metrics in new tab"}</button>
                                    </div>
                                </div>
                                <div class="metrics-block">
                                    <pre>{ (*metrics_text).clone() }</pre>
                                </div>
                                {
                                    if !metrics_rows.is_empty() {
                                        let max = metrics_rows.iter().fold(0f64, |m, r| m.max(r.value));
                                        html!{
                                            <div class="metrics-cards">
                                                { for metrics_rows.iter().map(|row| {
                                                    let pct = if max > 0.0 { (row.value / max * 100.0).min(100.0) } else { 0.0 };
                                                    html!{
                                                        <article class="metric-card">
                                                            <div class="metric-head">
                                                                <span class="pill pill-ghost mono">{ &row.listener }</span>
                                                                <span class="pill">{ format!("{}", row.status.to_uppercase()) }</span>
                                                            </div>
                                                            <div class="bar">
                                                                <div class="fill" style={format!("width:{:.1}%;", pct)}></div>
                                                            </div>
                                                            <p class="muted">{ format!("{:.0} requests", row.value) }</p>
                                                        </article>
                                                    }
                                                }) }
                                            </div>
                                        }
                                    } else {
                                        html!{<p class="muted">{"Waiting for metrics scrape..."}</p>}
                                    }
                                }

                                <div class="panel-head" style="margin-top:24px;">
                                    <div>
                                        <p class="eyebrow">{"Latency (histogram buckets)"}</p>
                                        <h3>{"P50 / P95 / P99 by listener"}</h3>
                                        <p class="muted">{"Approximate quantiles derived from Prometheus buckets."}</p>
                                    </div>
                                </div>
                                {
                                    if !latency_rows.is_empty() {
                                        html!{
                                            <div class="cards">
                                                { for latency_rows.iter().map(|row| {
                                                    html!{
                                                        <article class="card">
                                                            <div class="card-head">
                                                                <div>
                                                                    <p class="eyebrow">{"Listener"}</p>
                                                                    <h3 class="mono">{ &row.listener }</h3>
                                                                    <p class="muted">{format!("{:.0} samples", row.count)}</p>
                                                                </div>
                                                            </div>
                                                            <div class="pill-row wrap">
                                                                <span class="pill pill-ghost">{format!("p50 ≈ {:.3}s", row.p50)}</span>
                                                                <span class="pill pill-ghost">{format!("p95 ≈ {:.3}s", row.p95)}</span>
                                                                <span class="pill pill-ghost">{format!("p99 ≈ {:.3}s", row.p99)}</span>
                                                            </div>
                                                            <div class="bar">
                                                                <div class="fill" style={format!("width:{:.1}%;", (row.p95 / row.p99.max(0.001) * 100.0).min(100.0))}></div>
                                                            </div>
                                                        </article>
                                                    }
                                                }) }
                                            </div>
                                        }
                                    } else {
                                        html!{<p class="muted">{"Latency data not yet available."}</p>}
                                    }
                                }
                            </section>
                        },
                        Tab::Logs => html!{
                            <section class="panel">
                                <div class="panel-head">
                                    <div>
                                        <p class="eyebrow">{"Logs"}</p>
                                        <h2>{"Recent server logs"}</h2>
                                        <p class="muted">{"Filtered log feed with optional file download."}</p>
                                    </div>
                                    <div class="pill-row">
                                        <button type="button" class="ghost" onclick={{
                                            let logs = logs.clone();
                                            let log_files = log_files.clone();
                                            let handle_error = handle_error.clone();
                                            Callback::from(move |_| {
                                                let logs = logs.clone();
                                                let log_files = log_files.clone();
                                                let handle_error = handle_error.clone();
                                                spawn_local(async move {
                                                    match api_logs().await {
                                                        Ok(entries) => logs.set(entries),
                                                        Err(err) => handle_error(err),
                                                    }
                                                    match api_log_files().await {
                                                        Ok(files) => log_files.set(files),
                                                        Err(err) => handle_error(err),
                                                    }
                                                });
                                            })
                                        }}>{"Refresh"}</button>
                                        <select onchange={{
                                            let log_filter = log_filter.clone();
                                            Callback::from(move |e: Event| {
                                                if let Some(val) = select_value(&e) {
                                                    log_filter.set(val);
                                                }
                                            })
                                        }}>
                                            <option value="all" selected={log_filter.as_str() == "all"}>{"All"}</option>
                                            <option value="info" selected={log_filter.as_str() == "info"}>{"Info"}</option>
                                            <option value="warn" selected={log_filter.as_str() == "warn"}>{"Warn"}</option>
                                            <option value="error" selected={log_filter.as_str() == "error"}>{"Error"}</option>
                                        </select>
                                    </div>
                                </div>
                                <div class="pill-row wrap" style="margin-bottom:12px;">
                                    <span class="pill pill-ghost">{"Trace sampling"}</span>
                                    {
                                        for [100,50,10].iter().map(|pct| {
                                            let trace_settings = trace_settings.clone();
                                            let trace_status = trace_status.clone();
                                            let handle_error = handle_error.clone();
                                            let trace_loading = trace_loading.clone();
                                            html!{
                                                <button type="button" class="ghost" disabled={*trace_loading} onclick={{
                                                    let trace_settings = trace_settings.clone();
                                                    let trace_status = trace_status.clone();
                                                    let handle_error = handle_error.clone();
                                                    let trace_loading = trace_loading.clone();
                                                    let val = (*pct as u64) * 100;
                                                    Callback::from(move |_| {
                                                        let trace_settings = trace_settings.clone();
                                                        let trace_status = trace_status.clone();
                                                        let handle_error = handle_error.clone();
                                                        let trace_loading = trace_loading.clone();
                                                        spawn_local(async move {
                                                            trace_loading.set(true);
                                                            if let Err(err) = api_set_trace_settings(val).await {
                                                                handle_error(err);
                                                            } else {
                                                                trace_settings.set(TraceSettings{ sample_permyriad: val });
                                                                trace_status.set(StatusLine::success("Sampling updated"));
                                                            }
                                                            trace_loading.set(false);
                                                        });
                                                    })
                                                }}>{format!("{pct}%")}</button>
                                            }
                                        })
                                    }
                                    <input
                                        type="range"
                                        min="1"
                                        max="100"
                                        value={(trace_settings.sample_permyriad / 100).to_string()}
                                        oninput={{
                                            let trace_settings = trace_settings.clone();
                                            Callback::from(move |e: InputEvent| {
                                                let pct = event_value(&e).parse::<u64>().unwrap_or(100);
                                                trace_settings.set(TraceSettings{ sample_permyriad: (pct.min(100))*100 });
                                            })
                                        }}
                                    />
                                    <button type="button" class="primary" disabled={*trace_loading} onclick={{
                                        let trace_settings = trace_settings.clone();
                                        let trace_status = trace_status.clone();
                                        let handle_error = handle_error.clone();
                                        let trace_loading = trace_loading.clone();
                                        Callback::from(move |_| {
                                            let trace_settings = trace_settings.clone();
                                            let trace_status = trace_status.clone();
                                            let handle_error = handle_error.clone();
                                            let trace_loading = trace_loading.clone();
                                            spawn_local(async move {
                                                trace_loading.set(true);
                                                let val = trace_settings.sample_permyriad;
                                                if val == 0 {
                                                    trace_status.set(StatusLine::error("Sampling cannot be 0 (min 0.1%)"));
                                                    trace_loading.set(false);
                                                    return;
                                                }
                                                match api_set_trace_settings(val).await {
                                                    Ok(_) => trace_status.set(StatusLine::success(format!("Sampling set to {:.1}%", val as f64 / 100.0))),
                                                    Err(err) => handle_error(err),
                                                }
                                                trace_loading.set(false);
                                            });
                                        })
                                    }}>{"Apply sampling"}</button>
                                    <span class="pill pill-ghost">{ format!("Current {:.1}%", trace_settings.sample_permyriad as f64 / 100.0) }</span>
                                    <StatusBadge status={(*trace_status).clone()} />
                                </div>
                                <div class="log-list">
                                    { render_logs(&logs, log_filter.as_str()) }
                                </div>
                                <div class="panel-head" style="margin-top:24px;">
                                    <div>
                                        <p class="eyebrow">{"Log files"}</p>
                                        <h3>{"Download JSONL"}</h3>
                                        <p class="muted">{"Recent rotated files (14-day retention)."}</p>
                                    </div>
                                </div>
                                <div class="cards">
                                    { for log_files.iter().map(|f| {
                                        let log_file_view = log_file_view.clone();
                                        let handle_error = handle_error.clone();
                                        let download_name = f.name.clone();
                                        let preview_name = f.name.clone();
                                        html!{
                                            <article class="card">
                                                <div class="card-head">
                                                    <div>
                                                        <p class="eyebrow">{"File"}</p>
                                                        <h3 class="mono">{ &f.name }</h3>
                                                        <p class="muted">{format!("{} bytes • {}", f.size, f.modified)}</p>
                                                    </div>
                                                    <div class="pill-row">
                                                        <button class="ghost" type="button" onclick={Callback::from(move |_| {
                                                            if let Some(win) = web_sys::window() {
                                                                let _ = win.open_with_url_and_target(&format!("/api/logs/files/{}", download_name), "_blank");
                                                            }
                                                        })}>{"Download"}</button>
                                                        <button class="ghost" type="button" onclick={Callback::from(move |_| {
                                                            let name = preview_name.clone();
                                                            let log_file_view = log_file_view.clone();
                                                            let handle_error = handle_error.clone();
                                                            spawn_local(async move {
                                                                match api_log_file(name.clone()).await {
                                                                    Ok(body) => log_file_view.set(Some((name.clone(), body))),
                                                                    Err(err) => handle_error(err),
                                                                }
                                                            });
                                                        })}>{"View"}</button>
                                                    </div>
                                                </div>
                                            </article>
                                        }
                                    }) }
                                    { if log_files.is_empty() { html!{<p class="muted">{"No log files yet."}</p>} } else { html!{} } }
                                </div>
                                <div class="log-file-view">
                                    {
                                        if let Some((name, body)) = (*log_file_view).clone() {
                                            let preview: String = body
                                                .lines()
                                                .take(200)
                                                .collect::<Vec<_>>()
                                                .join("\n");
                                            html!{
                                                <div class="card">
                                                    <div class="card-head">
                                                        <div>
                                                            <p class="eyebrow">{"Preview"}</p>
                                                            <h3 class="mono">{name}</h3>
                                                            <p class="muted">{"Showing first ~200 lines"}</p>
                                                        </div>
                                                    </div>
                                                    <pre class="log-pre">{preview}</pre>
                                                </div>
                                            }
                                        } else {
                                            html!{}
                                        }
                                    }
                                </div>
                            </section>
                        },
                        Tab::Acme => html!{
                            <section class="panel">
                                <div class="panel-head">
                                    <div>
                                        <p class="eyebrow">{"ACME Automation"}</p>
                                        <h2>{"DNS providers & challenge settings"}</h2>
                                        <p class="muted">{"Configure DNS providers for DNS-01 challenges. HTTP-01 tokens are served automatically from the challenge directory."}</p>
                                        <p class="muted mono">{"DNS Provider section"} </p>
                                    </div>
                                    <StatusBadge status={(*acme_status).clone()} />
                                </div>
                                <div class="panel-head" style="margin-top:8px;">
                                    <div>
                                        <p class="eyebrow">{"Certificate scheduling"}</p>
                                        <h3>{"Attach ACME to a host route"}</h3>
                                        <p class="muted">{"Pick a listener + host route, then issue/renew with a selected DNS provider."}</p>
                                    </div>
                                </div>
                                <div class="card soft" style="margin-top:8px;">
                                <form class="form-grid" onsubmit={{
                                    let acme_schedule = acme_schedule.clone();
                                    let acme_status = acme_status.clone();
                                    let handle_error = handle_error.clone();
                                    let listeners_state = listeners.clone();
                                    let acme_jobs_state = acme_jobs.clone();
                                    Callback::from(move |e: SubmitEvent| {
                                        e.prevent_default();
                                        let form = (*acme_schedule).clone();
                                        if form.listener.is_empty() || form.host.is_empty() {
                                            acme_status.set(StatusLine::error("Select listener and host"));
                                            return;
                                        }
                                        let listener_id = match Uuid::parse_str(&form.listener) {
                                            Ok(id) => id,
                                            Err(_) => {
                                                acme_status.set(StatusLine::error("Invalid listener id"));
                                                return;
                                            }
                                        };
                                        let acme_cfg = AcmeConfig {
                                            email: Some(form.email.clone()),
                                            provider: if form.provider.is_empty() { None } else { Some(form.provider.clone()) },
                                            directory_url: Some(form.directory_url.clone()),
                                            challenge: form.challenge.clone(),
                                            label: if form.label.is_empty() { None } else { Some(form.label.clone()) },
                                            cache_dir: None,
                                        };
                                        let host = form.host.clone();
                                        let acme_status = acme_status.clone();
                                        let handle_error = handle_error.clone();
                                        let listeners_state = listeners_state.clone();
                                        let acme_jobs_state = acme_jobs_state.clone();
                                        spawn_local(async move {
                                            match api_acme_schedule(listener_id, host, acme_cfg).await {
                                                Ok(_) => {
                                                    let listeners_handle = listeners_state.clone();
                                                    if let Ok(fresh) = api_listeners().await {
                                                    listeners_handle.set(fresh);
                                                    }
                                                    if let Ok(jobs) = api_acme_jobs().await {
                                                        acme_jobs_state.set(jobs);
                                                    }
                                                    acme_status.set(StatusLine::success("ACME scheduled"));
                                                }
                                                Err(err) => handle_error(err),
                                            }
                                        });
                                    })
                                }}>
                                    <label class="field">
                                        <span>{"Listener"}</span>
                                        <select
                                            onchange={{
                                                let acme_schedule = acme_schedule.clone();
                                                let listeners = listeners.clone();
                                                Callback::from(move |e: Event| {
                                                        let mut next = (*acme_schedule).clone();
                                                        next.listener = select_value(&e).unwrap_or_default();
                                                        if let Ok(id) = Uuid::parse_str(&next.listener) {
                                                            if let Some(listener) = listeners.iter().find(|l| l.id == id) {
                                                                if let Some(route) = listener.host_routes.clone().unwrap_or_default().first() {
                                                                    next.host = route.host.clone();
                                                                    next.label = route
                                                                        .tls
                                                                        .as_ref()
                                                                        .map(|t| t.cert_path.rsplit('/').next().unwrap_or("").to_string())
                                                                        .unwrap_or_default();
                                                                } else {
                                                                    next.host.clear();
                                                                    next.label.clear();
                                                                }
                                                    }
                                                } else {
                                                    next.host.clear();
                                                    next.label.clear();
                                                }
                                                acme_schedule.set(next);
                                            })
                                            }}
                                        >
                                            <option value="" selected={acme_schedule_form.listener.is_empty()}>{"Select listener"}</option>
                                            { for listeners.iter().map(|l| html!{
                                                <option value={l.id.to_string()} selected={acme_schedule_form.listener == l.id.to_string()}>{&l.name}</option>
                                            }) }
                                        </select>
                                    </label>
                                    <label class="field">
                                        <span>{"Host route"}</span>
                                        <select
                                            onchange={{
                                                let acme_schedule = acme_schedule.clone();
                                                Callback::from(move |e: Event| {
                                                    let mut next = (*acme_schedule).clone();
                                                    next.host = select_value(&e).unwrap_or_default();
                                                    acme_schedule.set(next);
                                                })
                                            }}
                                        >
                                            <option value="" selected={acme_schedule_form.host.is_empty()}>{"Select host"}</option>
                                            { for acme_hosts_for_schedule.iter().map(|h| html!{
                                                <option value={h.clone()} selected={acme_schedule_form.host == *h}>{h}</option>
                                            }) }
                                        </select>
                                    </label>
                                    <label class="field">
                                        <span>{"Friendly name (optional)"}</span>
                                        <input
                                            value={acme_schedule_form.label.clone()}
                                            oninput={{
                                                let acme_schedule = acme_schedule.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*acme_schedule).clone();
                                                    next.label = event_value(&e);
                                                    acme_schedule.set(next);
                                                })
                                            }}
                                            placeholder="cert-friendly-name"
                                        />
                                    </label>
                                    <label class="field">
                                        <span>{"Contact email"}</span>
                                        <input
                                            value={acme_schedule_form.email.clone()}
                                            oninput={{
                                                let acme_schedule = acme_schedule.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*acme_schedule).clone();
                                                    next.email = event_value(&e);
                                                    acme_schedule.set(next);
                                                })
                                            }}
                                            placeholder="ops@example.com"
                                        />
                                    </label>
                                    <label class="field">
                                        <span>{"DNS provider"}</span>
                                        <select
                                            onchange={{
                                                let acme_schedule = acme_schedule.clone();
                                                Callback::from(move |e: Event| {
                                                    let mut next = (*acme_schedule).clone();
                                                    next.provider = select_value(&e).unwrap_or_default();
                                                    acme_schedule.set(next);
                                                })
                                            }}
                                        >
                                            <option value="" selected={acme_schedule_form.provider.is_empty()}>{"Select provider"}</option>
                                            { for acme_providers.iter().map(|p| html!{
                                                <option value={p.name.clone()} selected={acme_schedule_form.provider == p.name}>{format!("{} ({:?})", p.name, p.provider)}</option>
                                            }) }
                                        </select>
                                    </label>
                                    <label class="field">
                                        <span>{"Directory URL"}</span>
                                        <input
                                            value={acme_schedule_form.directory_url.clone()}
                                            oninput={{
                                                let acme_schedule = acme_schedule.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*acme_schedule).clone();
                                                    next.directory_url = event_value(&e);
                                                    acme_schedule.set(next);
                                                })
                                            }}
                                        />
                                    </label>
                                    <label class="field">
                                        <span>{"Challenge type"}</span>
                                        <select onchange={{
                                            let acme_schedule = acme_schedule.clone();
                                            Callback::from(move |e: Event| {
                                                let mut next = (*acme_schedule).clone();
                                                next.challenge = select_value(&e)
                                                    .and_then(|v| serde_json::from_str(&format!("\"{}\"", v)).ok())
                                                    .unwrap_or(AcmeChallenge::Dns01);
                                                acme_schedule.set(next);
                                            })
                                        }}>
                                            <option value="DNS-01" selected={matches!(acme_schedule_form.challenge, AcmeChallenge::Dns01)}>{"DNS-01"}</option>
                                            <option value="HTTP-01" selected={matches!(acme_schedule_form.challenge, AcmeChallenge::Http01)}>{"HTTP-01"}</option>
                                        </select>
                                    </label>
                                    <div class="actions span-12">
                                        <button class="primary" type="submit">{"Schedule ACME"}</button>
                                    </div>
                                </form>
                                </div>
                                <div class="panel-head" style="margin-top:16px;">
                                    <div>
                                        <p class="eyebrow">{"Standalone certificates"}</p>
                                        <h3>{"Request ACME cert without binding to a listener"}</h3>
                                        <p class="muted">{"Issues and stores a certificate; attach it to listeners later."}</p>
                                    </div>
                                </div>
                                <div class="card soft" style="margin-top:8px;">
                                <form class="form-grid" onsubmit={{
                                    let acme_standalone = acme_standalone.clone();
                                    let acme_status = acme_status.clone();
                                    let handle_error = handle_error.clone();
                                    Callback::from(move |e: SubmitEvent| {
                                        e.prevent_default();
                                        let form = (*acme_standalone).clone();
                                        if form.host.is_empty() {
                                            acme_status.set(StatusLine::error("Host is required"));
                                            return;
                                        }
                                        let acme_cfg = AcmeConfig {
                                            email: Some(form.email.clone()),
                                            provider: if form.provider.is_empty() { None } else { Some(form.provider.clone()) },
                                            directory_url: Some(form.directory_url.clone()),
                                            challenge: form.challenge.clone(),
                                            label: if form.label.is_empty() { None } else { Some(form.label.clone()) },
                                            cache_dir: None,
                                        };
                                        let host = form.host.clone();
                                        let acme_status = acme_status.clone();
                                        let handle_error = handle_error.clone();
                                        spawn_local(async move {
                                            match api_acme_request(host, acme_cfg).await {
                                                Ok(_) => acme_status.set(StatusLine::success("Standalone ACME requested")),
                                                Err(err) => handle_error(err),
                                            }
                                        });
                                    })
                                }}>
                                    <label class="field">
                                        <span>{"Hostname"}</span>
                                        <input
                                            value={acme_standalone_form.host.clone()}
                                            oninput={{
                                                let acme_standalone = acme_standalone.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*acme_standalone).clone();
                                                    next.host = event_value(&e);
                                                            acme_standalone.set(next);
                                                        })
                                                    }}
                                                    placeholder="api.example.com"
                                                />
                                            </label>
                                    <label class="field">
                                        <span>{"Friendly name (optional)"}</span>
                                        <input
                                            value={acme_standalone_form.label.clone()}
                                            oninput={{
                                                let acme_standalone = acme_standalone.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*acme_standalone).clone();
                                                    next.label = event_value(&e);
                                                            acme_standalone.set(next);
                                                        })
                                                    }}
                                                    placeholder="cert-friendly-name"
                                                />
                                            </label>
                                    <label class="field">
                                        <span>{"Contact email"}</span>
                                        <input
                                            value={acme_standalone_form.email.clone()}
                                            oninput={{
                                                let acme_standalone = acme_standalone.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*acme_standalone).clone();
                                                    next.email = event_value(&e);
                                                            acme_standalone.set(next);
                                                        })
                                                    }}
                                                    placeholder="ops@example.com"
                                                />
                                            </label>
                                    <label class="field">
                                        <span>{"DNS provider"}</span>
                                        <select
                                            onchange={{
                                                let acme_standalone = acme_standalone.clone();
                                                        Callback::from(move |e: Event| {
                                                            let mut next = (*acme_standalone).clone();
                                                            next.provider = select_value(&e).unwrap_or_default();
                                                            acme_standalone.set(next);
                                                        })
                                                    }}
                                        >
                                            <option value="" selected={acme_standalone_form.provider.is_empty()}>{"Select provider"}</option>
                                            { for acme_providers.iter().map(|p| html!{
                                                <option value={p.name.clone()} selected={acme_standalone_form.provider == p.name}>{format!("{} ({:?})", p.name, p.provider)}</option>
                                            }) }
                                        </select>
                                    </label>
                                    <label class="field">
                                        <span>{"Directory URL"}</span>
                                        <input
                                            value={acme_standalone_form.directory_url.clone()}
                                            oninput={{
                                                let acme_standalone = acme_standalone.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*acme_standalone).clone();
                                                    next.directory_url = event_value(&e);
                                                            acme_standalone.set(next);
                                                        })
                                                    }}
                                                />
                                            </label>
                                    <label class="field">
                                        <span>{"Challenge type"}</span>
                                        <select onchange={{
                                            let acme_standalone = acme_standalone.clone();
                                            Callback::from(move |e: Event| {
                                                    let mut next = (*acme_standalone).clone();
                                                    next.challenge = select_value(&e)
                                                        .and_then(|v| serde_json::from_str(&format!("\"{}\"", v)).ok())
                                                        .unwrap_or(AcmeChallenge::Dns01);
                                                    acme_standalone.set(next);
                                                })
                                            }}>
                                                <option value="DNS-01" selected={matches!(acme_standalone_form.challenge, AcmeChallenge::Dns01)}>{"DNS-01"}</option>
                                                <option value="HTTP-01" selected={matches!(acme_standalone_form.challenge, AcmeChallenge::Http01)}>{"HTTP-01"}</option>
                                            </select>
                                        </label>
                                        <div class="actions span-12">
                                            <button class="primary" type="submit">{"Request standalone certificate"}</button>
                                        </div>
                                </form>
                                </div>
                                <div class="panel-head" style="margin-top:16px;">
                                    <div>
                                        <p class="eyebrow">{"Scheduled certificates"}</p>
                                        <h3>{"ACME jobs (host-bound & standalone)"}</h3>
                                        <p class="muted">{"Review, renew, edit, or remove existing ACME schedules. Issued certs live in the Certificates tab."}</p>
                                    </div>
                                </div>
                                <div class="cards" style="margin-bottom:16px;">
                                    { for acme_job_cards.iter().map(|(lid_opt, host, pool, acme_cfg, status, tls)| {
                                        let cert_match = tls
                                            .as_ref()
                                            .and_then(|t| t.cert_path.rsplit('/').next())
                                            .map(|b| acme_cert_names.contains(b))
                                            .unwrap_or(false);
                                        let show_actions = acme_cfg.is_some();
                                        let (label, class) = if let Some(st) = status {
                                            match st.state {
                                                AcmeState::Issued => (format!("ACME: valid until {}", st.not_after.clone().unwrap_or_else(|| "n/a".into())), "pill pill-on"),
                                                AcmeState::Pending => ("ACME pending".into(), "pill pill-ghost"),
                                                AcmeState::Failed => (format!("ACME failed: {}", st.message.clone().unwrap_or_else(|| "error".into())), "pill pill-error"),
                                            }
                                        } else if acme_cfg.is_some() {
                                            ("ACME scheduled".into(), "pill pill-ghost")
                                        } else if cert_match {
                                            ("ACME certificate present".into(), "pill pill-on")
                                        } else {
                                            ("ACME scheduled".into(), "pill pill-ghost")
                                        };
                                        let listeners_state = listeners.clone();
                                        let listeners_state_for_renew = listeners_state.clone();
                                        let listeners_state_for_remove = listeners_state.clone();
                                        let acme_jobs_state = acme_jobs.clone();
                                        let acme_jobs_state_for_remove = acme_jobs.clone();
                                        let host_disp = host.clone();
                                        let pool_disp = pool.clone().unwrap_or_else(|| "Standalone".into());
                                        html!{
                                            <article class="card">
                                            <div class="card-head">
                                                <div>
                                                    <p class="eyebrow">{format!("Host {}", host_disp)}</p>
                                                    <h3>{
                                                        if let Some(lid) = lid_opt {
                                                            let name = listeners.iter().find(|l| l.id == *lid).map(|l| l.name.clone()).unwrap_or_else(|| "Listener".into());
                                                            name
                                                        } else {
                                                            "Standalone".into()
                                                        }
                                                    }</h3>
                                                    <p class="muted">{pool_disp}</p>
                                                </div>
                                                { if show_actions {
                                                    html!{
                                                        <div class="pill-row">
                                                            <button class="ghost" type="button" onclick={{
                                                                let lid_opt = *lid_opt;
                                                                let host = host.clone();
                                                                let acme_status = acme_status.clone();
                                                                let handle_error = handle_error.clone();
                                                                Callback::from(move |_| {
                                                                    let acme_status = acme_status.clone();
                                                                    let handle_error = handle_error.clone();
                                                                    let listeners_state_inner = listeners_state_for_renew.clone();
                                                                    let host_val = host.clone();
                                                                    let acme_jobs_state = acme_jobs_state.clone();
                                                                    spawn_local(async move {
                                                                        let result = if let Some(lid) = lid_opt {
                                                                            api_acme_renew(lid).await
                                                                        } else {
                                                                            api_acme_renew_standalone(host_val.clone()).await
                                                                        };
                                                                        match result {
                                                                            Ok(_) => {
                                                                                if let Ok(fresh) = api_listeners().await {
                                                                                    listeners_state_inner.set(fresh);
                                                                                }
                                                                                if let Ok(jobs) = api_acme_jobs().await {
                                                                                    acme_jobs_state.set(jobs);
                                                                                }
                                                                                acme_status.set(StatusLine::success("Renewal triggered"));
                                                                            }
                                                                            Err(err) => handle_error(err),
                                                                        }
                                                                    });
                                                                })
                                                            }}>{"Renew now"}</button>
                                                            <button class="ghost" type="button" onclick={{
                                                                let acme_schedule = acme_schedule.clone();
                                                                let host = host.clone();
                                                                let acme_cfg = acme_cfg.clone();
                                                                Callback::from(move |_| {
                                                                    if let Some(cfg) = acme_cfg.clone() {
                                                                        let mut next = (*acme_schedule).clone();
                                                                        next.host = host.clone();
                                                                        next.email = cfg.email.clone().unwrap_or_default();
                                                                        next.provider = cfg.provider.clone().unwrap_or_default();
                                                                        next.directory_url = cfg.directory_url.clone().unwrap_or_else(|| "https://acme-v02.api.letsencrypt.org/directory".into());
                                                                        next.challenge = cfg.challenge.clone();
                                                                        if let Some(lbl) = cfg.label.clone() {
                                                                            next.label = lbl;
                                                                        }
                                                                        acme_schedule.set(next);
                                                                    }
                                                                })
                                                            }}>{"Edit schedule"}</button>
                                                            <button class="ghost" type="button" onclick={{
                                                                let acme_status = acme_status.clone();
                                                                let handle_error = handle_error.clone();
                                                                let host = host.clone();
                                                                let lid_opt = *lid_opt;
                                                                let listeners_state = listeners_state_for_remove.clone();
                                                                Callback::from(move |_| {
                                                                    let acme_status_cb = acme_status.clone();
                                                                    let handle_error_cb = handle_error.clone();
                                                                    let host_cb = host.clone();
                                                                    let listeners_handle = listeners_state.clone();
                                                                    let acme_jobs_state = acme_jobs_state_for_remove.clone();
                                                                    spawn_local(async move {
                                                                        let result = if let Some(lid) = lid_opt {
                                                                            api_acme_unschedule(lid, host_cb.clone()).await
                                                                        } else {
                                                                            api_acme_delete_standalone(host_cb.clone()).await
                                                                        };
                                                                        match result {
                                                                            Ok(_) => {
                                                                                if let Ok(fresh) = api_listeners().await {
                                                                                    listeners_handle.set(fresh);
                                                                                }
                                                                                if let Ok(jobs) = api_acme_jobs().await {
                                                                                    acme_jobs_state.set(jobs);
                                                                                }
                                                                                acme_status_cb.set(StatusLine::success("ACME schedule removed"));
                                                                            }
                                                                            Err(err) => handle_error_cb(err),
                                                                        }
                                                                    });
                                                                })
                                                            }}>{"Remove"}</button>
                                                        </div>
                                                    }
                                                } else {
                                                    html!{}
                                                }}
                                            </div>
                                                <div class="pill-row">
                                                    <span class={classes!(class)}>{label}</span>
                                                    { if let Some(t) = tls { html!{<span class="pill pill-ghost mono">{t.cert_path.clone()}</span>} } else { html!{} } }
                                                    { if let Some(cfg) = acme_cfg { if let Some(lbl) = cfg.label.clone() { html!{<span class="pill pill-ghost">{lbl}</span>} } else { html!{} } } else { html!{} } }
                                                </div>
                                            </article>
                                        }
                                    }) }
                                    { if acme_job_cards.is_empty() { html!{<p class="muted">{"No ACME schedules yet. Use the forms above to add one."}</p>} } else { html!{} } }
                                </div>
                                <div class="panel-head" style="margin-top:16px;">
                                    <div>
                                        <p class="eyebrow">{"DNS providers"}</p>
                                        <h3>{"Credentials for DNS-01"}</h3>
                                        <p class="muted">{"Store provider tokens/keys here, then pick a provider when scheduling certificates."}</p>
                                    </div>
                                </div>
                                <form class="form-grid" onsubmit={{
                                    let acme_form = acme_form.clone();
                                    let acme_providers = acme_providers.clone();
                                    let acme_status = acme_status.clone();
                                    let handle_error = handle_error.clone();
                                    Callback::from(move |e: SubmitEvent| {
                                        e.prevent_default();
                                        let payload = (*acme_form).clone().into_config();
                                        let acme_providers = acme_providers.clone();
                                        let acme_status = acme_status.clone();
                                        let handle_error = handle_error.clone();
                                        spawn_local(async move {
                                            match api_upsert_acme_provider(payload).await {
                                                Ok(saved) => {
                                                    let mut list = (*acme_providers).clone();
                                                    if let Some(pos) = list.iter().position(|p| p.name == saved.name) {
                                                        list[pos] = saved.clone();
                                                    } else {
                                                        list.push(saved.clone());
                                                    }
                                                    acme_providers.set(list);
                                                    acme_status.set(StatusLine::success("Saved ACME provider"));
                                                }
                                                Err(err) => handle_error(err),
                                            }
                                        });
                                    })
                                }}>
                                    <label class="field">
                                        <span>{"Provider name"}</span>
                                        <input
                                            value={acme_form.name.clone()}
                                            oninput={{
                                                let acme_form = acme_form.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*acme_form).clone();
                                                    next.name = event_value(&e);
                                                    acme_form.set(next);
                                                })
                                            }}
                                            placeholder="prod-cloudflare"
                                        />
                                    </label>
                                    <label class="field">
                                        <span>{"Provider type"}</span>
                                        <select onchange={{
                                            let acme_form = acme_form.clone();
                                            Callback::from(move |e: Event| {
                                                let mut next = (*acme_form).clone();
                                                let val = select_value(&e).unwrap_or_else(|| "cloudflare".into());
                                                next.provider = match val.as_str() {
                                                    "route53" => DnsProvider::Route53,
                                                    "generic" => DnsProvider::Generic,
                                                    _ => DnsProvider::Cloudflare,
                                                };
                                                next.provider_url = default_provider_url(&next.provider);
                                                acme_form.set(next);
                                            })
                                        }}>
                                            <option value="cloudflare" selected={acme_form.provider == DnsProvider::Cloudflare}>{"Cloudflare"}</option>
                                            <option value="route53" selected={acme_form.provider == DnsProvider::Route53}>{"AWS Route53"}</option>
                                            <option value="generic" selected={acme_form.provider == DnsProvider::Generic}>{"Generic (token-based)"}</option>
                                        </select>
                                    </label>
                                    { match acme_form.provider {
                                        DnsProvider::Cloudflare => html!{
                                            <>
                                            <label class="field">
                                                <span>{"API base URL"}</span>
                                                <input
                                                    value={acme_form.provider_url.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.provider_url = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="https://api.cloudflare.com/client/v4"
                                                />
                                            </label>
                                            <label class="field">
                                                <span>{"API token"}</span>
                                                <input
                                                    value={acme_form.api_token.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.api_token = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="cf_pat_..."
                                                />
                                            </label>
                                            <label class="field">
                                                <span>{"Zone / domain (optional)"}</span>
                                                <input
                                                    value={acme_form.zone.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.zone = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="example.com or zone id"
                                                />
                                            </label>
                                            <label class="field">
                                                <span>{"TXT prefix"}</span>
                                                <input
                                                    value={acme_form.txt_prefix.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.txt_prefix = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="_acme-challenge"
                                                />
                                            </label>
                                            </>
                                        },
                                        DnsProvider::Route53 => html!{
                                            <>
                                            <label class="field">
                                                <span>{"Region"}</span>
                                                <input
                                                    value={acme_form.provider_url.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.provider_url = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="us-east-1"
                                                />
                                            </label>
                                            <label class="field">
                                                <span>{"Access key"}</span>
                                                <input
                                                    value={acme_form.access_key.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.access_key = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="AKIA..."
                                                />
                                            </label>
                                            <label class="field">
                                                <span>{"Secret key"}</span>
                                                <input
                                                    value={acme_form.secret_key.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.secret_key = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="******"
                                                    type="password"
                                                />
                                            </label>
                                            <label class="field">
                                                <span>{"Hosted zone ID or domain"}</span>
                                                <input
                                                    value={acme_form.zone.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.zone = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="Z123ABC... or example.com"
                                                />
                                            </label>
                                            <label class="field">
                                                <span>{"TXT prefix"}</span>
                                                <input
                                                    value={acme_form.txt_prefix.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.txt_prefix = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="_acme-challenge"
                                                />
                                            </label>
                                            </>
                                        },
                                        DnsProvider::Generic => html!{
                                            <>
                                            <label class="field">
                                                <span>{"API endpoint (webhook)"}</span>
                                                <input
                                                    value={acme_form.provider_url.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.provider_url = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="https://api.example.com/dns"
                                                />
                                            </label>
                                            <label class="field">
                                                <span>{"Bearer token (optional)"}</span>
                                                <input
                                                    value={acme_form.api_token.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.api_token = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="token..."
                                                />
                                            </label>
                                            <label class="field">
                                                <span>{"Zone / domain (optional)"}</span>
                                                <input
                                                    value={acme_form.zone.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.zone = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="example.com"
                                                />
                                            </label>
                                            <label class="field">
                                                <span>{"TXT prefix"}</span>
                                                <input
                                                    value={acme_form.txt_prefix.clone()}
                                                    oninput={{
                                                        let acme_form = acme_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*acme_form).clone();
                                                            next.txt_prefix = event_value(&e);
                                                            acme_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="_acme-challenge"
                                                />
                                            </label>
                                            </>
                                        },
                                    }}
                                    <div class="actions">
                                        <button class="primary" type="submit">{"Save provider"}</button>
                                        <button class="ghost" type="button" onclick={{
                                            let acme_form = acme_form.clone();
                                            Callback::from(move |_| acme_form.set(AcmeProviderForm::default()))
                                        }}>{"Clear"}</button>
                                    </div>
                                </form>
                                <div class="cards">
                                    { for acme_providers.iter().map(|p| {
                                        let acme_providers = acme_providers.clone();
                                        let acme_form = acme_form.clone();
                                        let acme_status = acme_status.clone();
                                        let handle_error = handle_error.clone();
                                        let name = p.name.clone();
                                        html!{
                                            <article class="card">
                                                <div class="card-head">
                                                    <div>
                                                        <p class="eyebrow">{format!("{:?}", p.provider)}</p>
                                                        <h3>{ &p.name }</h3>
                                                        <p class="muted mono">{p.zone.clone().unwrap_or_else(|| "Any zone".into())}</p>
                                                    </div>
                                                    <div class="pill-row">
                                                        <button class="ghost" type="button" onclick={{
                                                            let p = p.clone();
                                                            Callback::from(move |_| acme_form.set(AcmeProviderForm::from_config(&p)))
                                                        }}>{"Edit"}</button>
                                                        <button class="ghost" type="button" onclick={Callback::from(move |_| {
                                                            let acme_providers = acme_providers.clone();
                                                            let acme_status = acme_status.clone();
                                                            let handle_error = handle_error.clone();
                                                            let name = name.clone();
                                                            spawn_local(async move {
                                                                match api_delete_acme_provider(name.clone()).await {
                                                                    Ok(_) => {
                                                                        let filtered: Vec<_> = acme_providers.iter().cloned().filter(|x| x.name != name).collect();
                                                                        acme_providers.set(filtered);
                                                                        acme_status.set(StatusLine::success("Deleted provider"));
                                                                    }
                                                                    Err(err) => handle_error(err),
                                                                }
                                                            });
                                                        })}>{"Delete"}</button>
                                                    </div>
                                                </div>
                                                <div class="pill-row">
                                                    { if let Some(zone) = &p.zone { html!{<span class="pill pill-ghost">{format!("Zone {}", zone)}</span>} } else { html!{} } }
                                                    { if let Some(prefix) = &p.txt_prefix { html!{<span class="pill pill-ghost">{format!("TXT {}", prefix)}</span>} } else { html!{} } }
                                                </div>
                                            </article>
                                        }
                                    }) }
                                    { if acme_providers.is_empty() { html!{<p class="muted">{"No ACME DNS providers configured."}</p>} } else { html!{} } }
                                </div>
                            </section>
                        },
                        Tab::Certs => html!{
                            <section class="panel">
                                <div class="panel-head">
                                    <div>
                                        <p class="eyebrow">{"Certificates"}</p>
                                        <h2>{"Upload or download PEM bundles"}</h2>
                                        <p class="muted">{"Use manual uploads for custom certs. ACME-issued certs will appear here when automation is wired."}</p>
                                    </div>
                                    <StatusBadge status={(*cert_status).clone()} />
                                </div>
                                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 18px;">
                                    <form class="card" style="padding:16px;" onsubmit={{
                                        let cert_form = cert_form.clone();
                                        let certs = certs.clone();
                                        let cert_status = cert_status.clone();
                                        let handle_error = handle_error.clone();
                                        Callback::from(move |e: SubmitEvent| {
                                            e.prevent_default();
                                            let payload = match (*cert_form).clone().into_payload() {
                                                Ok(p) => p,
                                                Err(msg) => {
                                                    cert_status.set(StatusLine::error(msg));
                                                    return;
                                                }
                                            };
                                            let certs = certs.clone();
                                            let cert_status = cert_status.clone();
                                            let cert_form = cert_form.clone();
                                            let handle_error = handle_error.clone();
                                            spawn_local(async move {
                                                match api_upload_cert(payload).await {
                                                    Ok(saved) => {
                                                        let mut list = (*certs).clone();
                                                        if let Some(pos) = list.iter().position(|c| c.name == saved.name) {
                                                            list[pos] = saved.clone();
                                                        } else {
                                                            list.push(saved.clone());
                                                        }
                                                        certs.set(list);
                                                        cert_form.set(CertificateForm::default());
                                                        cert_status.set(StatusLine::success("Certificate uploaded"));
                                                    }
                                                    Err(err) => handle_error(err),
                                                }
                                            });
                                        })
                                    }}>
                                        <p class="eyebrow">{"Upload"}</p>
                                        <h3>{"Manual PEM bundle"}</h3>
                                        <label class="field">
                                            <span>{"Name"}</span>
                                            <input
                                                value={cert_form.name.clone()}
                                                oninput={{
                                                    let cert_form = cert_form.clone();
                                                    Callback::from(move |e: InputEvent| {
                                                        let mut next = (*cert_form).clone();
                                                        next.name = event_value(&e);
                                                        cert_form.set(next);
                                                    })
                                                }}
                                                placeholder="edge-cert"
                                            />
                                        </label>
                                        <label class="field">
                                            <span>{"Certificate (PEM)"}</span>
                                            <textarea
                                                value={cert_form.cert_pem.clone()}
                                                oninput={{
                                                    let cert_form = cert_form.clone();
                                                    Callback::from(move |e: InputEvent| {
                                                        let mut next = (*cert_form).clone();
                                                        next.cert_pem = textarea_value(&e);
                                                        cert_form.set(next);
                                                    })
                                                }}
                                                placeholder="-----BEGIN CERTIFICATE-----"
                                                rows={4}
                                            />
                                        </label>
                                        <label class="field">
                                            <span>{"Private key (PEM)"}</span>
                                            <textarea
                                                value={cert_form.key_pem.clone()}
                                                oninput={{
                                                    let cert_form = cert_form.clone();
                                                    Callback::from(move |e: InputEvent| {
                                                        let mut next = (*cert_form).clone();
                                                        next.key_pem = textarea_value(&e);
                                                        cert_form.set(next);
                                                    })
                                                }}
                                                placeholder="-----BEGIN PRIVATE KEY-----"
                                                rows={4}
                                            />
                                        </label>
                                        <div class="actions">
                                            <button class="primary" type="submit">{"Upload"}</button>
                                            <button class="ghost" type="button" onclick={{
                                                let cert_form = cert_form.clone();
                                                let cert_status = cert_status.clone();
                                                Callback::from(move |_| {
                                                    cert_form.set(CertificateForm::default());
                                                    cert_status.set(StatusLine::clear());
                                                })
                                            }}>{"Clear"}</button>
                                        </div>
                                    </form>

                                    <div class="cards" style="margin:0;">
                                        { for certs.iter().map(|c| {
                                            let cert_status = cert_status.clone();
                                            let certs = certs.clone();
                                            let handle_error = handle_error.clone();
                                            let name = c.name.clone();
                                            html!{
                                                <article class="card">
                                                    <div class="card-head">
                                                        <div>
                                                            <p class="eyebrow">{&c.source}</p>
                                                            <h3>{ &c.name }</h3>
                                                            <p class="muted mono">{&c.cert_path}</p>
                                                        </div>
                                                        <div class="pill-row">
                                                            <button class="ghost" type="button" onclick={{
                                                                let name = name.clone();
                                                                let cert_status = cert_status.clone();
                                                                let handle_error = handle_error.clone();
                                                                Callback::from(move |_| {
                                                                    let name = name.clone();
                                                                    let cert_status = cert_status.clone();
                                                                    let handle_error = handle_error.clone();
                                                                    spawn_local(async move {
                                                                        match api_get_cert(&name).await {
                                                                            Ok(_) => {
                                                                                cert_status.set(StatusLine::success(format!("Downloaded {}", name)));
                                                                            }
                                                                            Err(err) => handle_error(err),
                                                                        }
                                                                    });
                                                                })
                                                            }}>{"Download"}</button>
                                                            <button class="ghost" type="button" onclick={{
                                                                let certs = certs.clone();
                                                                let cert_status = cert_status.clone();
                                                                let handle_error = handle_error.clone();
                                                                let name = name.clone();
                                                                Callback::from(move |_| {
                                                                    let name = name.clone();
                                                                    let certs = certs.clone();
                                                                    let cert_status = cert_status.clone();
                                                                    let handle_error = handle_error.clone();
                                                                    spawn_local(async move {
                                                                        match api_delete_cert(&name).await {
                                                                            Ok(_) => {
                                                                                let filtered: Vec<_> = certs.iter().cloned().filter(|x| x.name != name).collect();
                                                                                certs.set(filtered);
                                                                                cert_status.set(StatusLine::success("Deleted certificate"));
                                                                            }
                                                                            Err(err) => handle_error(err),
                                                                        }
                                                                    });
                                                                })
                                                            }}>{"Delete"}</button>
                                                        </div>
                                                    </div>
                                                </article>
                                            }
                                        }) }
                                        { if certs.is_empty() { html!{<p class="muted">{"No certificates uploaded."}</p>} } else { html!{} } }
                                    </div>
                                </div>
                            </section>
                        },
                        Tab::Pools => html!{
                            <section class="panel">
                                <div class="panel-head">
                                    <div>
                                        <p class="eyebrow">{"Upstream pools"}</p>
                                        <h2>{"Reuse upstream sets"}</h2>
                                        <p class="muted">{"Create pools once and reuse them in listeners and host routes."}</p>
                                    </div>
                                    <StatusBadge status={(*pool_status).clone()} />
                                </div>
                                <div class="form-grid">
                                    <label class="field">
                                        <span>{"Pool name"}</span>
                                        <input
                                            value={pool_form.name.clone()}
                                            oninput={{
                                                let pool_form = pool_form.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*pool_form).clone();
                                                    next.name = event_value(&e);
                                                    pool_form.set(next);
                                                })
                                            }}
                                            placeholder="api-pool"
                                        />
                                    </label>
                                    <label class="field span-2">
                                        <span>{"Upstreams (one per line, optional label via name=url)"}</span>
                                        <p class="hint">{"HTTP: http(s)://host:port • TCP: host:port"}</p>
                                        <textarea
                                            value={pool_form.upstreams_text.clone()}
                                            oninput={{
                                                let pool_form = pool_form.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*pool_form).clone();
                                                    next.upstreams_text = textarea_value(&e);
                                                    pool_form.set(next);
                                                })
                                            }}
                                            placeholder="api=http://127.0.0.1:7000"
                                        />
                                    </label>
                                </div>
                                <div class="actions">
                                    <button type="button" class="primary" onclick={{
                                        let pool_form = pool_form.clone();
                                        let pools = pools.clone();
                                        let pool_status = pool_status.clone();
                                        let handle_error = handle_error.clone();
                                        Callback::from(move |_| {
                                            let pool_form = (*pool_form).clone();
                                            let pools = pools.clone();
                                            let pool_status = pool_status.clone();
                                            let handle_error = handle_error.clone();
                                            spawn_local(async move {
                                                let payload = UpstreamPoolPayload {
                                                    name: pool_form.name.clone(),
                                                    upstreams: pool_form.upstreams_text.lines().enumerate().filter_map(|(idx, line)| {
                                                        let line = line.trim();
                                                        if line.is_empty() { return None; }
                                                        Some(to_upstream_payload(idx, line, &Protocol::Http))
                                                    }).collect::<Result<Vec<_>, _>>().unwrap_or_default(),
                                                };
                                                if payload.name.trim().is_empty() || payload.upstreams.is_empty() {
                                                    pool_status.set(StatusLine::error("Name and at least one upstream are required"));
                                                    return;
                                                }
                                                match api_upsert_pool(payload).await {
                                                    Ok(saved) => {
                                                        let mut next = (*pools).clone();
                                                        if let Some(existing) = next.iter_mut().find(|p| p.name == saved.name) {
                                                            *existing = saved.clone();
                                                        } else {
                                                            next.push(saved.clone());
                                                        }
                                                        pools.set(next);
                                                        pool_status.set(StatusLine::success("Pool saved"));
                                                    }
                                                    Err(err) => handle_error(err),
                                                }
                                            });
                                        })
                                    }}>{"Save pool"}</button>
                                    <StatusBadge status={(*pool_status).clone()} />
                                </div>
                                <div class="cards">
                                    { for pools.iter().map(|p| {
                                        let pools = pools.clone();
                                        let handle_error = handle_error.clone();
                                        html!{
                                            <article class="card">
                                                <div class="card-head">
                                                    <div>
                                                        <p class="eyebrow">{"Pool"}</p>
                                                        <h3>{ &p.name }</h3>
                                                        <p class="muted">{ format!("{} upstream(s)", p.upstreams.len()) }</p>
                                                    </div>
                                                    <div class="pill-row">
                                                        <button class="ghost" type="button" onclick={{
                                                            let p = p.clone();
                                                            let pool_form = pool_form.clone();
                                                            Callback::from(move |_| {
                                                                let mut next = (*pool_form).clone();
                                                                next.name = p.name.clone();
                                                                next.upstreams_text = p.upstreams.iter().map(|u| format!("{}={}", u.name, u.address)).collect::<Vec<_>>().join("\n");
                                                                pool_form.set(next);
                                                            })
                                                        }}>{"Edit"}</button>
                                                        <button class="ghost" type="button" onclick={{
                                                            let name = p.name.clone();
                                                            let pools = pools.clone();
                                                            let handle_error = handle_error.clone();
                                                            Callback::from(move |_| {
                                                                let name = name.clone();
                                                                let pools = pools.clone();
                                                                let handle_error = handle_error.clone();
                                                                spawn_local(async move {
                                                                    match api_delete_pool(name.clone()).await {
                                                                        Ok(_) => {
                                                                            let filtered: Vec<_> = pools.iter().cloned().filter(|pool| pool.name != name).collect();
                                                                            pools.set(filtered);
                                                                        }
                                                                        Err(err) => handle_error(err),
                                                                    }
                                                                });
                                                            })
                                                        }}>{"Delete"}</button>
                                                    </div>
                                                </div>
                                                <div class="pill-row wrap">
                                                    { for p.upstreams.iter().map(|u| {
                                                        html!{ <span class="pill pill-ghost">{ format!("{} → {}", u.name, u.address) }</span> }
                                                    }) }
                                                </div>
                                            </article>
                                        }
                                    })}
                                    { if pools.is_empty() { html!{<p class="muted">{"No pools defined yet."}</p>} } else { html!{} } }
                                </div>
                            </section>
                        },
                        Tab::Users => html!{
                            <section class="panel users-panel">
                                <div class="panel-head">
                                    <div>
                                        <p class="eyebrow">{"Users"}</p>
                                        <h2>{"Access control"}</h2>
                                        <p class="muted">{"Admins can create or remove users. Operators/viewers are read-only in UI."}</p>
                                    </div>
                                    <StatusBadge status={(*status).clone()} />
                                </div>

                                <div class="pill-row wrap" style="margin-bottom: 12px;">
                                    <span class="pill pill-on">{format!("Total users: {}", users.len())}</span>
                                    { if users.iter().any(|u| u.role == Role::Admin) { html!{<span class="pill pill-ghost">{"Admin present"}</span>} } else { html!{<span class="pill pill-error">{"No admin user yet"}</span>} } }
                                </div>

                                <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 18px;">
                                    <form class="simple-form card" style="padding:16px;" onsubmit={{
                                        let user_form = user_form.clone();
                                        let users = users.clone();
                                        let status = status.clone();
                                        let handle_error = handle_error.clone();
                                        Callback::from(move |e: SubmitEvent| {
                                            e.prevent_default();
                                            let payload = match (*user_form).to_payload() {
                                                Ok(p) => p,
                                                Err(msg) => {
                                                    status.set(StatusLine::error(msg));
                                                    return;
                                                }
                                            };
                                            let users = users.clone();
                                            let status = status.clone();
                                            let user_form = user_form.clone();
                                            let handle_error = handle_error.clone();
                                            spawn_local(async move {
                                                match api_create_user(payload).await {
                                                    Ok(saved) => {
                                                        let mut list = (*users).clone();
                                                        list.push(saved.clone());
                                                        users.set(list);
                                                        user_form.set(UserForm::default());
                                                        status.set(StatusLine::success("User created"));
                                                    }
                                                    Err(err) => handle_error(err),
                                                }
                                            });
                                        })
                                    }}>
                                        <div class="field-row column">
                                            <label class="field">
                                                <span>{"Username"}</span>
                                                <input
                                                    value={user_form.username.clone()}
                                                    oninput={{
                                                        let user_form = user_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*user_form).clone();
                                                            next.username = event_value(&e);
                                                            user_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="alice"
                                                />
                                            </label>
                                            <label class="field">
                                                <span>{"Password"}</span>
                                                <input
                                                    type="password"
                                                    value={user_form.password.clone()}
                                                    oninput={{
                                                        let user_form = user_form.clone();
                                                        Callback::from(move |e: InputEvent| {
                                                            let mut next = (*user_form).clone();
                                                            next.password = event_value(&e);
                                                            user_form.set(next);
                                                        })
                                                    }}
                                                    placeholder="strong password"
                                                />
                                            </label>
                                            <label class="field">
                                                <span>{"Role"}</span>
                                                <select
                                                    onchange={{
                                                        let user_form = user_form.clone();
                                                        Callback::from(move |e: Event| {
                                                            let mut next = (*user_form).clone();
                                                            let value = select_value(&e).unwrap_or_else(|| "viewer".into());
                                                            next.role = match value.as_str() {
                                                                "admin" => Role::Admin,
                                                                "operator" => Role::Operator,
                                                                _ => Role::Viewer,
                                                            };
                                                            user_form.set(next);
                                                        })
                                                    }}
                                                >
                                                    <option value="admin" selected={user_form.role == Role::Admin}>{"Admin"}</option>
                                                    <option value="operator" selected={user_form.role == Role::Operator}>{"Operator"}</option>
                                                    <option value="viewer" selected={user_form.role == Role::Viewer}>{"Viewer"}</option>
                                                </select>
                                            </label>
                                        </div>
                                        <div class="actions">
                                            <button class="primary" type="submit">{"Create user"}</button>
                                            <button class="ghost" type="button" onclick={{
                                                let user_form = user_form.clone();
                                                let status = status.clone();
                                                Callback::from(move |_| {
                                                    user_form.set(UserForm::default());
                                                    status.set(StatusLine::clear());
                                                })
                                            }}>{"Clear"}</button>
                                        </div>
                                    </form>

                                    <div class="cards" style="margin:0;">
                                        { for (*users).iter().map(|u| {
                                            let users = users.clone();
                                            let status = status.clone();
                                            let handle_error = handle_error.clone();
                                            let id = u.id;
                                            html!{
                                                <article class="card">
                                                    <div class="card-head">
                                                        <div>
                                                            <p class="eyebrow">{"User"}</p>
                                                            <h3>{ &u.username }</h3>
                                                            <span class="pill pill-ghost">{format!("{:?}", u.role)}</span>
                                                        </div>
                                                        <button class="ghost" type="button" onclick={Callback::from(move |_| {
                                                            let users = users.clone();
                                                            let status = status.clone();
                                                            let handle_error = handle_error.clone();
                                                            spawn_local(async move {
                                                                match api_delete_user(id).await {
                                                                    Ok(_) => {
                                                                        let filtered: Vec<_> = users.iter().cloned().filter(|usr| usr.id != id).collect();
                                                                        users.set(filtered);
                                                                        status.set(StatusLine::success("User deleted"));
                                                                    }
                                                                    Err(err) => handle_error(err),
                                                                }
                                                            });
                                                        })}>{"Delete"}</button>
                                                    </div>
                                                </article>
                                            }
                                        }) }
                                        { if users.is_empty() { html!{<p class="muted">{"No users yet."}</p>} } else { html!{} } }
                                    </div>
                                </div>
                            </section>
                        },
                    }
                }
            </main>

        </div>
    }
}

fn render_listener(
    listener: Listener,
    on_delete: Callback<Uuid>,
    on_edit: Callback<Listener>,
) -> Html {
    let proto_label = match listener.protocol {
        Protocol::Http => "HTTP",
        Protocol::Tcp => "TCP",
    };

    let on_delete_click = {
        let id = listener.id;
        let on_delete = on_delete.clone();
        Callback::from(move |_| on_delete.emit(id))
    };

    let on_edit_click = {
        let listener = listener.clone();
        let on_edit = on_edit.clone();
        Callback::from(move |_| on_edit.emit(listener.clone()))
    };

    html! {
        <article class="card">
            <div class="card-head">
                <div>
                    <p class="eyebrow">{proto_label}</p>
                    <h3>{listener.name.clone()}</h3>
                    <p class="muted mono">{listener.listen.clone()}</p>
                </div>
                <div class="pill-row">
                    <button class="ghost" onclick={on_edit_click}>{"Edit"}</button>
                    <button class="ghost" onclick={on_delete_click}>{"Delete"}</button>
                </div>
            </div>
            <div class="pill-row">
                {
                    if listener.protocol == Protocol::Http {
                        html! { <span class="pill">{"HTTP"}</span> }
                    } else {
                        html! { <span class="pill">{"TCP"}</span> }
                    }
                }
                {
                    if !listener.enabled {
                        html! { <span class="pill pill-error">{"Disabled"}</span> }
                    } else {
                        html!{}
                    }
                }
                {
                    if listener.tls.is_some() {
                        let label = listener
                            .tls
                            .as_ref()
                            .and_then(|t| {
                                let parts: Vec<&str> = t.cert_path.rsplit('/').collect();
                                parts.get(0).cloned().map(|s| format!("TLS: {}", s))
                            })
                            .unwrap_or_else(|| "TLS".to_string());
                        html! { <span class="pill pill-glow">{label}</span> }
                    } else {
                        html! {}
                    }
                }
                {
                    if listener.acme.is_some() {
                        html! { <span class="pill pill-ghost">{"ACME"}</span> }
                    } else {
                        html! {}
                    }
                }
                {
                    match &listener.sticky {
                        Some(StickyConfig { strategy: StickyStrategy::Cookie, .. }) => html!{ <span class="pill pill-on">{"Sticky: Cookie"}</span> },
                        Some(StickyConfig { strategy: StickyStrategy::IpHash, .. }) => html!{ <span class="pill pill-on">{"Sticky: IP hash"}</span> },
                        None => html!{},
                    }
                }
            </div>
            {
                if let Some(routes) = &listener.host_routes {
                    html!{
                        <div class="pill-column">
                            { for routes.iter().map(|r| {
                                let host_label = if let Some(pool) = &r.pool {
                                    format!("{} (pool: {})", r.host, pool)
                                } else {
                                    format!("{}", r.host)
                                };
                                let (tls_label, tls_class) = if let Some(status) = &r.acme_status {
                                    match status.state {
                                        AcmeState::Issued => {
                                            let until = status
                                                .not_after
                                                .clone()
                                                .unwrap_or_else(|| "issued".into());
                                            (format!("ACME: valid until {until}"), "pill pill-on")
                                        }
                                        AcmeState::Pending => {
                                            ("ACME pending".into(), "pill pill-ghost")
                                        }
                                        AcmeState::Failed => {
                                            let msg = status
                                                .message
                                                .clone()
                                                .unwrap_or_else(|| "error".into());
                                            (format!("ACME failed: {msg}"), "pill pill-error")
                                        }
                                    }
                                } else if let Some(t) = r.tls.as_ref() {
                                    let name = t
                                        .cert_path
                                        .rsplit('/')
                                        .next()
                                        .map(|s| s.to_string())
                                        .unwrap_or_else(|| "TLS".into());
                                    (name, "pill pill-on")
                                } else {
                                    ("No TLS".into(), "pill pill-ghost")
                                };
                                html!{
                                    <div class="pill-row wrap">
                                        <span class="pill pill-ghost">{host_label}</span>
                                        { if !r.enabled { html!{<span class="pill pill-error">{"Disabled"}</span>} } else { html!{} } }
                                        <span class={classes!(tls_class)}>
                                            {format!("TLS: {}", tls_label)}
                                        </span>
                                        { for r.upstreams.iter().map(|u| {
                                            let (status, class) = match u.healthy {
                                                Some(true) => ("up", "pill pill-on"),
                                                Some(false) => ("down", "pill pill-error"),
                                                None => ("unknown", "pill pill-ghost"),
                                            };
                                            html!{
                                                <span class={classes!(class)}>
                                                    {format!("{} • {} • {}", u.name, u.address, status)}
                                                </span>
                                            }
                                        })}
                                    </div>
                                }
                            }) }
                        </div>
                    }
                } else {
                    html!{
                        <div class="pill-row">
                            { for listener.upstreams.iter().map(|u| {
                                let (status, class) = match u.healthy {
                                    Some(true) => ("up", "pill pill-on"),
                                    Some(false) => ("down", "pill pill-error"),
                                    None => ("unknown", "pill pill-ghost"),
                                };
                                html!{
                                    <span class={classes!(class)}>
                                        {format!("{} • {} • {}", u.name, u.address, status)}
                                    </span>
                                }
                            })}
                        </div>
                    }
                }
            }
        </article>
    }
}

#[derive(Clone)]
struct ListenerForm {
    name: String,
    listen: String,
    protocol: Protocol,
    health_path: String,
    health_headers: String,
    health_script: String,
    rate_rps: String,
    rate_burst: String,
    enabled: bool,
    upstreams_text: String,
    tcp_pool: String,
    host_rules: Vec<HostRuleForm>,
    tls_enabled: bool,
    cert_path: String,
    key_path: String,
    #[allow(dead_code)]
    selected_cert: String,
    acme_enabled: bool,
    acme_email: String,
    acme_directory: String,
    acme_challenge: AcmeChallenge,
    acme_provider: String,
    sticky: StickyMode,
    cookie_name: String,
}

#[derive(Clone, PartialEq, Debug)]
enum Tab {
    Listeners,
    Logs,
    Users,
    Metrics,
    Acme,
    Certs,
    Pools,
}

#[derive(Clone, Serialize, Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct UserForm {
    username: String,
    password: String,
    role: Role,
}

#[derive(Clone, Serialize, Deserialize)]
struct AcmeProviderForm {
    name: String,
    provider: DnsProvider,
    provider_url: String,
    api_token: String,
    access_key: String,
    secret_key: String,
    zone: String,
    txt_prefix: String,
}

#[derive(Clone)]
struct AcmeScheduleForm {
    listener: String,
    host: String,
    label: String,
    email: String,
    provider: String,
    directory_url: String,
    challenge: AcmeChallenge,
}

#[derive(Clone, Serialize, Deserialize)]
struct CertificateForm {
    name: String,
    cert_pem: String,
    key_pem: String,
    source: String,
}

#[derive(Clone, PartialEq)]
enum StickyMode {
    None,
    Cookie,
    IpHash,
}

impl Default for ListenerForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            listen: String::from("0.0.0.0:9000"),
            protocol: Protocol::Http,
            health_path: "/health".into(),
            health_headers: String::new(),
            health_script: String::new(),
            rate_rps: String::new(),
            rate_burst: String::new(),
            enabled: true,
            upstreams_text: String::from("http://127.0.0.1:7000"),
            tcp_pool: String::new(),
            host_rules: vec![HostRuleForm::default()],
            tls_enabled: false,
            cert_path: String::new(),
            key_path: String::new(),
            selected_cert: String::new(),
            acme_enabled: false,
            acme_email: String::new(),
            acme_directory: String::new(),
            acme_challenge: AcmeChallenge::Http01,
            acme_provider: String::new(),
            sticky: StickyMode::None,
            cookie_name: String::from("BALOR_STICKY"),
        }
    }
}

impl Default for UpstreamPoolForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            upstreams_text: String::from("http://127.0.0.1:7000"),
        }
    }
}

impl Default for HostRuleForm {
    fn default() -> Self {
        Self {
            host: String::new(),
            enabled: true,
            tls_enabled: false,
            rate_rps: String::new(),
            rate_burst: String::new(),
            upstreams_text: String::from("http://127.0.0.1:7000"),
            pool: String::new(),
            selected_cert: String::new(),
            cert_path: String::new(),
            key_path: String::new(),
            acme: None,
        }
    }
}

impl Default for AcmeProviderForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            provider: DnsProvider::Cloudflare,
            provider_url: default_provider_url(&DnsProvider::Cloudflare),
            api_token: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
            zone: String::new(),
            txt_prefix: "_acme-challenge".into(),
        }
    }
}

impl Default for AcmeScheduleForm {
    fn default() -> Self {
        Self {
            listener: String::new(),
            host: String::new(),
            label: String::new(),
            email: String::new(),
            provider: String::new(),
            directory_url: "https://acme-v02.api.letsencrypt.org/directory".into(),
            challenge: AcmeChallenge::Dns01,
        }
    }
}

impl Default for CertificateForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            cert_pem: String::new(),
            key_pem: String::new(),
            source: "manual".into(),
        }
    }
}

impl AcmeProviderForm {
    fn from_config(cfg: &AcmeProviderConfig) -> Self {
        Self {
            name: cfg.name.clone(),
            provider: cfg.provider.clone(),
            provider_url: cfg
                .api_base
                .clone()
                .unwrap_or_else(|| default_provider_url(&cfg.provider)),
            api_token: cfg.api_token.clone().unwrap_or_default(),
            access_key: cfg.access_key.clone().unwrap_or_default(),
            secret_key: cfg.secret_key.clone().unwrap_or_default(),
            zone: cfg.zone.clone().unwrap_or_default(),
            txt_prefix: cfg
                .txt_prefix
                .clone()
                .unwrap_or_else(|| "_acme-challenge".into()),
        }
    }

    fn into_config(self) -> AcmeProviderConfig {
        AcmeProviderConfig {
            name: self.name,
            provider: self.provider,
            api_base: (!self.provider_url.trim().is_empty()).then(|| self.provider_url),
            api_token: (!self.api_token.trim().is_empty()).then(|| self.api_token),
            access_key: (!self.access_key.trim().is_empty()).then(|| self.access_key),
            secret_key: (!self.secret_key.trim().is_empty()).then(|| self.secret_key),
            zone: (!self.zone.trim().is_empty()).then(|| self.zone),
            txt_prefix: (!self.txt_prefix.trim().is_empty()).then(|| self.txt_prefix),
        }
    }
}

impl CertificateForm {
    fn into_payload(self) -> Result<CertificatePayload, String> {
        if self.name.trim().is_empty() {
            return Err("Certificate name is required".into());
        }
        if self.cert_pem.trim().is_empty() || self.key_pem.trim().is_empty() {
            return Err("Provide certificate and key PEM".into());
        }
        Ok(CertificatePayload {
            name: self.name,
            cert_pem: self.cert_pem,
            key_pem: self.key_pem,
            source: self.source,
        })
    }
}

impl Default for LoginForm {
    fn default() -> Self {
        Self {
            username: String::from("admin"),
            password: String::new(),
        }
    }
}

impl Default for UserForm {
    fn default() -> Self {
        Self {
            username: String::new(),
            password: String::new(),
            role: Role::Operator,
        }
    }
}

impl ListenerForm {
    fn parse_rate(rps: &str, burst: &str) -> Result<Option<RateLimitConfig>, String> {
        let rps_trim = rps.trim();
        let burst_trim = burst.trim();
        if rps_trim.is_empty() && burst_trim.is_empty() {
            return Ok(None);
        }
        let rps_val: u32 = rps_trim
            .parse()
            .map_err(|_| "Rate limit RPS must be a number".to_string())?;
        if rps_val == 0 {
            return Ok(None);
        }
        let burst_val: u32 = if burst_trim.is_empty() {
            rps_val
        } else {
            burst_trim
                .parse()
                .map_err(|_| "Burst must be a number".to_string())?
        };
        Ok(Some(RateLimitConfig {
            rps: rps_val,
            burst: burst_val.max(rps_val),
        }))
    }
    fn from_listener(listener: &Listener) -> Self {
        let upstreams_text = listener
            .upstreams
            .iter()
            .map(|u| format!("{}={}", u.name, u.address))
            .collect::<Vec<_>>()
            .join("\n");

        let (tls_enabled, cert_path, key_path) = if let Some(tls) = &listener.tls {
            (true, tls.cert_path.clone(), tls.key_path.clone())
        } else {
            (false, String::new(), String::new())
        };
        let selected_cert = listener
            .tls
            .as_ref()
            .and_then(|t| t.cert_path.rsplit('/').next().map(|s| s.to_string()))
            .unwrap_or_default();

        let (sticky, cookie_name) = if let Some(sticky) = &listener.sticky {
            let name = sticky
                .cookie_name
                .clone()
                .unwrap_or_else(|| "BALOR_STICKY".to_string());
            match sticky.strategy {
                StickyStrategy::Cookie => (StickyMode::Cookie, name),
                StickyStrategy::IpHash => (StickyMode::IpHash, name),
            }
        } else {
            (StickyMode::None, "BALOR_STICKY".to_string())
        };

        let (acme_enabled, acme_email, acme_directory, acme_challenge, acme_provider) =
            if let Some(acme) = &listener.acme {
                (
                    true,
                    acme.email.clone().unwrap_or_default(),
                    acme.directory_url.clone().unwrap_or_default(),
                    acme.challenge.clone(),
                    acme.provider.clone().unwrap_or_default(),
                )
            } else {
                (
                    false,
                    String::new(),
                    String::new(),
                    AcmeChallenge::Http01,
                    String::new(),
                )
            };

        let host_rules = listener
            .host_routes
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|r| {
                let form = HostRuleForm {
                    host: r.host,
                    enabled: r.enabled,
                    tls_enabled: r.tls.is_some() || r.acme.is_some(),
                    rate_rps: r
                        .rate_limit
                        .as_ref()
                        .map(|rl| rl.rps.to_string())
                        .unwrap_or_default(),
                    rate_burst: r
                        .rate_limit
                        .as_ref()
                        .map(|rl| rl.burst.to_string())
                        .unwrap_or_default(),
                    upstreams_text: r
                        .upstreams
                        .into_iter()
                        .map(|u| format!("{}={}", u.name, u.address))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    pool: r.pool.unwrap_or_default(),
                    selected_cert: r
                        .tls
                        .as_ref()
                        .map(|t| t.cert_path.rsplit('/').next().unwrap_or("").to_string())
                        .unwrap_or_default(),
                    cert_path: r
                        .tls
                        .as_ref()
                        .map(|t| t.cert_path.clone())
                        .unwrap_or_default(),
                    key_path: r
                        .tls
                        .as_ref()
                        .map(|t| t.key_path.clone())
                        .unwrap_or_default(),
                    acme: r.acme.clone(),
                };
                form
            })
            .collect();

        Self {
            name: listener.name.clone(),
            listen: listener.listen.clone(),
            protocol: listener.protocol.clone(),
            health_path: listener
                .health_probe
                .as_ref()
                .and_then(|p| p.path.clone())
                .unwrap_or_else(|| "/health".into()),
            health_headers: listener
                .health_probe
                .as_ref()
                .map(|p| {
                    p.headers
                        .iter()
                        .map(|(k, v)| format!("{k}: {v}"))
                        .collect::<Vec<_>>()
                        .join("\n")
                })
                .unwrap_or_default(),
            health_script: listener
                .health_probe
                .as_ref()
                .and_then(|p| p.script.clone())
                .unwrap_or_default(),
            upstreams_text,
            tcp_pool: String::new(),
            host_rules,
            tls_enabled,
            cert_path,
            key_path,
            selected_cert,
            acme_enabled,
            acme_email,
            acme_directory,
            acme_challenge,
            acme_provider,
            rate_rps: listener
                .rate_limit
                .as_ref()
                .map(|r| r.rps.to_string())
                .unwrap_or_default(),
            rate_burst: listener
                .rate_limit
                .as_ref()
                .map(|r| r.burst.to_string())
                .unwrap_or_default(),
            sticky,
            cookie_name,
            enabled: listener.enabled,
        }
    }

    fn to_payload(&self) -> Result<ListenerPayload, String> {
        if self.name.trim().is_empty() {
            return Err("Name is required".into());
        }
        if self.listen.trim().is_empty() {
            return Err("Listen address is required".into());
        }

        let upstreams: Vec<_> = self
            .upstreams_text
            .lines()
            .filter(|l| !l.trim().is_empty())
            .enumerate()
            .map(|(idx, line)| to_upstream_payload(idx, line, &self.protocol))
            .collect::<Result<_, _>>()?;

        let host_routes = if self.protocol == Protocol::Http {
            if !self.host_rules.is_empty() {
                let mut routes = Vec::new();
                for rule in &self.host_rules {
                    if rule.host.trim().is_empty() {
                        continue;
                    }
                    if rule.pool.trim().is_empty() && rule.enabled {
                        return Err(format!("Host {} must select a pool", rule.host));
                    }
                    let (selected_cert, cert_path, key_path) = (
                        rule.selected_cert.clone(),
                        rule.cert_path.clone(),
                        rule.key_path.clone(),
                    );
                    let upstreams: Vec<UpstreamPayload> = Vec::new();
                    if !selected_cert.trim().is_empty()
                        && (cert_path.trim().is_empty() || key_path.trim().is_empty())
                    {
                        return Err(format!(
                            "Host {} certificate paths missing after selection",
                            rule.host
                        ));
                    }
                    routes.push(HostRulePayload {
                        host: rule.host.trim().to_lowercase(),
                        enabled: rule.enabled,
                        upstreams,
                        rate_limit: ListenerForm::parse_rate(&rule.rate_rps, &rule.rate_burst)?,
                        pool: (!rule.pool.trim().is_empty()).then(|| rule.pool.clone()),
                        tls: if !cert_path.trim().is_empty()
                            && !key_path.trim().is_empty()
                            && rule.tls_enabled
                        {
                            Some(TlsConfig {
                                cert_path,
                                key_path,
                            })
                        } else {
                            None
                        },
                        acme: rule.acme.clone(),
                        acme_status: None,
                    });
                }
                Some(routes)
            } else {
                None
            }
        } else {
            None
        };

        if self.protocol == Protocol::Tcp && upstreams.is_empty() {
            return Err("Add at least one upstream".into());
        }
        if self.protocol == Protocol::Http
            && upstreams.is_empty()
            && host_routes.as_ref().map_or(true, |r| r.is_empty())
        {
            return Err(
                "Add at least one host route (or provide default upstreams for fallback)".into(),
            );
        }

        let health_probe = if self.protocol == Protocol::Http {
            let headers: Vec<(String, String)> = self
                .health_headers
                .lines()
                .filter(|l| !l.trim().is_empty())
                .filter_map(|line| {
                    line.split_once(':')
                        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
                })
                .collect();
            Some(HealthProbePayload {
                path: Some(self.health_path.trim().to_string()),
                headers,
                script: (!self.health_script.trim().is_empty()).then(|| self.health_script.clone()),
            })
        } else {
            None
        };

        let tls = if self.tls_enabled && self.protocol == Protocol::Http {
            if self.acme_enabled {
                return Err("Choose either ACME automation or a certificate, not both".into());
            }
            if self.cert_path.trim().is_empty() || self.key_path.trim().is_empty() {
                return Err("Select a certificate for TLS".into());
            }
            Some(TlsConfig {
                cert_path: self.cert_path.clone(),
                key_path: self.key_path.clone(),
            })
        } else {
            None
        };

        let acme = if self.acme_enabled && self.protocol == Protocol::Http {
            if self.acme_challenge == AcmeChallenge::Dns01 && self.acme_provider.trim().is_empty() {
                return Err("DNS-01 requires a DNS provider name".into());
            }
            Some(AcmeConfig {
                email: (!self.acme_email.trim().is_empty()).then(|| self.acme_email.clone()),
                directory_url: (!self.acme_directory.trim().is_empty())
                    .then(|| self.acme_directory.clone()),
                cache_dir: None,
                challenge: self.acme_challenge.clone(),
                provider: (!self.acme_provider.trim().is_empty())
                    .then(|| self.acme_provider.clone()),
                label: None,
            })
        } else {
            None
        };

        let sticky = if self.protocol == Protocol::Http {
            match self.sticky {
                StickyMode::None => None,
                StickyMode::Cookie => {
                    if self.cookie_name.trim().is_empty() {
                        return Err("Cookie name is required for cookie affinity".into());
                    }
                    Some(StickyConfig {
                        strategy: StickyStrategy::Cookie,
                        cookie_name: Some(self.cookie_name.clone()),
                    })
                }
                StickyMode::IpHash => Some(StickyConfig {
                    strategy: StickyStrategy::IpHash,
                    cookie_name: Some(self.cookie_name.clone()),
                }),
            }
        } else {
            None
        };

        Ok(ListenerPayload {
            name: self.name.clone(),
            listen: self.listen.clone(),
            protocol: self.protocol.clone(),
            health_probe,
            rate_limit: ListenerForm::parse_rate(&self.rate_rps, &self.rate_burst)?,
            enabled: self.enabled,
            upstreams,
            host_routes,
            tls,
            sticky,
            acme,
        })
    }
}

impl UserForm {
    fn to_payload(&self) -> Result<UserPayload, String> {
        if self.username.trim().is_empty() {
            return Err("Username is required".into());
        }
        if self.password.trim().is_empty() {
            return Err("Password is required".into());
        }

        Ok(UserPayload {
            username: self.username.clone(),
            role: self.role.clone(),
            password: self.password.clone(),
        })
    }
}

fn to_upstream_payload(
    index: usize,
    line: &str,
    _protocol: &Protocol,
) -> Result<UpstreamPayload, String> {
    let trimmed = line.trim();
    let (name, address, weight) = if let Some((name, rest)) = trimmed.split_once('=') {
        let parts: Vec<&str> = rest.split_whitespace().collect();
        let addr = parts.get(0).unwrap_or(&"").trim().to_string();
        let weight = if let Some(w) = parts.get(1) {
            w.parse::<u32>().unwrap_or(1)
        } else {
            1
        };
        (name.trim().to_string(), addr, weight)
    } else {
        (format!("upstream-{}", index + 1), trimmed.to_string(), 1)
    };

    if address.is_empty() {
        return Err("Upstream address cannot be empty".into());
    }

    Ok(UpstreamPayload {
        name,
        address,
        enabled: true,
        weight,
    })
}

fn event_value(event: &InputEvent) -> String {
    event
        .target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|input| input.value())
        .unwrap_or_default()
}

fn textarea_value(event: &InputEvent) -> String {
    event
        .target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlTextAreaElement>().ok())
        .map(|input| input.value())
        .unwrap_or_default()
}

fn checkbox_checked(event: &Event) -> bool {
    event
        .target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlInputElement>().ok())
        .map(|input| input.checked())
        .unwrap_or(false)
}

fn select_value(event: &Event) -> Option<String> {
    event
        .target()
        .and_then(|t| t.dyn_into::<web_sys::HtmlSelectElement>().ok())
        .map(|select| select.value())
}

fn load_session() -> Option<Session> {
    let stored: Option<Session> = web_sys::window()
        .and_then(|w| w.local_storage().ok().flatten())
        .and_then(|s| s.get_item("balor_session").ok().flatten())
        .and_then(|raw| serde_json::from_str(&raw).ok());

    if let Some(sess) = stored {
        SESSION_CACHE.with(|c| *c.borrow_mut() = Some(sess.clone()));
        return Some(sess);
    }

    SESSION_CACHE.with(|c| (*c.borrow()).clone())
}

fn save_session(session: &Session) {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        if let Ok(json) = serde_json::to_string(session) {
            let _ = storage.set_item("balor_session", &json);
        }
    }
    SESSION_CACHE.with(|c| *c.borrow_mut() = Some(session.clone()));
}

fn clear_session_storage() {
    if let Some(storage) = web_sys::window().and_then(|w| w.local_storage().ok().flatten()) {
        let _ = storage.remove_item("balor_session");
    }
    SESSION_CACHE.with(|c| *c.borrow_mut() = None);
}

#[derive(Clone, PartialEq)]
struct MetricRow {
    listener: String,
    status: String,
    value: f64,
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
struct VersionInfo {
    api_version: String,
    ui_version: String,
    build: String,
}

#[derive(Clone, PartialEq)]
struct LatencyRow {
    listener: String,
    p50: f64,
    p95: f64,
    p99: f64,
    count: f64,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct LogEntry {
    timestamp: String,
    level: String,
    message: String,
    target: Option<String>,
    listener: Option<String>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct LogFileInfo {
    name: String,
    size: u64,
    modified: String,
}

fn parse_metrics_summary(body: &str) -> Vec<MetricRow> {
    let mut rows = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with("balor_http_requests_total") {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let labels = parts[0];
        let value: f64 = parts[1].parse().unwrap_or(0.0);

        let (listener, status) = if let Some(start) = labels.find('{') {
            let inner = &labels[start + 1..labels.len().saturating_sub(1)];
            let mut listener = String::from("unknown");
            let mut status_label = String::from("other");
            for pair in inner.split(',') {
                let mut kv = pair.splitn(2, '=');
                if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                    let v = v.trim_matches('"');
                    match k {
                        "listener_id" => listener = v.to_string(),
                        "status" => status_label = v.to_string(),
                        _ => {}
                    }
                }
            }
            (listener, status_label)
        } else {
            (String::from("unknown"), String::from("other"))
        };

        rows.push(MetricRow {
            listener,
            status,
            value,
        });
    }
    rows
}

fn parse_latency_summary(body: &str) -> Vec<LatencyRow> {
    use std::collections::HashMap;
    let mut buckets: HashMap<String, Vec<(f64, f64)>> = HashMap::new();

    for line in body.lines() {
        let line = line.trim();
        if !line.starts_with("balor_http_request_duration_seconds_bucket") {
            continue;
        }
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 2 {
            continue;
        }
        let labels = parts[0];
        let value: f64 = parts[1].parse().unwrap_or(0.0);
        let mut listener = "unknown".to_string();
        let mut le = f64::INFINITY;
        if let Some(start) = labels.find('{') {
            let inner = &labels[start + 1..labels.len().saturating_sub(1)];
            for pair in inner.split(',') {
                let mut kv = pair.splitn(2, '=');
                if let (Some(k), Some(v)) = (kv.next(), kv.next()) {
                    let v = v.trim_matches('"');
                    match k {
                        "listener_id" => listener = v.to_string(),
                        "le" => le = v.parse().unwrap_or(f64::INFINITY),
                        _ => {}
                    }
                }
            }
        }
        buckets.entry(listener).or_default().push((le, value));
    }

    let quant = |data: &[(f64, f64)], q: f64| -> f64 {
        let mut sorted = data.to_vec();
        sorted.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let total = sorted.last().map(|(_, v)| *v).unwrap_or(0.0);
        if total <= 0.0 {
            return 0.0;
        }
        let target = total * q;
        for (le, count) in sorted {
            if count >= target {
                return le;
            }
        }
        0.0
    };

    buckets
        .into_iter()
        .map(|(listener, data)| {
            let count = data.iter().map(|(_, v)| *v).fold(0.0, f64::max); // cumulative buckets; take max as total
            LatencyRow {
                listener,
                p50: quant(&data, 0.50),
                p95: quant(&data, 0.95),
                p99: quant(&data, 0.99),
                count,
            }
        })
        .collect()
}

fn render_logs(logs: &UseStateHandle<Vec<LogEntry>>, filter: &str) -> Html {
    let entries: Vec<_> = logs
        .iter()
        .filter(|l| filter == "all" || l.level.to_lowercase().starts_with(filter))
        .collect();
    if entries.is_empty() {
        html! { <p class="muted">{"No logs yet."}</p> }
    } else {
        html! {
            <ul>
                { for entries.iter().map(|l| {
                    html!{
                        <li class="log-line">
                            <span class={classes!("pill", match l.level.to_lowercase().as_str() {
                                "error" => "pill-error",
                                "warn" => "pill-on",
                                _ => "pill-ghost",
                            })}>{&l.level}</span>
                            <span class="mono muted">{&l.timestamp}</span>
                            { if let Some(t) = &l.target { html!{<span class="pill pill-ghost">{t}</span>} } else { html!{} } }
                            { if let Some(listener) = &l.listener { html!{<span class="pill pill-ghost">{listener}</span>} } else { html!{} } }
                            <span>{&l.message}</span>
                        </li>
                    }
                }) }
            </ul>
        }
    }
}

fn with_auth(req: gloo_net::http::RequestBuilder) -> gloo_net::http::RequestBuilder {
    if let Some(session) = load_session() {
        req.header("Authorization", &format!("Bearer {}", session.token))
    } else {
        req
    }
}

fn download_text_file(name: &str, content: &str, mime: &str) {
    if let Some(window) = web_sys::window() {
        if let Some(document) = window.document() {
            let parts = Array::new();
            parts.push(&JsValue::from_str(content));
            let bag = BlobPropertyBag::new();
            bag.set_type(mime);
            if let Ok(blob) = Blob::new_with_str_sequence_and_options(&parts, &bag) {
                if let Ok(url) = Url::create_object_url_with_blob(&blob) {
                    if let Ok(element) = document.create_element("a") {
                        if let Ok(anchor) = element.dyn_into::<HtmlAnchorElement>() {
                            anchor.set_href(&url);
                            anchor.set_download(name);
                            if let Some(body) = document.body() {
                                let _ = anchor.set_attribute("style", "display:none;");
                                let _ = body.append_child(&anchor);
                                anchor.click();
                                let _ = body.remove_child(&anchor);
                            } else {
                                anchor.click();
                            }
                            let _ = Url::revoke_object_url(&url);
                        }
                    }
                }
            }
        }
    }
}

async fn api_listeners() -> Result<Vec<Listener>, String> {
    let resp = with_auth(Request::get("/api/listeners"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    parse_json_response::<Vec<Listener>>(resp).await
}

async fn api_stats() -> Result<Stats, String> {
    let resp = with_auth(Request::get("/api/stats"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    parse_json_response::<Stats>(resp).await
}

async fn api_version() -> Result<VersionInfo, String> {
    let resp = Request::get("/api/version")
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<VersionInfo>(resp).await
}

async fn api_metrics() -> Result<String, String> {
    let resp = with_auth(Request::get("/metrics"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    if resp.ok() {
        match resp.text().await {
            Ok(body) => {
                let max = 50_000;
                if body.len() > max {
                    let mut preview = body[..max].to_string();
                    preview.push_str("\n# ...truncated. Open full /metrics for complete output.");
                    Ok(preview)
                } else {
                    Ok(body)
                }
            }
            Err(e) => Err(format!("read body failed: {e}")),
        }
    } else {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<unable to read body>".into());
        Err(format!("{status}: {body}"))
    }
}

async fn api_trace_settings() -> Result<TraceSettings, String> {
    let resp = with_auth(Request::get("/api/logging"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<TraceSettings>(resp).await
}

async fn api_set_trace_settings(sample_permyriad: u64) -> Result<(), String> {
    let payload = TraceSettings { sample_permyriad };
    let resp = with_auth(Request::put("/api/logging"))
        .json(&payload)
        .map_err(|e| format!("serialize: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(format!(
            "{}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ))
    }
}

async fn api_create_listener(payload: ListenerPayload) -> Result<Listener, String> {
    let resp = with_auth(Request::post("/api/listeners"))
        .json(&payload)
        .map_err(|e| format!("serialize: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    parse_json_response::<Listener>(resp).await
}

async fn api_update_listener(id: Uuid, payload: ListenerPayload) -> Result<Listener, String> {
    let url = format!("/api/listeners/{}", id);
    let resp = with_auth(Request::put(&url))
        .json(&payload)
        .map_err(|e| format!("serialize: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    parse_json_response::<Listener>(resp).await
}

async fn api_delete_listener(id: Uuid) -> Result<(), String> {
    let url = format!("/api/listeners/{}", id);
    let resp = with_auth(Request::delete(&url))
        .send()
        .await
        .map_err(|e| format!("delete failed: {e}"))?;

    if resp.ok() {
        Ok(())
    } else {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<unable to read body>".into());
        Err(format!("{status}: {body}"))
    }
}

async fn api_users() -> Result<Vec<User>, String> {
    let resp = with_auth(Request::get("/api/users"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<Vec<User>>(resp).await
}

async fn api_create_user(payload: UserPayload) -> Result<User, String> {
    let resp = with_auth(Request::post("/api/users"))
        .json(&payload)
        .map_err(|e| format!("serialize: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<User>(resp).await
}

async fn api_delete_user(id: Uuid) -> Result<(), String> {
    let url = format!("/api/users/{}", id);
    let resp = with_auth(Request::delete(&url))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    if resp.ok() {
        Ok(())
    } else {
        let status = resp.status();
        let body = resp
            .text()
            .await
            .unwrap_or_else(|_| "<unable to read body>".into());
        Err(format!("{status}: {body}"))
    }
}

async fn api_acme_providers() -> Result<Vec<AcmeProviderConfig>, String> {
    let resp = with_auth(Request::get("/api/acme/providers"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<Vec<AcmeProviderConfig>>(resp).await
}

async fn api_acme_schedule(listener: Uuid, host: String, acme: AcmeConfig) -> Result<(), String> {
    #[derive(Serialize)]
    struct SchedulePayload {
        listener: Uuid,
        host: String,
        acme: AcmeConfig,
    }
    let body = serde_json::to_string(&SchedulePayload {
        listener,
        host,
        acme,
    })
    .map_err(|e| e.to_string())?;
    let resp = with_auth(Request::post("/api/acme/schedule"))
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| format!("request failed: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(parse_error(resp).await)
    }
}

async fn api_acme_jobs() -> Result<Vec<StandaloneAcmeJob>, String> {
    let resp = with_auth(Request::get("/api/acme/standalone"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<Vec<StandaloneAcmeJob>>(resp).await
}

async fn api_acme_renew_standalone(host: String) -> Result<(), String> {
    #[derive(Serialize)]
    struct RenewPayload {
        host: String,
    }
    let body = serde_json::to_string(&RenewPayload { host }).map_err(|e| e.to_string())?;
    let resp = with_auth(Request::post("/api/acme/standalone/renew"))
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| format!("request failed: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(parse_error(resp).await)
    }
}

async fn api_acme_delete_standalone(host: String) -> Result<(), String> {
    #[derive(Serialize)]
    struct DeletePayload {
        host: String,
    }
    let body = serde_json::to_string(&DeletePayload { host }).map_err(|e| e.to_string())?;
    let resp = with_auth(Request::post("/api/acme/standalone/delete"))
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| format!("request failed: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(parse_error(resp).await)
    }
}

async fn api_logs() -> Result<Vec<LogEntry>, String> {
    let resp = with_auth(Request::get("/api/logs"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<Vec<LogEntry>>(resp).await
}

async fn api_console() -> Result<AdminConsoleConfig, String> {
    let resp = with_auth(Request::get("/api/admin/console"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<AdminConsoleConfig>(resp).await
}

async fn api_save_console(payload: AdminConsoleConfig) -> Result<AdminConsoleConfig, String> {
    let body = serde_json::to_string(&payload).map_err(|e| e.to_string())?;
    let resp = with_auth(Request::put("/api/admin/console"))
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| format!("request failed: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<AdminConsoleConfig>(resp).await
}

async fn api_acme_renew(listener: Uuid) -> Result<(), String> {
    let resp = with_auth(Request::post(&format!("/api/acme/renew/{listener}")))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(parse_error(resp).await)
    }
}

#[allow(dead_code)]
async fn api_acme_renew_all() -> Result<(), String> {
    let resp = with_auth(Request::post("/api/acme/renew_all"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(parse_error(resp).await)
    }
}

async fn api_acme_unschedule(listener: Uuid, host: String) -> Result<(), String> {
    #[derive(Serialize)]
    struct UnschedulePayload {
        listener: Uuid,
        host: String,
    }
    let body =
        serde_json::to_string(&UnschedulePayload { listener, host }).map_err(|e| e.to_string())?;
    let resp = with_auth(Request::post("/api/acme/unschedule"))
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| format!("request failed: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(parse_error(resp).await)
    }
}

async fn api_acme_request(host: String, acme: AcmeConfig) -> Result<(), String> {
    #[derive(Serialize)]
    struct RequestPayload {
        host: String,
        acme: AcmeConfig,
    }
    let body = serde_json::to_string(&RequestPayload { host, acme }).map_err(|e| e.to_string())?;
    let resp = with_auth(Request::post("/api/acme/request"))
        .header("Content-Type", "application/json")
        .body(body)
        .map_err(|e| format!("request failed: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(parse_error(resp).await)
    }
}

async fn api_log_files() -> Result<Vec<LogFileInfo>, String> {
    let resp = with_auth(Request::get("/api/logs/files"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<Vec<LogFileInfo>>(resp).await
}

async fn api_log_file(name: String) -> Result<String, String> {
    let url = format!("/api/logs/files/{name}");
    let resp = with_auth(Request::get(&url))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        resp.text()
            .await
            .map_err(|e| format!("read body failed: {e}"))
    } else {
        Err(format!(
            "{}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        ))
    }
}

async fn api_upsert_acme_provider(
    payload: AcmeProviderConfig,
) -> Result<AcmeProviderConfig, String> {
    let resp = with_auth(Request::post("/api/acme/providers"))
        .json(&payload)
        .map_err(|e| format!("serialize: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<AcmeProviderConfig>(resp).await
}

async fn api_delete_acme_provider(name: String) -> Result<(), String> {
    let url = format!("/api/acme/providers/{name}");
    let resp = with_auth(Request::delete(&url))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(format!("delete failed: {}", resp.status()))
    }
}

async fn api_certs() -> Result<Vec<CertificateBundle>, String> {
    let resp = with_auth(Request::get("/api/certs"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<Vec<CertificateBundle>>(resp).await
}

async fn api_upload_cert(payload: CertificatePayload) -> Result<CertificateBundle, String> {
    let resp = with_auth(Request::post("/api/certs"))
        .json(&payload)
        .map_err(|e| format!("serialize: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<CertificateBundle>(resp).await
}

async fn api_get_cert(name: &str) -> Result<CertificatePayload, String> {
    let url = format!("/api/certs/{name}");
    let resp = with_auth(Request::get(&url))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<CertificatePayload>(resp).await
}

async fn api_delete_cert(name: &str) -> Result<(), String> {
    let url = format!("/api/certs/{name}");
    let resp = with_auth(Request::delete(&url))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(format!("delete failed: {}", resp.status()))
    }
}

async fn api_pools() -> Result<Vec<UpstreamPool>, String> {
    let resp = with_auth(Request::get("/api/pools"))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<Vec<UpstreamPool>>(resp).await
}

async fn api_upsert_pool(payload: UpstreamPoolPayload) -> Result<UpstreamPool, String> {
    let resp = with_auth(Request::post("/api/pools"))
        .json(&payload)
        .map_err(|e| format!("serialize: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<UpstreamPool>(resp).await
}

async fn api_delete_pool(name: String) -> Result<(), String> {
    let url = format!("/api/pools/{name}");
    let resp = with_auth(Request::delete(&url))
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(format!("delete failed: {}", resp.status()))
    }
}

async fn api_login(username: String, password: String) -> Result<Session, String> {
    let resp = Request::post("/api/login")
        .json(&json!({ "username": username, "password": password }))
        .map_err(|e| format!("serialize: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    parse_json_response::<Session>(resp).await
}

async fn api_logout(token: &str) -> Result<(), String> {
    let resp = with_auth(Request::post("/api/logout"))
        .json(&json!({ "token": token }))
        .map_err(|e| format!("serialize: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;
    if resp.ok() {
        Ok(())
    } else {
        Err(format!("logout failed: {}", resp.status()))
    }
}

async fn parse_json_response<T: for<'de> Deserialize<'de>>(
    resp: gloo_net::http::Response,
) -> Result<T, String> {
    let status = resp.status();
    let body = resp.text().await.map_err(|e| format!("read failed: {e}"))?;

    if !resp.ok() {
        if status == 401 {
            clear_session_storage();
        }
        return Err(format!("{status}: {body}"));
    }

    serde_json::from_str(&body).map_err(|e| format!("parse failed: {e}; body: {body}"))
}

async fn parse_error(resp: gloo_net::http::Response) -> String {
    let status = resp.status();
    let body = resp
        .text()
        .await
        .unwrap_or_else(|e| format!("read failed: {e}"));
    if status == 401 {
        clear_session_storage();
    }
    format!("{status}: {body}")
}

#[derive(Clone, PartialEq)]
enum StatusKind {
    None,
    Success,
    Error,
}

#[derive(Clone, PartialEq)]
struct StatusLine {
    text: String,
    kind: StatusKind,
}

impl Default for StatusLine {
    fn default() -> Self {
        Self {
            text: String::new(),
            kind: StatusKind::None,
        }
    }
}

impl StatusLine {
    fn success<T: Into<String>>(text: T) -> Self {
        Self {
            text: text.into(),
            kind: StatusKind::Success,
        }
    }

    fn error<T: Into<String>>(text: T) -> Self {
        Self {
            text: text.into(),
            kind: StatusKind::Error,
        }
    }

    fn clear() -> Self {
        Self::default()
    }
}

#[derive(Properties, PartialEq)]
struct StatusProps {
    status: StatusLine,
}

#[function_component(StatusBadge)]
fn status_badge(StatusProps { status }: &StatusProps) -> Html {
    if matches!(status.kind, StatusKind::None) {
        return html! {};
    }

    let class = match status.kind {
        StatusKind::Success => "pill pill-on",
        StatusKind::Error => "pill pill-error",
        StatusKind::None => "",
    };

    html! {
        <span class={classes!(class, "pill-tight")}>{ status.text.clone() }</span>
    }
}
