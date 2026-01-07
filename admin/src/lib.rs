// Balor admin UI
// Author: Eduard Gevorkyan (egevorky@arencloud.com)
// License: Apache 2.0

use gloo_net::http::Request;
use gloo_timers::callback::Interval;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::f64;
use std::{cell::RefCell, rc::Rc};
use uuid::Uuid;
use wasm_bindgen::{prelude::*, JsCast};
use wasm_bindgen_futures::spawn_local;
use yew::prelude::*;

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
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct Upstream {
    id: Uuid,
    name: String,
    address: String,
    enabled: bool,
    #[serde(default)]
    healthy: Option<bool>,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
struct Listener {
    id: Uuid,
    name: String,
    listen: String,
    protocol: Protocol,
    upstreams: Vec<Upstream>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<TlsConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sticky: Option<StickyConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    acme: Option<AcmeConfig>,
}

#[derive(Clone, Serialize, Deserialize)]
struct UpstreamPayload {
    name: String,
    address: String,
    enabled: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct ListenerPayload {
    name: String,
    listen: String,
    protocol: Protocol,
    upstreams: Vec<UpstreamPayload>,
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

#[derive(Clone, Default, Serialize, Deserialize, PartialEq)]
struct Stats {
    listener_count: usize,
    active_runtimes: usize,
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
    let session = use_state(load_session);
    let tab = use_state(|| Tab::Listeners);
    let users = use_state(Vec::<User>::new);
    let user_form = use_state(UserForm::default);
    let login_form = use_state(LoginForm::default);
    let acme_providers = use_state(Vec::<AcmeProviderConfig>::new);
    let acme_form = use_state(AcmeProviderForm::default);
    let acme_status = use_state(StatusLine::default);

    let handle_error = {
        let session = session.clone();
        let listeners = listeners.clone();
        let users = users.clone();
        let stats = stats.clone();
        let status = status.clone();
        Rc::new(move |err: String| {
            if err.contains("401") || err.to_lowercase().contains("unauthorized") {
                clear_session_storage();
                session.set(None);
                listeners.set(vec![]);
                users.set(vec![]);
                stats.set(Stats::default());
                status.set(StatusLine::error("Session expired. Please log in again."));
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
        use_effect_with((*tab).clone(), move |current_tab: &Tab| {
            let metrics_text = metrics_text.clone();
            let metrics_rows = metrics_rows.clone();
            let session = session.clone();
            let acme_providers = acme_providers_state.clone();
            let handle_error_acme = handle_error_acme.clone();
            if *current_tab == Tab::Metrics {
                spawn_local(async move {
                    if session.is_none() {
                        return;
                    }
                    match api_metrics().await {
                        Ok(body) => {
                            metrics_rows.set(parse_metrics_summary(&body));
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
                        }
                    }
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
        let handle_error = handle_error.clone();
        let status = status.clone();
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
                    if session.role == Role::Admin {
                        if let Ok(u) = api_users().await {
                            users.set(u);
                        }
                        if let Ok(p) = api_acme_providers().await {
                            acme_providers.set(p);
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
        let handle_error = handle_error.clone();
        use_effect_with((*session).clone(), move |current: &Option<Session>| {
            let current = current.clone();
            let interval = current.as_ref().map(|sess| {
                let listeners = listeners.clone();
                let stats = stats.clone();
                let users = users.clone();
                let handle_error = handle_error.clone();
                let session_clone = Some(sess.clone());
                Interval::new(5000, move || {
                    let listeners = listeners.clone();
                    let stats = stats.clone();
                    let users = users.clone();
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
        Callback::from(move |event: SubmitEvent| {
            event.prevent_default();
            let payload = match form.to_payload() {
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
                    <p class="eyebrow">{"UI / API"}</p>
                    <h2 class="stat-value">{"Axum + Yew"}</h2>
                </div>
            </section>

            <main class="content" key={
                match *tab {
                    Tab::Listeners => "listeners",
                    Tab::Metrics => "metrics",
                    Tab::Users => "users",
                    Tab::Acme => "acme",
                }
            }>
                { match *tab {
                    Tab::Listeners => html! {
                        <div key="listeners-pane">
                            <section class="panel">
                                <h2>{"Create Listener"}</h2>
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
                                                        next.acme_cache.clear();
                                                        next.acme_challenge = AcmeChallenge::Http01;
                                                        next.acme_provider.clear();
                                                        next.sticky = StickyMode::None;
                                                    }
                                                    form.set(next);
                                                })
                                            }}
                                        >
                                            <option value="http" selected={form.protocol == Protocol::Http}>{"HTTP (L7)"}</option>
                                            <option value="tcp" selected={form.protocol == Protocol::Tcp}>{"TCP (L4)"}</option>
                                        </select>
                                    </label>
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
                                        <p class="hint">{"HTTP only. Cookie sets a sticky upstream id."}</p>
                                    </label>
                                    <label class="field span-2">
                                        <span>{"Upstreams (one per line, optional label via name=url)"}</span>
                                        <p class="hint">{"HTTP: include http(s)://. TCP: host:port."}</p>
                                        <textarea
                                            value={form.upstreams_text.clone()}
                                            oninput={{
                                                let form = form.clone();
                                                Callback::from(move |e: InputEvent| {
                                                    let mut next = (*form).clone();
                                                    next.upstreams_text = textarea_value(&e);
                                                    form.set(next);
                                                })
                                            }}
                                            placeholder="api=http://127.0.0.1:7000\ntcp1=127.0.0.1:7001"
                                        />
                                    </label>
                                    {
                                        if form.protocol == Protocol::Http {
                                            html!{
                                                <>
                                                    <label class="field">
                                                        <span>{"TLS termination (PEM paths)"}</span>
                                                        <div class="inline">
                                                            <input
                                                                type="checkbox"
                                                                checked={form.tls_enabled}
                                                                onchange={{
                                                                    let form = form.clone();
                                                                    Callback::from(move |e: Event| {
                                                                        let mut next = (*form).clone();
                                                                        next.tls_enabled = checkbox_checked(&e);
                                                                        if next.tls_enabled {
                                                                            next.acme_enabled = false;
                                                                        }
                                                                        form.set(next);
                                                                    })
                                                                }}
                                                                aria-label="Enable TLS"
                                                            />
                                                            <p class="hint">{"Enable Rustls with cert/key PEM files"}</p>
                                                        </div>
                                                    </label>
                                                    <label class="field">
                                                        <span>{"Certificate path"}</span>
                                                        <input
                                                            value={form.cert_path.clone()}
                                                            disabled={!form.tls_enabled}
                                                            oninput={{
                                                                let form = form.clone();
                                                                Callback::from(move |e: InputEvent| {
                                                                    let mut next = (*form).clone();
                                                                    next.cert_path = event_value(&e);
                                                                    form.set(next);
                                                                })
                                                            }}
                                                            placeholder="/etc/ssl/certs/balor.crt"
                                                        />
                                                    </label>
                                                    <label class="field">
                                                        <span>{"Private key path"}</span>
                                                        <input
                                                            value={form.key_path.clone()}
                                                            disabled={!form.tls_enabled}
                                                            oninput={{
                                                                let form = form.clone();
                                                                Callback::from(move |e: InputEvent| {
                                                                    let mut next = (*form).clone();
                                                                    next.key_path = event_value(&e);
                                                                    form.set(next);
                                                                })
                                                            }}
                                                            placeholder="/etc/ssl/private/balor.key"
                                                        />
                                                    </label>
                                                    {
                                                        if form.sticky == StickyMode::Cookie {
                                                            html!{
                                                                <label class="field">
                                                                    <span>{"Sticky cookie name"}</span>
                                                                    <input
                                                                        value={form.cookie_name.clone()}
                                                                        oninput={{
                                                                            let form = form.clone();
                                                                            Callback::from(move |e: InputEvent| {
                                                                                let mut next = (*form).clone();
                                                                                next.cookie_name = event_value(&e);
                                                                                form.set(next);
                                                                            })
                                                                        }}
                                                                        placeholder="BALOR_STICKY"
                                                                    />
                                                                </label>
                                                            }
                                                        } else {
                                                            html!{}
                                                        }
                                                    }
                                                </>
                                            }
                                        } else {
                                            html!{}
                                        }
                                    }
                                    {
                                        if form.protocol == Protocol::Http {
                                            html!{
                                                <>
                                                    <label class="field">
                                                        <span>{"ACME (Let's Encrypt) automation"}</span>
                                                        <div class="inline">
                                                            <input
                                                                type="checkbox"
                                                                checked={form.acme_enabled}
                                                                onchange={{
                                                                    let form = form.clone();
                                                                    Callback::from(move |e: Event| {
                                                                    let mut next = (*form).clone();
                                                                    next.acme_enabled = checkbox_checked(&e);
                                                                    if next.acme_enabled {
                                                                        next.tls_enabled = false;
                                                                        next.acme_challenge = AcmeChallenge::Http01;
                                                                    }
                                                                    form.set(next);
                                                                })
                                                            }}
                                                            aria-label="Enable ACME automation"
                                                        />
                                                        <p class="hint">{"Serve HTTP-01 challenges and provision certs automatically (PEM reload pipeline pending)."}</p>
                                                    </div>
                                                    </label>
                                                    <label class="field">
                                                        <span>{"ACME challenge type"}</span>
                                                        <select
                                                            disabled={!form.acme_enabled}
                                                            onchange={{
                                                                let form = form.clone();
                                                                let acme_providers = acme_providers.clone();
                                                                Callback::from(move |e: Event| {
                                                                    let mut next = (*form).clone();
                                                                    let value = select_value(&e).unwrap_or_else(|| "http01".into());
                                                                    next.acme_challenge = if value == "dns01" { AcmeChallenge::Dns01 } else { AcmeChallenge::Http01 };
                                                                    if next.acme_challenge == AcmeChallenge::Http01 {
                                                                        next.acme_provider.clear();
                                                                    } else if next.acme_provider.is_empty() {
                                                                        if let Some(first) = acme_providers.get(0) {
                                                                            next.acme_provider = first.name.clone();
                                                                        }
                                                                    }
                                                                    form.set(next);
                                                                })
                                                            }}
                                                        >
                                                            <option value="http01" selected={form.acme_challenge == AcmeChallenge::Http01}>{"HTTP-01 (default)"}</option>
                                                            <option value="dns01" selected={form.acme_challenge == AcmeChallenge::Dns01}>{"DNS-01 (needs provider)"}</option>
                                                        </select>
                                                    </label>
                                                    {
                                                        if form.acme_enabled && form.acme_challenge == AcmeChallenge::Dns01 {
                                                            let providers = (*acme_providers).clone();
                                                            html!{
                                                                <label class="field">
                                                                    <span>{"DNS provider"}</span>
                                                                    <select
                                                                        onchange={{
                                                                            let form = form.clone();
                                                                            Callback::from(move |e: Event| {
                                                                                let mut next = (*form).clone();
                                                                                next.acme_provider = select_value(&e).unwrap_or_default();
                                                                                form.set(next);
                                                                            })
                                                                        }}
                                                                    >
                                                                        {
                                                                            if providers.is_empty() {
                                                                                html!{<option value="" selected=true>{"No providers configured"}</option>}
                                                                            } else {
                                                                                html!{}
                                                                            }
                                                                        }
                                                                        { for providers.iter().map(|p| {
                                                                            let selected = form.acme_provider == p.name;
                                                                            html!{<option value={p.name.clone()} selected={selected}>{format!("{} ({:?})", p.name, p.provider)}</option>}
                                                                        }) }
                                                                    </select>
                                                                    <p class="hint">{"Configure providers in the ACME tab."}</p>
                                                                </label>
                                                            }
                                                        } else { html!{} }
                                                    }
                                                    <label class="field">
                                                        <span>{"Contact email (optional)"}</span>
                                                        <input
                                                            value={form.acme_email.clone()}
                                                            disabled={!form.acme_enabled}
                                                            oninput={{
                                                                let form = form.clone();
                                                                Callback::from(move |e: InputEvent| {
                                                                    let mut next = (*form).clone();
                                                                    next.acme_email = event_value(&e);
                                                                    form.set(next);
                                                                })
                                                            }}
                                                            placeholder="ops@example.com"
                                                        />
                                                    </label>
                                                    <label class="field">
                                                        <span>{"Directory URL (optional override)"}</span>
                                                        <input
                                                            value={form.acme_directory.clone()}
                                                            disabled={!form.acme_enabled}
                                                            oninput={{
                                                                let form = form.clone();
                                                                Callback::from(move |e: InputEvent| {
                                                                    let mut next = (*form).clone();
                                                                    next.acme_directory = event_value(&e);
                                                                    form.set(next);
                                                                })
                                                            }}
                                                            placeholder="https://acme-v02.api.letsencrypt.org/directory"
                                                        />
                                                    </label>
                                                    <label class="field">
                                                        <span>{"Cache dir (optional override)"}</span>
                                                        <input
                                                            value={form.acme_cache.clone()}
                                                            disabled={!form.acme_enabled}
                                                            oninput={{
                                                                let form = form.clone();
                                                                Callback::from(move |e: InputEvent| {
                                                                    let mut next = (*form).clone();
                                                                    next.acme_cache = event_value(&e);
                                                                    form.set(next);
                                                                })
                                                            }}
                                                            placeholder="data/acme-challenges"
                                                        />
                                                    </label>
                                                </>
                                            }
                                        } else {
                                            html!{}
                                        }
                                    }
                                    <div class="actions">
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
                                        <StatusBadge status={(*status).clone()} />
                                    </div>
                                </form>
                            </section>

                            <section class="panel">
                                <div class="panel-head">
                                    <h2>{"Active Listeners"}</h2>
                                    { if *loading { html!{<span class="pill pill-ghost">{"Loading..."}</span>} } else { html!{} } }
                                </div>
                                {
                                    if listeners.is_empty() {
                                        html!{<p class="muted">{"No listeners yet. Add one above to start balancing traffic."}</p>}
                                    } else {
                                        html!{
                                            <div class="cards">
                                                { for listeners.iter().map(|l| render_listener(l.clone(), on_delete.clone(), {
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
                            </section>
                        </div>
                    },
                    Tab::Metrics => html! {
                        <section class="panel metrics-panel" key="metrics-pane">
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
                        </section>
                    },
                    Tab::Acme => html! {
                        <section class="panel" key="acme-pane">
                            <div class="panel-head">
                                <div>
                                    <p class="eyebrow">{"ACME Automation"}</p>
                                    <h2>{"DNS providers & challenge settings"}</h2>
                                    <p class="muted">{"Configure DNS providers for DNS-01 challenges. HTTP-01 tokens are served automatically from the challenge directory."}</p>
                                </div>
                                <StatusBadge status={(*acme_status).clone()} />
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
                                            acme_form.set(next);
                                        })
                                    }}>
                                        <option value="cloudflare" selected={acme_form.provider == DnsProvider::Cloudflare}>{"Cloudflare"}</option>
                                        <option value="route53" selected={acme_form.provider == DnsProvider::Route53}>{"AWS Route53"}</option>
                                        <option value="generic" selected={acme_form.provider == DnsProvider::Generic}>{"Generic (token-based)"}</option>
                                    </select>
                                </label>
                                <label class="field">
                                    <span>{"API token (use for Cloudflare / generic)"}</span>
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
                                    <span>{"Access key (Route53)"}</span>
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
                                    <span>{"Secret key (Route53)"}</span>
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
                    Tab::Users => html! {
                        <section class="panel users-panel" key="users-pane">
                            <div class="panel-head">
                                <h2>{"Users"}</h2>
                                <p class="muted">{"RBAC: Admin, Operator, Viewer"}</p>
                            </div>
                            <form class="form-grid" onsubmit={{
                                let user_form = user_form.clone();
                                let users = users.clone();
                                let status = status.clone();
                                let handle_error = handle_error.clone();
                                Callback::from(move |e: SubmitEvent| {
                                    e.prevent_default();
                                    let payload = match user_form.to_payload() {
                                        Ok(p) => p,
                                        Err(msg) => { status.set(StatusLine::error(msg)); return; }
                                    };
                                    let user_form = user_form.clone();
                                    let users = users.clone();
                                    let status = status.clone();
                                    let handle_error = handle_error.clone();
                                    spawn_local(async move {
                                        match api_create_user(payload).await {
                                            Ok(user) => {
                                                let mut next = (*users).clone();
                                                next.push(user);
                                                users.set(next);
                                                user_form.set(UserForm::default());
                                                status.set(StatusLine::success("User created"));
                                            }
                                            Err(err) => handle_error(err),
                                        }
                                    });
                                })
                            }}>
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
                                        placeholder="operator"
                                    />
                                </label>
                                <label class="field">
                                    <span>{"Password"}</span>
                                    <input
                                        r#type="password"
                                        value={user_form.password.clone()}
                                        oninput={{
                                            let user_form = user_form.clone();
                                            Callback::from(move |e: InputEvent| {
                                                let mut next = (*user_form).clone();
                                                next.password = event_value(&e);
                                                user_form.set(next);
                                            })
                                        }}
                                        placeholder="•••••••"
                                    />
                                </label>
                                <label class="field">
                                    <span>{"Role"}</span>
                                    <select onchange={{
                                        let user_form = user_form.clone();
                                        Callback::from(move |e: Event| {
                                            let mut next = (*user_form).clone();
                                            let value = select_value(&e).unwrap_or_else(|| "operator".into());
                                            next.role = match value.as_str() {
                                                "admin" => Role::Admin,
                                                "viewer" => Role::Viewer,
                                                _ => Role::Operator,
                                            };
                                            user_form.set(next);
                                        })
                                    }}>
                                        <option value="operator" selected={user_form.role == Role::Operator}>{"Operator"}</option>
                                        <option value="admin" selected={user_form.role == Role::Admin}>{"Admin"}</option>
                                        <option value="viewer" selected={user_form.role == Role::Viewer}>{"Viewer"}</option>
                                    </select>
                                </label>
                                <div class="actions">
                                    <button class="primary" type="submit">{"Create user"}</button>
                                    <StatusBadge status={(*status).clone()} />
                                </div>
                            </form>
                            <div class="cards">
                                { for (*users).iter().cloned().map(|user| {
                                    let id = user.id;
                                    html!{
                                        <article class="card" key={id.to_string()}>
                                            <div class="card-head">
                                                <div>
                                                    <p class="eyebrow">{"User"}</p>
                                                    <h3>{user.username.clone()}</h3>
                                                    <p class="muted">{format!("{:?}", user.role)}</p>
                                                </div>
                                                <div class="pill-row">
                                                    <button class="ghost" onclick={{
                                                        let users = users.clone();
                                                        let status = status.clone();
                                                        let handle_error = handle_error.clone();
                                                        Callback::from(move |_| {
                                                            let users = users.clone();
                                                            let status = status.clone();
                                                            let handle_error = handle_error.clone();
                                                            spawn_local(async move {
                                                                match api_delete_user(id).await {
                                                                    Ok(_) => {
                                                                        users.set(users.iter().cloned().filter(|u| u.id != id).collect());
                                                                        status.set(StatusLine::success("Deleted user"));
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
                                })}
                            </div>
                        </section>
                    },
                }}
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
                    if listener.tls.is_some() {
                        html! { <span class="pill pill-glow">{"TLS"}</span> }
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
        </article>
    }
}

#[derive(Clone)]
struct ListenerForm {
    name: String,
    listen: String,
    protocol: Protocol,
    upstreams_text: String,
    tls_enabled: bool,
    cert_path: String,
    key_path: String,
    acme_enabled: bool,
    acme_email: String,
    acme_directory: String,
    acme_cache: String,
    acme_challenge: AcmeChallenge,
    acme_provider: String,
    sticky: StickyMode,
    cookie_name: String,
}

#[derive(Clone, PartialEq, Debug)]
enum Tab {
    Listeners,
    Users,
    Metrics,
    Acme,
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
    api_token: String,
    access_key: String,
    secret_key: String,
    zone: String,
    txt_prefix: String,
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
            upstreams_text: String::from("http://127.0.0.1:7000"),
            tls_enabled: false,
            cert_path: String::new(),
            key_path: String::new(),
            acme_enabled: false,
            acme_email: String::new(),
            acme_directory: String::new(),
            acme_cache: String::new(),
            acme_challenge: AcmeChallenge::Http01,
            acme_provider: String::new(),
            sticky: StickyMode::None,
            cookie_name: String::from("BALOR_STICKY"),
        }
    }
}

impl Default for AcmeProviderForm {
    fn default() -> Self {
        Self {
            name: String::new(),
            provider: DnsProvider::Cloudflare,
            api_token: String::new(),
            access_key: String::new(),
            secret_key: String::new(),
            zone: String::new(),
            txt_prefix: "_acme-challenge".into(),
        }
    }
}

impl AcmeProviderForm {
    fn from_config(cfg: &AcmeProviderConfig) -> Self {
        Self {
            name: cfg.name.clone(),
            provider: cfg.provider.clone(),
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
            api_token: (!self.api_token.trim().is_empty()).then(|| self.api_token),
            access_key: (!self.access_key.trim().is_empty()).then(|| self.access_key),
            secret_key: (!self.secret_key.trim().is_empty()).then(|| self.secret_key),
            zone: (!self.zone.trim().is_empty()).then(|| self.zone),
            txt_prefix: (!self.txt_prefix.trim().is_empty()).then(|| self.txt_prefix),
        }
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

        let (acme_enabled, acme_email, acme_directory, acme_cache, acme_challenge, acme_provider) =
            if let Some(acme) = &listener.acme {
                (
                    true,
                    acme.email.clone().unwrap_or_default(),
                    acme.directory_url.clone().unwrap_or_default(),
                    acme.cache_dir.clone().unwrap_or_default(),
                    acme.challenge.clone(),
                    acme.provider.clone().unwrap_or_default(),
                )
            } else {
                (
                    false,
                    String::new(),
                    String::new(),
                    String::new(),
                    AcmeChallenge::Http01,
                    String::new(),
                )
            };

        Self {
            name: listener.name.clone(),
            listen: listener.listen.clone(),
            protocol: listener.protocol.clone(),
            upstreams_text,
            tls_enabled,
            cert_path,
            key_path,
            acme_enabled,
            acme_email,
            acme_directory,
            acme_cache,
            acme_challenge,
            acme_provider,
            sticky,
            cookie_name,
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

        if upstreams.is_empty() {
            return Err("Add at least one upstream".into());
        }

        let tls = if self.tls_enabled && self.protocol == Protocol::Http {
            if self.acme_enabled {
                return Err("Choose either ACME automation or TLS PEM paths, not both".into());
            }
            if self.cert_path.trim().is_empty() || self.key_path.trim().is_empty() {
                return Err("Provide TLS cert and key paths".into());
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
                cache_dir: (!self.acme_cache.trim().is_empty()).then(|| self.acme_cache.clone()),
                challenge: self.acme_challenge.clone(),
                provider: (!self.acme_provider.trim().is_empty())
                    .then(|| self.acme_provider.clone()),
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
            upstreams,
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
    let (name, address) = if let Some((name, addr)) = trimmed.split_once('=') {
        (name.trim().to_string(), addr.trim().to_string())
    } else {
        (format!("upstream-{}", index + 1), trimmed.to_string())
    };

    if address.is_empty() {
        return Err("Upstream address cannot be empty".into());
    }

    Ok(UpstreamPayload {
        name,
        address,
        enabled: true,
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

fn with_auth(req: gloo_net::http::RequestBuilder) -> gloo_net::http::RequestBuilder {
    if let Some(session) = load_session() {
        req.header("Authorization", &format!("Bearer {}", session.token))
    } else {
        req
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
        return Err(format!("{status}: {body}"));
    }

    serde_json::from_str(&body).map_err(|e| format!("parse failed: {e}; body: {body}"))
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
