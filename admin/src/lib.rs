// Balor admin UI
// Author: Eduard Gevorkyan (egevorky@arencloud.com)
// License: Apache 2.0

use gloo_net::http::Request;
use gloo_timers::callback::Interval;
use serde::{Deserialize, Serialize};
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

    {
        let listeners = listeners.clone();
        let stats = stats.clone();
        let status = status.clone();
        let loading = loading.clone();
        use_effect_with((), move |_| {
            loading.set(true);
            spawn_local(async move {
                match api_listeners().await {
                    Ok(items) => {
                        listeners.set(items);
                        status.set(StatusLine::clear());
                    }
                    Err(err) => status.set(StatusLine::error(err)),
                }
                match api_stats().await {
                    Ok(s) => stats.set(s),
                    Err(err) => status.set(StatusLine::error(err)),
                }
                loading.set(false);
            });
            || ()
        });
    }

    {
        let listeners = listeners.clone();
        let stats = stats.clone();
        let status = status.clone();
        use_effect_with((), move |_| {
            let interval = Interval::new(5000, move || {
                let listeners = listeners.clone();
                let stats = stats.clone();
                let status = status.clone();
                spawn_local(async move {
                    match api_listeners().await {
                        Ok(items) => listeners.set(items),
                        Err(err) => status.set(StatusLine::error(err)),
                    }
                    match api_stats().await {
                        Ok(s) => stats.set(s),
                        Err(err) => status.set(StatusLine::error(err)),
                    }
                });
            });
            move || drop(interval)
        });
    }

    let on_submit = {
        let form = form.clone();
        let listeners = listeners.clone();
        let status = status.clone();
        let loading = loading.clone();
        let editing = editing.clone();
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
                    Err(err) => status.set(StatusLine::error(err)),
                }
                loading.set(false);
            });
        })
    };

    let on_delete = {
        let listeners = listeners.clone();
        let status = status.clone();
        Callback::from(move |id: Uuid| {
            let listeners = listeners.clone();
            let status = status.clone();
            spawn_local(async move {
                if let Err(err) = api_delete_listener(id).await {
                    status.set(StatusLine::error(err));
                    return;
                }
                status.set(StatusLine::success("Deleted listener"));
                let filtered: Vec<_> = listeners.iter().cloned().filter(|l| l.id != id).collect();
                listeners.set(filtered);
            });
        })
    };

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
                    <div class="pill">{"Rust + WASM UI"}</div>
                    <div class="pill pill-glow">{"Round robin HTTP/TCP"}</div>
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

            <main class="content">
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
                                        let target: web_sys::HtmlSelectElement = e.target_unchecked_into();
                                        next.protocol = if target.value() == "tcp" { Protocol::Tcp } else { Protocol::Http };
                                        if next.protocol == Protocol::Tcp {
                                            next.tls_enabled = false;
                                            next.cert_path.clear();
                                            next.key_path.clear();
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
                                        let target: web_sys::HtmlSelectElement = e.target_unchecked_into();
                                        next.sticky = match target.value().as_str() {
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
                                                            form.set(next);
                                                        })
                                                    }}
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
    sticky: StickyMode,
    cookie_name: String,
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
            sticky: StickyMode::None,
            cookie_name: String::from("BALOR_STICKY"),
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

        Self {
            name: listener.name.clone(),
            listen: listener.listen.clone(),
            protocol: listener.protocol.clone(),
            upstreams_text,
            tls_enabled,
            cert_path,
            key_path,
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

async fn api_listeners() -> Result<Vec<Listener>, String> {
    let resp = Request::get("/api/listeners")
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    parse_json_response::<Vec<Listener>>(resp).await
}

async fn api_stats() -> Result<Stats, String> {
    let resp = Request::get("/api/stats")
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    parse_json_response::<Stats>(resp).await
}

async fn api_create_listener(payload: ListenerPayload) -> Result<Listener, String> {
    let resp = Request::post("/api/listeners")
        .json(&payload)
        .map_err(|e| format!("serialize: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    parse_json_response::<Listener>(resp).await
}

async fn api_update_listener(id: Uuid, payload: ListenerPayload) -> Result<Listener, String> {
    let url = format!("/api/listeners/{}", id);
    let resp = Request::put(&url)
        .json(&payload)
        .map_err(|e| format!("serialize: {e}"))?
        .send()
        .await
        .map_err(|e| format!("request failed: {e}"))?;

    parse_json_response::<Listener>(resp).await
}

async fn api_delete_listener(id: Uuid) -> Result<(), String> {
    let url = format!("/api/listeners/{}", id);
    let resp = Request::delete(&url)
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
