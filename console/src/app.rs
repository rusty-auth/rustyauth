use base64::Engine as _;
use dioxus::prelude::*;
use dx_icons_tabler::{Icon, TablerIcon};

use crate::fixtures::{
    AUTH_VOLUME, PREVIEW_METRICS, PREVIEW_OPERATOR, preview_fleet_connections,
    preview_fleet_environments, preview_fleet_organizations, preview_fleet_projects,
    preview_organization, preview_service_accounts, preview_users, preview_webhooks,
};
use crate::fleet_client;
use crate::models::{NavKey, OrganizationView, ServiceAccountView, UserView, WebhookView};
use crate::proto::rustyauth::fleet::v1::{
    AuditEvent, ConnectionState, Environment as FleetEnvironment, EnvironmentKind, FleetOverview,
    Organization as FleetOrganization, Project as FleetProject, RealmConnection,
};

const DASHBOARD_STYLES: &str = include_str!("../../dashboard/src/styles.css");
const BRAND_LOCKUP: &[u8] = include_bytes!("../../site/public/brand/rustyauth-lockup.png");
const BRAND_LOCKUP_DARK: &[u8] =
    include_bytes!("../../site/public/brand/rustyauth-lockup-dark.png");
const BRAND_MARK: &[u8] = include_bytes!("../../site/public/brand/rustyauth-mark.png");
const BRAND_MARK_TRANSPARENT: &[u8] =
    include_bytes!("../../site/public/brand/rustyauth-mark-transparent.png");
const OPERATOR_PAPER: &[u8] = include_bytes!("../../site/public/brand/operator-paper-v1.webp");

#[derive(Clone, Copy, PartialEq)]
enum AppView {
    Dashboard(DashboardMode),
    SignIn(SignInVariant),
    Setup,
}

#[derive(Clone, Copy, PartialEq)]
enum DashboardMode {
    Preview,
    Live,
}

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
enum SignInVariant {
    Classic,
    Aperture,
}

#[allow(non_snake_case)]
pub fn App() -> Element {
    let mut view = use_signal(initial_app_view);
    let mut active = use_signal(|| NavKey::FleetOverview);
    let mut mobile_nav = use_signal(|| false);
    let mut organization = use_signal(preview_organization);
    let accounts = use_signal(preview_service_accounts);
    let paper_uri = format!(
        "data:image/webp;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(OPERATOR_PAPER)
    );
    let embedded_styles = format!(
        "{}\n.auth-copy h1 {{ width: 110%; max-width: none; transform: scaleX(0.925); transform-origin: left top; }}\n.aperture-copy h1 {{ width: 107.53%; transform: scaleX(0.93); transform-origin: left top; }}",
        DASHBOARD_STYLES.replace("/brand/operator-paper-v1.webp", &paper_uri)
    );

    rsx! {
        style { dangerous_inner_html: embedded_styles }
        match view() {
            AppView::SignIn(SignInVariant::Classic) => rsx! {
                SignInScreen {
                    on_authenticated: move |_| {
                        active.set(NavKey::FleetOverview);
                        navigate_to(&mut view, AppView::Dashboard(DashboardMode::Live));
                    },
                    on_preview: move |_| {
                        active.set(NavKey::FleetOverview);
                        navigate_to(&mut view, AppView::Dashboard(DashboardMode::Preview));
                    },
                    on_setup: move |_| navigate_to(&mut view, AppView::Setup),
                }
            },
            AppView::SignIn(SignInVariant::Aperture) => rsx! {
                ApertureSignInScreen {
                    on_authenticated: move |_| {
                        active.set(NavKey::FleetOverview);
                        navigate_to(&mut view, AppView::Dashboard(DashboardMode::Live));
                    },
                    on_preview: move |_| {
                        active.set(NavKey::FleetOverview);
                        navigate_to(&mut view, AppView::Dashboard(DashboardMode::Preview));
                    },
                    on_setup: move |_| navigate_to(&mut view, AppView::Setup),
                }
            },
            AppView::Setup => rsx! {
                OperatorSetupScreen {
                    on_registered: move |_| {
                        active.set(NavKey::FleetOverview);
                        navigate_to(&mut view, AppView::Dashboard(DashboardMode::Live));
                    },
                    on_back: move |_| navigate_to(&mut view, AppView::SignIn(SignInVariant::Classic)),
                }
            },
            AppView::Dashboard(mode) => rsx! {
                div { class: "app-shell",
                    if mobile_nav() {
                        button {
                            r#type: "button",
                            class: "mobile-nav-scrim",
                            aria_label: "Close navigation",
                            onclick: move |_| mobile_nav.set(false),
                        }
                    }
                    Sidebar {
                        active: active(),
                        preview: mode == DashboardMode::Preview,
                        mobile_open: mobile_nav(),
                        on_navigate: move |key| {
                            active.set(key);
                            mobile_nav.set(false);
                        },
                        on_sign_out: move |_| {
                            if mode == DashboardMode::Live {
                                spawn(async move {
                                    let _ = fleet_client::sign_out().await;
                                    navigate_to(&mut view, AppView::SignIn(SignInVariant::Classic));
                                });
                            } else {
                                navigate_to(&mut view, AppView::SignIn(SignInVariant::Classic));
                            }
                        },
                    }
                    main { class: "main-stage",
                        Topbar {
                            title: active().label(),
                            on_menu: move |_| mobile_nav.toggle(),
                            on_navigate: move |key| active.set(key),
                            on_sign_out: move |_| {
                                if mode == DashboardMode::Live {
                                    spawn(async move {
                                        let _ = fleet_client::sign_out().await;
                                        navigate_to(&mut view, AppView::SignIn(SignInVariant::Classic));
                                    });
                                } else {
                                    navigate_to(&mut view, AppView::SignIn(SignInVariant::Classic));
                                }
                            },
                        }
                        div { class: "page-canvas",
                            PreviewBanner {
                                preview: mode == DashboardMode::Preview,
                                on_connect: move |_| navigate_to(&mut view, AppView::SignIn(SignInVariant::Classic)),
                            }
                            match active() {
                                NavKey::FleetOverview | NavKey::Organizations | NavKey::Projects | NavKey::Environments | NavKey::Connections | NavKey::Audit => rsx! {
                                    FleetWorkspace { mode, active: active(), on_navigate: move |key| active.set(key) }
                                },
                                NavKey::Overview => rsx! {
                                    OverviewPage {
                                        organization: organization(),
                                        accounts: accounts(),
                                        on_navigate: move |key| active.set(key),
                                    }
                                },
                                NavKey::Users => rsx! { UsersPage {} },
                                NavKey::Organization => rsx! {
                                    OrganizationPage {
                                        organization: organization(),
                                        on_update: move |name: String| organization.write().name = name,
                                    }
                                },
                                NavKey::ServiceAccounts => rsx! { ServiceAccountsPage { accounts: accounts() } },
                                NavKey::Webhooks => rsx! { WebhooksPage {} },
                                NavKey::Metrics => rsx! { MetricsPage {} },
                            }
                        }
                    }
                }
            },
        }
    }
}

fn initial_app_view() -> AppView {
    #[cfg(target_arch = "wasm32")]
    {
        let search = web_sys::window()
            .and_then(|window| window.location().search().ok())
            .unwrap_or_default();

        if search.contains("preview=1") {
            return AppView::Dashboard(DashboardMode::Preview);
        }
        if search.contains("fleet=1") {
            return AppView::Dashboard(DashboardMode::Live);
        }
        if search.contains("login=aperture") {
            return AppView::SignIn(SignInVariant::Aperture);
        }
        if search.contains("setup=1") {
            return AppView::Setup;
        }
    }

    AppView::SignIn(SignInVariant::Classic)
}

fn navigate_to(view: &mut Signal<AppView>, next: AppView) {
    view.set(next);

    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window()
        && let Ok(history) = window.history()
    {
        let path = match next {
            AppView::Dashboard(DashboardMode::Preview) => "/?preview=1",
            AppView::Dashboard(DashboardMode::Live) => "/?fleet=1",
            AppView::SignIn(SignInVariant::Classic) => "/",
            AppView::SignIn(SignInVariant::Aperture) => "/?login=aperture",
            AppView::Setup => "/?setup=1",
        };
        let _ = history.replace_state_with_url(&wasm_bindgen::JsValue::NULL, "", Some(path));
    }
}

fn png_data(bytes: &[u8]) -> String {
    format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(bytes)
    )
}

#[component]
fn SignInScreen(
    on_authenticated: EventHandler<()>,
    on_preview: EventHandler<()>,
    on_setup: EventHandler<()>,
) -> Element {
    let mut email = use_signal(|| "admin@rustyauth.local".to_string());
    let mut error = use_signal(String::new);
    let mut authenticating = use_signal(|| false);
    let brand_mark = png_data(BRAND_MARK);

    rsx! {
        main { class: "auth-stage",
            section { class: "auth-card",
                header { class: "auth-brand",
                    img { src: brand_mark, width: "48", height: "48", alt: "" }
                    div {
                        strong { "Rusty" span { "Auth" } }
                        small { "Operator control plane" }
                    }
                }
                div { class: "auth-copy",
                    p { class: "eyebrow", "Passkey-protected administration" }
                    h1 { "Operate your identity boundary." }
                    p { "Search accounts, rotate service credentials and inspect delivery health without exposing SableDB." }
                }
                form { onsubmit: move |event| {
                    event.prevent_default();
                    if email().trim().is_empty() {
                        error.set("Enter the operator email bound to your passkey.".to_string());
                    } else {
                        authenticating.set(true);
                        error.set(String::new());
                        let operator_email = email().trim().to_owned();
                        spawn(async move {
                            match fleet_client::authenticate_passkey(&operator_email).await {
                                Ok(()) => on_authenticated.call(()),
                                Err(reason) => error.set(reason.0),
                            }
                            authenticating.set(false);
                        });
                    }
                },
                    label { r#for: "operator-email", "Operator email" }
                    input {
                        id: "operator-email",
                        r#type: "email",
                        autocomplete: "username webauthn",
                        value: email(),
                        required: true,
                        oninput: move |event| {
                            error.set(String::new());
                            email.set(event.value());
                        },
                    }
                    if !error().is_empty() {
                        p { class: "form-error", role: "alert",
                            Icon { icon: TablerIcon::AlertTriangle, size: 16 }
                            "{error}"
                        }
                    }
                    button { class: "button primary wide", r#type: "submit", disabled: authenticating(),
                        Icon { icon: TablerIcon::ShieldCheck, size: 18 }
                        if authenticating() { "Waiting for passkey…" } else { "Continue with passkey" }
                    }
                }
                div { class: "auth-divider", span { "Local evaluation" } }
                button { class: "button secondary wide", r#type: "button", onclick: move |_| on_preview.call(()),
                    "Open populated preview "
                    Icon { icon: TablerIcon::ArrowUpRight, size: 17 }
                }
                button { class: "auth-setup-link", r#type: "button", onclick: move |_| on_setup.call(()),
                    "Set up the first operator passkey"
                }
                p { class: "auth-footnote",
                    "Only users listed in " code { "AUTH_OPERATOR_EMAILS" } " can bootstrap operator access."
                }
            }
            aside { class: "auth-aside",
                p { class: "eyebrow", "Trust boundary" }
                div { class: "boundary-stack",
                    AuthBoundaryItem { icon: TablerIcon::UserCircle, label: "Operator", detail: "Passkey + HttpOnly session" }
                    AuthBoundaryItem { icon: TablerIcon::ShieldCheck, label: "RustyAuth", detail: "Authorization and audit policy", class: "accent" }
                    AuthBoundaryItem { icon: TablerIcon::Database, label: "SableDB", detail: "Private durable state", class: "dark" }
                }
            }
        }
    }
}

#[component]
fn OperatorSetupScreen(on_registered: EventHandler<()>, on_back: EventHandler<()>) -> Element {
    let mut email = use_signal(|| "admin@rustyauth.local".to_string());
    let mut display_name = use_signal(|| "Local owner".to_string());
    let mut bootstrap_token = use_signal(String::new);
    let mut error = use_signal(String::new);
    let mut registering = use_signal(|| false);
    let brand_mark = png_data(BRAND_MARK);

    rsx! {
        main { class: "auth-stage",
            section { class: "auth-card setup-card",
                header { class: "auth-brand",
                    img { src: brand_mark, width: "48", height: "48", alt: "" }
                    div { strong { "Rusty" span { "Auth" } } small { "Fleet first-run setup" } }
                }
                div { class: "auth-copy",
                    p { class: "eyebrow", "One-time local enrolment" }
                    h1 { "Create the first operator." }
                    p { "Bind the allowlisted owner account to a passkey. The bootstrap token is sent once and never stored by the dashboard." }
                }
                form { onsubmit: move |event| {
                    event.prevent_default();
                    if email().trim().is_empty() || display_name().trim().is_empty() || bootstrap_token().trim().is_empty() {
                        error.set("Complete all fields before creating the operator passkey.".into());
                        return;
                    }
                    registering.set(true);
                    error.set(String::new());
                    let operator_email = email().trim().to_owned();
                    let operator_name = display_name().trim().to_owned();
                    let token = bootstrap_token().trim().to_owned();
                    bootstrap_token.set(String::new());
                    spawn(async move {
                        match fleet_client::register_operator_passkey(&operator_email, &operator_name, &token).await {
                            Ok(()) => on_registered.call(()),
                            Err(reason) => error.set(reason.0),
                        }
                        registering.set(false);
                    });
                },
                    label { r#for: "setup-name", "Display name" }
                    input { id: "setup-name", value: display_name(), required: true, autocomplete: "name", oninput: move |event| display_name.set(event.value()) }
                    label { r#for: "setup-email", "Allowlisted operator email" }
                    input { id: "setup-email", r#type: "email", value: email(), required: true, autocomplete: "username", oninput: move |event| email.set(event.value()) }
                    label { r#for: "setup-token", "Bootstrap token" }
                    input { id: "setup-token", r#type: "password", value: bootstrap_token(), required: true, autocomplete: "off", oninput: move |event| bootstrap_token.set(event.value()) }
                    if !error().is_empty() {
                        p { class: "form-error", role: "alert", Icon { icon: TablerIcon::AlertTriangle, size: 16 } "{error}" }
                    }
                    button { class: "button primary wide", r#type: "submit", disabled: registering(),
                        Icon { icon: TablerIcon::ShieldCheck, size: 18 }
                        if registering() { "Creating passkey…" } else { "Create operator passkey" }
                    }
                }
                button { class: "auth-setup-link", r#type: "button", onclick: move |_| on_back.call(()), "Back to operator sign in" }
                p { class: "auth-footnote", "Local setup reads the token from " code { ".env.fleet.local" } ". Production should use a reviewed invitation controller." }
            }
            aside { class: "auth-aside",
                p { class: "eyebrow", "Credential path" }
                div { class: "boundary-stack",
                    AuthBoundaryItem { icon: TablerIcon::UserCircle, label: "Operator", detail: "User verification on this device" }
                    AuthBoundaryItem { icon: TablerIcon::ShieldCheck, label: "Passkey", detail: "Bound to the allowlisted identity", class: "accent" }
                    AuthBoundaryItem { icon: TablerIcon::Database, label: "Control plane", detail: "HttpOnly session and operator policy", class: "dark" }
                }
            }
        }
    }
}

#[component]
fn AuthBoundaryItem(
    icon: TablerIcon,
    label: &'static str,
    detail: &'static str,
    #[props(default)] class: &'static str,
) -> Element {
    let classes = if class.is_empty() {
        "boundary-item".to_string()
    } else {
        format!("boundary-item {class}")
    };

    rsx! {
        div { class: classes,
            Icon { icon, size: 20 }
            div { strong { "{label}" } span { "{detail}" } }
        }
    }
}

#[component]
fn ApertureSignInScreen(
    on_authenticated: EventHandler<()>,
    on_preview: EventHandler<()>,
    on_setup: EventHandler<()>,
) -> Element {
    let mut email = use_signal(|| "admin@rustyauth.local".to_string());
    let mut error = use_signal(String::new);
    let mut authenticating = use_signal(|| false);
    let brand_lockup = png_data(BRAND_LOCKUP_DARK);
    let emboss_mark = png_data(BRAND_MARK_TRANSPARENT);

    rsx! {
        main { class: "aperture-auth-stage",
            div { class: "aperture-atmosphere", aria_hidden: "true" }
            div { class: "aperture-watermark", aria_hidden: "true",
                img { class: "aperture-watermark-shadow", src: emboss_mark.clone(), alt: "" }
                img { class: "aperture-watermark-highlight", src: emboss_mark, alt: "" }
            }
            section { class: "aperture-console", aria_labelledby: "aperture-title",
                aside { class: "aperture-trust-rail",
                    header { class: "aperture-brand",
                        img { src: brand_lockup, width: "210", height: "73", alt: "RustyAuth" }
                        p { "Operator control plane" }
                    }
                    div { class: "aperture-boundary",
                        p { class: "aperture-kicker", "Trust boundary" }
                        ol {
                            ApertureBoundaryItem { icon: TablerIcon::UserCircle, label: "Operator", detail: "Passkey + device" }
                            ApertureBoundaryItem { icon: TablerIcon::ShieldCheck, label: "RustyAuth", detail: "Authorization and audit policy", active: true }
                            ApertureBoundaryItem { icon: TablerIcon::Database, label: "SableDB", detail: "Private durable state" }
                        }
                    }
                }
                div { class: "aperture-form-panel",
                    header { class: "aperture-copy",
                        p { class: "aperture-kicker", "Passkey-protected administration" }
                        h1 { id: "aperture-title", "Operator access." br {} "Identity-bound by design." }
                        p { "Search accounts, rotate service credentials and inspect delivery health without exposing SableDB." }
                    }
                    form { onsubmit: move |event| {
                        event.prevent_default();
                        if email().trim().is_empty() {
                            error.set("Enter the operator email bound to your passkey.".to_string());
                        } else {
                            authenticating.set(true);
                            error.set(String::new());
                            let operator_email = email().trim().to_owned();
                            spawn(async move {
                                match fleet_client::authenticate_passkey(&operator_email).await {
                                    Ok(()) => on_authenticated.call(()),
                                    Err(reason) => error.set(reason.0),
                                }
                                authenticating.set(false);
                            });
                        }
                    },
                        label { r#for: "aperture-operator-email", "Operator email" }
                        input {
                            id: "aperture-operator-email",
                            r#type: "email",
                            autocomplete: "username webauthn",
                            value: email(),
                            required: true,
                            oninput: move |event| {
                                error.set(String::new());
                                email.set(event.value());
                            },
                        }
                        if !error().is_empty() {
                            p { class: "aperture-error", role: "alert",
                                Icon { icon: TablerIcon::AlertTriangle, size: 16 }
                                "{error}"
                            }
                        }
                        button { class: "aperture-submit", r#type: "submit", disabled: authenticating(),
                            Icon { icon: TablerIcon::ShieldCheck, size: 19 }
                            span { if authenticating() { "Waiting for passkey…" } else { "Continue with passkey" } }
                        }
                    }
                    div { class: "aperture-divider", span { "Local evaluation" } }
                    button { class: "aperture-preview", r#type: "button", onclick: move |_| on_preview.call(()),
                        span { "Open populated preview" }
                        Icon { icon: TablerIcon::ArrowUpRight, size: 18 }
                    }
                    button { class: "aperture-setup-link", r#type: "button", onclick: move |_| on_setup.call(()),
                        "Set up the first operator passkey"
                    }
                    p { class: "aperture-footnote",
                        "Only users listed in " code { "AUTH_OPERATOR_EMAILS" } " can bootstrap operator access."
                    }
                }
            }
        }
    }
}

#[component]
fn ApertureBoundaryItem(
    icon: TablerIcon,
    label: &'static str,
    detail: &'static str,
    #[props(default)] active: bool,
) -> Element {
    rsx! {
        li { class: if active { "active" } else { "" },
            span { class: "aperture-boundary-icon", Icon { icon, size: 22 } }
            span { strong { "{label}" } small { "{detail}" } }
        }
    }
}

#[component]
fn Sidebar(
    active: NavKey,
    preview: bool,
    mobile_open: bool,
    on_navigate: EventHandler<NavKey>,
    on_sign_out: EventHandler<()>,
) -> Element {
    let sidebar_class = if mobile_open {
        "sidebar open"
    } else {
        "sidebar"
    };
    let brand_lockup = format!(
        "data:image/png;base64,{}",
        base64::engine::general_purpose::STANDARD.encode(BRAND_LOCKUP)
    );

    rsx! {
        aside { class: sidebar_class,
            a {
                class: "dashboard-brand",
                href: "/",
                aria_label: "RustyAuth control plane",
                onclick: move |event| {
                    event.prevent_default();
                    on_sign_out.call(());
                },
                img {
                    src: brand_lockup,
                    width: "154",
                    height: "54",
                    alt: "RustyAuth",
                }
            }
            div { class: "instance-switcher",
                span { class: "instance-mark", "FL" }
                div {
                    strong { "RustyAuth Fleet" }
                    small { if preview { "Sample control plane" } else { "Connected control plane" } }
                }
                Icon { icon: TablerIcon::ChevronRight, size: 16 }
            }
            nav { class: "side-nav", aria_label: "Control plane",
                p { "Workspace" }
                NavButton {
                    active: active == NavKey::FleetOverview,
                    icon: TablerIcon::LayoutDashboard,
                    label: "Fleet overview",
                    onclick: move |_| on_navigate.call(NavKey::FleetOverview),
                }
                NavButton {
                    active: active == NavKey::Organizations,
                    icon: TablerIcon::Building,
                    label: "Organizations",
                    onclick: move |_| on_navigate.call(NavKey::Organizations),
                }
                NavButton {
                    active: active == NavKey::Projects,
                    icon: TablerIcon::LayoutDashboard,
                    label: "Projects",
                    onclick: move |_| on_navigate.call(NavKey::Projects),
                }
                NavButton {
                    active: active == NavKey::Environments,
                    icon: TablerIcon::Database,
                    label: "Environments",
                    onclick: move |_| on_navigate.call(NavKey::Environments),
                }
                NavButton {
                    active: active == NavKey::Connections,
                    icon: TablerIcon::Webhook,
                    label: "Connections",
                    onclick: move |_| on_navigate.call(NavKey::Connections),
                }
                NavButton {
                    active: active == NavKey::Audit,
                    icon: TablerIcon::ChartHistogram,
                    label: "Audit log",
                    onclick: move |_| on_navigate.call(NavKey::Audit),
                }
                p { "Realm operations" }
                NavButton {
                    active: active == NavKey::Overview,
                    icon: TablerIcon::LayoutDashboard,
                    label: "Overview",
                    onclick: move |_| on_navigate.call(NavKey::Overview),
                }
                NavButton {
                    active: active == NavKey::Users,
                    icon: TablerIcon::Users,
                    label: "Users",
                    onclick: move |_| on_navigate.call(NavKey::Users),
                }
                NavButton {
                    active: active == NavKey::Organization,
                    icon: TablerIcon::Building,
                    label: "Organization",
                    onclick: move |_| on_navigate.call(NavKey::Organization),
                }
                NavButton {
                    active: active == NavKey::ServiceAccounts,
                    icon: TablerIcon::Key,
                    label: "Service accounts",
                    onclick: move |_| on_navigate.call(NavKey::ServiceAccounts),
                }
                NavButton {
                    active: active == NavKey::Webhooks,
                    icon: TablerIcon::Webhook,
                    label: "Webhooks",
                    badge: Some("3"),
                    onclick: move |_| on_navigate.call(NavKey::Webhooks),
                }
                NavButton {
                    active: active == NavKey::Metrics,
                    icon: TablerIcon::ChartHistogram,
                    label: "Metrics",
                    onclick: move |_| on_navigate.call(NavKey::Metrics),
                }
            }
            div { class: "sidebar-foot",
                div { class: "system-state",
                    span { class: "status-dot" }
                    div {
                        strong { "All systems nominal" }
                        small { "SableDB · 12 ms" }
                    }
                }
                button {
                    r#type: "button",
                    class: "operator-mini",
                    title: "Close preview",
                    onclick: move |_| on_sign_out.call(()),
                    span { "LO" }
                    div {
                        strong { "Local owner" }
                        small { "Owner" }
                    }
                    Icon { icon: TablerIcon::Logout, size: 17 }
                }
            }
        }
    }
}

#[component]
fn NavButton(
    active: bool,
    icon: TablerIcon,
    label: &'static str,
    onclick: EventHandler<MouseEvent>,
    #[props(default)] badge: Option<&'static str>,
) -> Element {
    let class = if active { "active" } else { "" };
    rsx! {
        button { r#type: "button", class, onclick,
            Icon { icon, size: 18 }
            span { "{label}" }
            if let Some(value) = badge {
                i { "{value}" }
            }
        }
    }
}

#[component]
fn Topbar(
    title: &'static str,
    on_menu: EventHandler<()>,
    on_navigate: EventHandler<NavKey>,
    on_sign_out: EventHandler<()>,
) -> Element {
    let mut menu_open = use_signal(|| false);
    let mut profile_open = use_signal(|| false);

    rsx! {
        header { class: "topbar",
            button {
                r#type: "button",
                class: "icon-button mobile-menu",
                aria_label: "Open navigation",
                onclick: move |_| on_menu.call(()),
                Icon { icon: TablerIcon::Menu2, size: 20 }
            }
            div {
                p { class: "eyebrow", "RustyAuth / Control plane" }
                h1 { "{title}" }
            }
            div { class: "topbar-actions",
                div { class: "runtime-meta", aria_label: "Runtime environment",
                    span { class: "workspace-mode", "Sample workspace" }
                    span { class: "runtime-state",
                        i {}
                        " Local"
                    }
                }
                button {
                    r#type: "button",
                    class: "avatar-button",
                    title: PREVIEW_OPERATOR.email,
                    aria_haspopup: "menu",
                    aria_expanded: menu_open(),
                    onclick: move |_| menu_open.toggle(),
                    "LO"
                }
                if menu_open() {
                    button {
                        r#type: "button",
                        class: "popover-dismiss",
                        aria_label: "Close operator menu",
                        onclick: move |_| menu_open.set(false),
                    }
                    div { class: "operator-popover", role: "menu",
                        header {
                            span { "LO" }
                            div {
                                strong { "Local owner" }
                                small { "admin@rustyauth.local" }
                            }
                        }
                        p { "Owner operator" }
                        button {
                            r#type: "button",
                            role: "menuitem",
                            onclick: move |_| {
                                menu_open.set(false);
                                profile_open.set(true);
                            },
                            Icon { icon: TablerIcon::UserCircle, size: 17 }
                            "Operator profile"
                            Icon { icon: TablerIcon::ChevronRight, size: 15 }
                        }
                        button {
                            r#type: "button",
                            role: "menuitem",
                            onclick: move |_| {
                                menu_open.set(false);
                                on_navigate.call(NavKey::Organization);
                            },
                            Icon { icon: TablerIcon::Building, size: 17 }
                            "Organization settings"
                            Icon { icon: TablerIcon::ChevronRight, size: 15 }
                        }
                        button {
                            r#type: "button",
                            class: "operator-signout",
                            role: "menuitem",
                            onclick: move |_| {
                                menu_open.set(false);
                                on_sign_out.call(());
                            },
                            Icon { icon: TablerIcon::Logout, size: 17 }
                            "Exit preview"
                        }
                    }
                }
            }
        }
        if profile_open() {
            OperatorProfileDrawer { on_close: move |_| profile_open.set(false), on_organization: move |_| {
                profile_open.set(false);
                on_navigate.call(NavKey::Organization);
            }, on_sign_out: move |_| {
                profile_open.set(false);
                on_sign_out.call(());
            } }
        }
    }
}

#[component]
fn PreviewBanner(preview: bool, on_connect: EventHandler<()>) -> Element {
    rsx! {
        div { class: "preview-context", role: "status",
            span { class: "preview-context-label", if preview { "Preview" } else { "Live" } }
            div {
                strong { if preview { "Sample Fleet data is active" } else { "Binary control-plane session is active" } }
                span { if preview { "Changes stay in this browser until you connect the live Rust handlers." } else { "Organization, project, environment and connection changes are persisted in Fleet SableDB." } }
            }
            if preview {
                a {
                    href: "/",
                    onclick: move |event| {
                        event.prevent_default();
                        on_connect.call(());
                    },
                    "Connect live "
                    Icon { icon: TablerIcon::ArrowUpRight, size: 14 }
                }
            }
        }
    }
}

#[component]
fn OperatorProfileDrawer(
    on_close: EventHandler<()>,
    on_organization: EventHandler<()>,
    on_sign_out: EventHandler<()>,
) -> Element {
    rsx! {
        div { class: "drawer-backdrop", onclick: move |_| on_close.call(()),
            aside { class: "drawer operator-drawer", aria_label: "Operator profile", onclick: move |event| event.stop_propagation(),
                header {
                    div {
                        p { class: "eyebrow", "Operator session" }
                        h3 { "Profile & access" }
                    }
                    button { r#type: "button", class: "icon-button", aria_label: "Close operator profile", onclick: move |_| on_close.call(()),
                        Icon { icon: TablerIcon::X, size: 18 }
                    }
                }
                div { class: "profile-hero operator-profile-hero",
                    span { "LO" }
                    div {
                        strong { "Local owner" }
                        small { "admin@rustyauth.local" }
                    }
                }
                div { class: "definition",
                    span { "Operator ID" }
                    strong { class: "mono-value", "780a15cd-d5d9-4ebf-82a2-30aff74f06bf" }
                }
                div { class: "definition", span { "Access" } strong { "Owner" } }
                div { class: "definition", span { "Authentication" } strong { "Preview session" } }
                div { class: "operator-session-note",
                    Icon { icon: TablerIcon::ShieldCheck, size: 18 }
                    div {
                        strong { "Local preview session" }
                        span { "No control-plane changes leave this browser." }
                    }
                }
                div { class: "drawer-actions operator-drawer-actions",
                    button { r#type: "button", class: "button secondary", onclick: move |_| on_organization.call(()), "Organization settings" }
                    button { r#type: "button", class: "danger-text", onclick: move |_| on_sign_out.call(()),
                        Icon { icon: TablerIcon::Logout, size: 15 }
                        "Exit preview"
                    }
                }
            }
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FleetDialogKind {
    Organization,
    Project,
    Environment,
    Connection,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FleetMutation {
    Organization {
        slug: String,
        name: String,
    },
    Project {
        slug: String,
        name: String,
    },
    Environment {
        slug: String,
        name: String,
    },
    Connection {
        endpoint: String,
        pairing_code: String,
    },
}

#[component]
fn FleetWorkspace(
    mode: DashboardMode,
    active: NavKey,
    on_navigate: EventHandler<NavKey>,
) -> Element {
    let preview = mode == DashboardMode::Preview;
    let mut organizations = use_signal(|| {
        if preview {
            preview_fleet_organizations()
        } else {
            Vec::new()
        }
    });
    let mut projects = use_signal(|| {
        if preview {
            preview_fleet_projects()
        } else {
            Vec::new()
        }
    });
    let mut environments = use_signal(|| {
        if preview {
            preview_fleet_environments()
        } else {
            Vec::new()
        }
    });
    let mut connections = use_signal(|| {
        if preview {
            preview_fleet_connections()
        } else {
            Vec::new()
        }
    });
    let mut audit_events = use_signal(Vec::<AuditEvent>::new);
    let mut overview = use_signal(|| FleetOverview {
        organizations: u64::from(preview),
        projects: if preview { 2 } else { 0 },
        environments: if preview { 2 } else { 0 },
        healthy_connections: u64::from(preview),
        calculated_at: "2026-08-08T08:30:00Z".into(),
        ..Default::default()
    });
    let mut selected_organization = use_signal(|| {
        organizations
            .read()
            .first()
            .map(|record| record.id.clone())
            .unwrap_or_default()
    });
    let mut selected_project = use_signal(|| {
        projects
            .read()
            .first()
            .map(|record| record.id.clone())
            .unwrap_or_default()
    });
    let mut selected_environment = use_signal(|| {
        environments
            .read()
            .first()
            .map(|record| record.id.clone())
            .unwrap_or_default()
    });
    let mut dialog = use_signal(|| None::<FleetDialogKind>);
    let mut loading = use_signal(|| !preview);
    let mut error = use_signal(String::new);

    use_effect(move || {
        if preview {
            return;
        }
        spawn(async move {
            loading.set(true);
            let result = async {
                let loaded_organizations = fleet_client::organizations().await?;
                let organization_id = loaded_organizations
                    .first()
                    .map(|record| record.id.clone())
                    .unwrap_or_default();
                let loaded_projects = if organization_id.is_empty() {
                    Vec::new()
                } else {
                    fleet_client::projects(&organization_id).await?
                };
                let project_id = loaded_projects
                    .first()
                    .map(|record| record.id.clone())
                    .unwrap_or_default();
                let loaded_environments = if project_id.is_empty() {
                    Vec::new()
                } else {
                    fleet_client::environments(&organization_id, &project_id).await?
                };
                let environment_id = loaded_environments
                    .first()
                    .map(|record| record.id.clone())
                    .unwrap_or_default();
                let loaded_connections = if organization_id.is_empty() {
                    Vec::new()
                } else {
                    fleet_client::connections(
                        &organization_id,
                        (!project_id.is_empty()).then_some(project_id.as_str()),
                        (!environment_id.is_empty()).then_some(environment_id.as_str()),
                    )
                    .await?
                };
                let loaded_overview = fleet_client::overview(None).await?;
                let loaded_audit = fleet_client::audit_events(None).await?;
                Ok::<_, fleet_client::ClientError>((
                    loaded_organizations,
                    loaded_projects,
                    loaded_environments,
                    loaded_connections,
                    loaded_overview,
                    loaded_audit,
                    organization_id,
                    project_id,
                    environment_id,
                ))
            }
            .await;
            match result {
                Ok((
                    new_orgs,
                    new_projects,
                    new_envs,
                    new_connections,
                    new_overview,
                    new_audit,
                    org_id,
                    project_id,
                    env_id,
                )) => {
                    organizations.set(new_orgs);
                    projects.set(new_projects);
                    environments.set(new_envs);
                    connections.set(new_connections);
                    overview.set(new_overview);
                    audit_events.set(new_audit);
                    selected_organization.set(org_id);
                    selected_project.set(project_id);
                    selected_environment.set(env_id);
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
            loading.set(false);
        });
    });

    let mutate = move |mutation: FleetMutation| {
        dialog.set(None);
        error.set(String::new());
        if preview {
            let stamp = "2026-08-08T08:30:00Z".to_string();
            match mutation {
                FleetMutation::Organization { slug, name } => {
                    let record = FleetOrganization {
                        id: uuid::Uuid::new_v4().to_string(),
                        slug,
                        name,
                        state: crate::proto::rustyauth::fleet::v1::ResourceState::Active.into(),
                        created_at: stamp.clone(),
                        updated_at: stamp,
                        ..Default::default()
                    };
                    selected_organization.set(record.id.clone());
                    organizations.write().insert(0, record);
                    overview.write().organizations += 1;
                }
                FleetMutation::Project { slug, name } => {
                    let record = FleetProject {
                        id: uuid::Uuid::new_v4().to_string(),
                        organization_id: selected_organization(),
                        slug,
                        name,
                        state: crate::proto::rustyauth::fleet::v1::ResourceState::Active.into(),
                        created_at: stamp.clone(),
                        updated_at: stamp,
                        ..Default::default()
                    };
                    selected_project.set(record.id.clone());
                    projects.write().insert(0, record);
                    overview.write().projects += 1;
                }
                FleetMutation::Environment { slug, name } => {
                    let record = FleetEnvironment {
                        id: uuid::Uuid::new_v4().to_string(),
                        organization_id: selected_organization(),
                        project_id: selected_project(),
                        slug,
                        name,
                        kind: EnvironmentKind::Development.into(),
                        provider: "Railway".into(),
                        region: "Auto".into(),
                        state: crate::proto::rustyauth::fleet::v1::ResourceState::Active.into(),
                        created_at: stamp.clone(),
                        updated_at: stamp,
                        ..Default::default()
                    };
                    selected_environment.set(record.id.clone());
                    environments.write().insert(0, record);
                    overview.write().environments += 1;
                }
                FleetMutation::Connection { endpoint, .. } => {
                    let record = RealmConnection {
                        id: uuid::Uuid::new_v4().to_string(),
                        organization_id: selected_organization(),
                        project_id: selected_project(),
                        environment_id: selected_environment(),
                        realm_id: "preview-realm".into(),
                        display_name: "Preview realm".into(),
                        mode: crate::proto::rustyauth::fleet::v1::ConnectionMode::PublicEndpoint
                            .into(),
                        management_endpoint: endpoint,
                        deployment_version: "0.1.0".into(),
                        protocol_version: "1".into(),
                        state: ConnectionState::Healthy.into(),
                        last_seen_at: stamp.clone(),
                        created_at: stamp.clone(),
                        updated_at: stamp,
                        ..Default::default()
                    };
                    connections.write().insert(0, record);
                    overview.write().healthy_connections += 1;
                }
            }
            return;
        }
        spawn(async move {
            loading.set(true);
            let result = match mutation {
                FleetMutation::Organization { slug, name } => {
                    fleet_client::create_organization(&slug, &name)
                        .await
                        .map(|record| {
                            selected_organization.set(record.id.clone());
                            organizations.write().insert(0, record);
                            overview.write().organizations += 1;
                        })
                }
                FleetMutation::Project { slug, name } => {
                    fleet_client::create_project(&selected_organization(), &slug, &name)
                        .await
                        .map(|record| {
                            selected_project.set(record.id.clone());
                            projects.write().insert(0, record);
                            overview.write().projects += 1;
                        })
                }
                FleetMutation::Environment { slug, name } => fleet_client::create_environment(
                    &selected_organization(),
                    &selected_project(),
                    &slug,
                    &name,
                    EnvironmentKind::Development,
                )
                .await
                .map(|record| {
                    selected_environment.set(record.id.clone());
                    environments.write().insert(0, record);
                    overview.write().environments += 1;
                }),
                FleetMutation::Connection {
                    endpoint,
                    pairing_code,
                } => {
                    match fleet_client::begin_connection(
                        &selected_organization(),
                        &selected_project(),
                        &selected_environment(),
                        &endpoint,
                    )
                    .await
                    {
                        Ok(attempt) => {
                            fleet_client::complete_connection(&attempt.id, &pairing_code)
                                .await
                                .map(|record| {
                                    connections.write().insert(0, record);
                                    overview.write().healthy_connections += 1;
                                })
                        }
                        Err(reason) => Err(reason),
                    }
                }
            };
            if let Err(reason) = result {
                error.set(reason.0);
            }
            loading.set(false);
        });
    };

    let select_organization = move |organization_id: String| {
        selected_organization.set(organization_id.clone());
        let preview_project = projects
            .read()
            .iter()
            .find(|record| record.organization_id == organization_id)
            .map(|record| record.id.clone())
            .unwrap_or_default();
        selected_project.set(preview_project.clone());
        let preview_environment = environments
            .read()
            .iter()
            .find(|record| record.project_id == preview_project)
            .map(|record| record.id.clone())
            .unwrap_or_default();
        selected_environment.set(preview_environment);
        if preview {
            return;
        }
        projects.set(Vec::new());
        environments.set(Vec::new());
        connections.set(Vec::new());
        spawn(async move {
            loading.set(true);
            let result = async {
                let loaded_projects = fleet_client::projects(&organization_id).await?;
                let project_id = loaded_projects
                    .first()
                    .map(|record| record.id.clone())
                    .unwrap_or_default();
                let loaded_environments = if project_id.is_empty() {
                    Vec::new()
                } else {
                    fleet_client::environments(&organization_id, &project_id).await?
                };
                let environment_id = loaded_environments
                    .first()
                    .map(|record| record.id.clone())
                    .unwrap_or_default();
                let loaded_connections = if environment_id.is_empty() {
                    Vec::new()
                } else {
                    fleet_client::connections(
                        &organization_id,
                        Some(&project_id),
                        Some(&environment_id),
                    )
                    .await?
                };
                Ok::<_, fleet_client::ClientError>((
                    loaded_projects,
                    loaded_environments,
                    loaded_connections,
                    project_id,
                    environment_id,
                ))
            }
            .await;
            match result {
                Ok((
                    loaded_projects,
                    loaded_environments,
                    loaded_connections,
                    project_id,
                    environment_id,
                )) => {
                    projects.set(loaded_projects);
                    environments.set(loaded_environments);
                    connections.set(loaded_connections);
                    selected_project.set(project_id);
                    selected_environment.set(environment_id);
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
            loading.set(false);
        });
    };

    let select_project = move |project_id: String| {
        selected_project.set(project_id.clone());
        let preview_environment = environments
            .read()
            .iter()
            .find(|record| record.project_id == project_id)
            .map(|record| record.id.clone())
            .unwrap_or_default();
        selected_environment.set(preview_environment);
        if preview {
            return;
        }
        environments.set(Vec::new());
        connections.set(Vec::new());
        let organization_id = selected_organization();
        spawn(async move {
            loading.set(true);
            let result = async {
                let loaded_environments =
                    fleet_client::environments(&organization_id, &project_id).await?;
                let environment_id = loaded_environments
                    .first()
                    .map(|record| record.id.clone())
                    .unwrap_or_default();
                let loaded_connections = if environment_id.is_empty() {
                    Vec::new()
                } else {
                    fleet_client::connections(
                        &organization_id,
                        Some(&project_id),
                        Some(&environment_id),
                    )
                    .await?
                };
                Ok::<_, fleet_client::ClientError>((
                    loaded_environments,
                    loaded_connections,
                    environment_id,
                ))
            }
            .await;
            match result {
                Ok((loaded_environments, loaded_connections, environment_id)) => {
                    environments.set(loaded_environments);
                    connections.set(loaded_connections);
                    selected_environment.set(environment_id);
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
            loading.set(false);
        });
    };

    let select_environment = move |environment_id: String| {
        selected_environment.set(environment_id.clone());
        if preview {
            return;
        }
        connections.set(Vec::new());
        let organization_id = selected_organization();
        let project_id = selected_project();
        spawn(async move {
            loading.set(true);
            match fleet_client::connections(
                &organization_id,
                Some(&project_id),
                Some(&environment_id),
            )
            .await
            {
                Ok(loaded_connections) => {
                    connections.set(loaded_connections);
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
            loading.set(false);
        });
    };

    rsx! {
        if !error().is_empty() {
            div { class: "fleet-alert", role: "alert",
                Icon { icon: TablerIcon::AlertTriangle, size: 17 }
                span { "{error}" }
                button { r#type: "button", onclick: move |_| error.set(String::new()), Icon { icon: TablerIcon::X, size: 15 } }
            }
        }
        if loading() {
            div { class: "fleet-loading", span {} "Synchronizing Fleet control plane…" }
        }
        match active {
            NavKey::FleetOverview => rsx! {
                FleetOverviewPage { overview: overview(), connections: connections(), on_navigate }
            },
            NavKey::Organizations => rsx! {
                FleetOrganizationsPage {
                    organizations: organizations(),
                    selected_id: selected_organization(),
                    on_select: select_organization,
                    on_create: move |_| dialog.set(Some(FleetDialogKind::Organization)),
                }
            },
            NavKey::Projects => rsx! {
                FleetProjectsPage {
                    organizations: organizations(),
                    projects: projects(),
                    selected_organization: selected_organization(),
                    selected_id: selected_project(),
                    on_select: select_project,
                    on_create: move |_| dialog.set(Some(FleetDialogKind::Project)),
                }
            },
            NavKey::Environments => rsx! {
                FleetEnvironmentsPage {
                    projects: projects(),
                    environments: environments(),
                    selected_project: selected_project(),
                    selected_id: selected_environment(),
                    on_select: select_environment,
                    on_create: move |_| dialog.set(Some(FleetDialogKind::Environment)),
                }
            },
            NavKey::Connections => rsx! {
                FleetConnectionsPage {
                    environments: environments(),
                    connections: connections(),
                    selected_environment: selected_environment(),
                    on_create: move |_| dialog.set(Some(FleetDialogKind::Connection)),
                }
            },
            NavKey::Audit => rsx! { FleetAuditPage { events: audit_events() } },
            _ => rsx! {},
        }
        if let Some(kind) = dialog() {
            FleetCreateDialog {
                kind,
                can_create: match kind {
                    FleetDialogKind::Organization => true,
                    FleetDialogKind::Project => !selected_organization().is_empty(),
                    FleetDialogKind::Environment => !selected_project().is_empty(),
                    FleetDialogKind::Connection => !selected_environment().is_empty(),
                },
                preview,
                on_close: move |_| dialog.set(None),
                on_submit: mutate,
            }
        }
    }
}

#[component]
fn FleetOverviewPage(
    overview: FleetOverview,
    connections: Vec<RealmConnection>,
    on_navigate: EventHandler<NavKey>,
) -> Element {
    rsx! {
        div { class: "content-stack",
            section { class: "page-heading",
                div {
                    p { class: "eyebrow", "Fleet intelligence" }
                    h2 { "Every identity boundary. One control plane." }
                    p { "Central metadata and health, without centralizing customer identity data." }
                }
                button { class: "button secondary", r#type: "button", onclick: move |_| on_navigate.call(NavKey::Connections),
                    "Connect a realm " Icon { icon: TablerIcon::ArrowUpRight, size: 17 }
                }
            }
            section { class: "metric-grid compact",
                MetricCard { label: "Organizations", value: overview.organizations.to_string(), change: "Isolated tenants", tone: "good" }
                MetricCard { label: "Projects", value: overview.projects.to_string(), change: "Product boundaries", tone: "good" }
                MetricCard { label: "Environments", value: overview.environments.to_string(), change: "Independently deployed", tone: "good" }
                MetricCard { label: "Healthy realms", value: overview.healthy_connections.to_string(), change: format!("{} need attention", overview.degraded_connections + overview.offline_connections), tone: if overview.degraded_connections + overview.offline_connections == 0 { "good" } else { "warn" } }
            }
            div { class: "overview-grid",
                section { class: "panel fleet-map-panel",
                    PanelHeader { eyebrow: "Topology", title: "Organizations → projects → environments" }
                    div { class: "fleet-topology",
                        div { strong { "Fleet control plane" } span { "Metadata, RBAC and audit" } }
                        i {}
                        div { strong { "Realm management APIs" } span { "Binary Protobuf over TLS" } }
                        i {}
                        div { strong { "Private SableDBs" } span { "Customer identity remains isolated" } }
                    }
                }
                section { class: "panel posture-panel",
                    PanelHeader { eyebrow: "Realm posture", title: "Connection health" }
                    if connections.is_empty() {
                        div { class: "fleet-empty compact", Icon { icon: TablerIcon::Webhook, size: 24 } strong { "No realms connected" } span { "Pair the first environment to start Fleet health monitoring." } }
                    } else {
                        for connection in connections.iter().take(4) {
                            FleetPostureRow {
                                label: connection.display_name.clone(),
                                value: connection.management_endpoint.clone(),
                                good: connection.state == ConnectionState::Healthy,
                            }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn FleetOrganizationsPage(
    organizations: Vec<FleetOrganization>,
    selected_id: String,
    on_select: EventHandler<String>,
    on_create: EventHandler<()>,
) -> Element {
    rsx! {
        FleetPageHeading { eyebrow: "Tenant boundaries", title: "Organizations", detail: "Keep brands, customers and operator grants isolated.", action: "New organization", on_action: on_create }
        section { class: "panel fleet-list-panel",
            PanelHeader { eyebrow: "Fleet registry", title: format!("{} organizations", organizations.len()) }
            if organizations.is_empty() { FleetEmpty { title: "No organizations", detail: "Create the first tenant boundary to continue." } }
            for record in organizations {
                button { r#type: "button", class: if record.id == selected_id { "fleet-row selected" } else { "fleet-row" }, onclick: move |_| on_select.call(record.id.clone()),
                    span { class: "fleet-row-mark", "{initials(&record.name)}" }
                    span { strong { "{record.name}" } small { "{record.slug}" } }
                    span { class: "status-badge good", "Active" }
                    span { class: "mono-value", "{short_id(&record.id)}" }
                    Icon { icon: TablerIcon::ChevronRight, size: 17 }
                }
            }
        }
    }
}

#[component]
fn FleetProjectsPage(
    organizations: Vec<FleetOrganization>,
    projects: Vec<FleetProject>,
    selected_organization: String,
    selected_id: String,
    on_select: EventHandler<String>,
    on_create: EventHandler<()>,
) -> Element {
    let visible = projects
        .into_iter()
        .filter(|record| record.organization_id == selected_organization)
        .collect::<Vec<_>>();
    let organization_name = organizations
        .iter()
        .find(|record| record.id == selected_organization)
        .map(|record| record.name.as_str())
        .unwrap_or("Select an organization");
    rsx! {
        FleetPageHeading { eyebrow: "Product boundaries", title: "Projects", detail: "Apps and products under the selected organization.", action: "New project", on_action: on_create }
        p { class: "fleet-scope-label", "Organization / " strong { "{organization_name}" } }
        section { class: "panel fleet-list-panel",
            PanelHeader { eyebrow: "Projects", title: format!("{} registered projects", visible.len()) }
            if visible.is_empty() { FleetEmpty { title: "No projects", detail: "Create a project inside the selected organization." } }
            for record in visible {
                button { r#type: "button", class: if record.id == selected_id { "fleet-row selected" } else { "fleet-row" }, onclick: move |_| on_select.call(record.id.clone()),
                    span { class: "fleet-row-mark", "{initials(&record.name)}" }
                    span { strong { "{record.name}" } small { "{record.description}" } }
                    span { class: "status-badge good", "Active" }
                    span { class: "mono-value", "{record.slug}" }
                    Icon { icon: TablerIcon::ChevronRight, size: 17 }
                }
            }
        }
    }
}

#[component]
fn FleetEnvironmentsPage(
    projects: Vec<FleetProject>,
    environments: Vec<FleetEnvironment>,
    selected_project: String,
    selected_id: String,
    on_select: EventHandler<String>,
    on_create: EventHandler<()>,
) -> Element {
    let visible = environments
        .into_iter()
        .filter(|record| record.project_id == selected_project)
        .collect::<Vec<_>>();
    let project_name = projects
        .iter()
        .find(|record| record.id == selected_project)
        .map(|record| record.name.as_str())
        .unwrap_or("Select a project");
    rsx! {
        FleetPageHeading { eyebrow: "Deployment boundaries", title: "Environments", detail: "Scale and recover each realm independently.", action: "New environment", on_action: on_create }
        p { class: "fleet-scope-label", "Project / " strong { "{project_name}" } }
        section { class: "panel fleet-list-panel",
            PanelHeader { eyebrow: "Environments", title: format!("{} deployment targets", visible.len()) }
            if visible.is_empty() { FleetEmpty { title: "No environments", detail: "Create development, staging or production." } }
            for record in visible {
                button { r#type: "button", class: if record.id == selected_id { "fleet-row selected" } else { "fleet-row" }, onclick: move |_| on_select.call(record.id.clone()),
                    span { class: "fleet-row-mark", "{initials(&record.name)}" }
                    span { strong { "{record.name}" } small { "{record.provider} · {record.region}" } }
                    span { class: "status-badge good", "Active" }
                    span { class: "mono-value", "{environment_label(record.kind)}" }
                    Icon { icon: TablerIcon::ChevronRight, size: 17 }
                }
            }
        }
    }
}

#[component]
fn FleetConnectionsPage(
    environments: Vec<FleetEnvironment>,
    connections: Vec<RealmConnection>,
    selected_environment: String,
    on_create: EventHandler<()>,
) -> Element {
    let visible = connections
        .into_iter()
        .filter(|record| record.environment_id == selected_environment)
        .collect::<Vec<_>>();
    let environment_name = environments
        .iter()
        .find(|record| record.id == selected_environment)
        .map(|record| record.name.as_str())
        .unwrap_or("Select an environment");
    rsx! {
        FleetPageHeading { eyebrow: "Trust boundaries", title: "Realm connections", detail: "The dashboard never connects directly to a realm database.", action: "Pair realm", on_action: on_create }
        p { class: "fleet-scope-label", "Environment / " strong { "{environment_name}" } }
        section { class: "panel fleet-list-panel",
            PanelHeader { eyebrow: "Connections", title: format!("{} managed realms", visible.len()) }
            if visible.is_empty() { FleetEmpty { title: "No realm connected", detail: "Generate a pairing code in the realm, then pair its management endpoint." } }
            for record in visible {
                div { class: "fleet-row",
                    span { class: "fleet-row-mark", Icon { icon: TablerIcon::ShieldCheck, size: 18 } }
                    span { strong { "{record.display_name}" } small { "{record.management_endpoint}" } }
                    span { class: if record.state == ConnectionState::Healthy { "status-badge good" } else { "status-badge warn" }, "{connection_label(record.state)}" }
                    span { class: "mono-value", "v{record.deployment_version}" }
                    span { "{format_time(&record.last_seen_at)}" }
                }
            }
        }
    }
}

#[component]
fn FleetAuditPage(events: Vec<AuditEvent>) -> Element {
    rsx! {
        FleetPageHeading { eyebrow: "Control-plane audit", title: "Audit log", detail: "Every Fleet mutation retains its operator, reason and resource scope." }
        section { class: "panel fleet-list-panel",
            PanelHeader { eyebrow: "Events", title: format!("{} retained events", events.len()) }
            if events.is_empty() { FleetEmpty { title: "No mutation events", detail: "Fleet actions will appear here with their request IDs." } }
            for event in events.into_iter().rev() {
                div { class: "fleet-row audit",
                    span { class: "fleet-row-mark", Icon { icon: TablerIcon::ShieldCheck, size: 18 } }
                    span { strong { "{event.action}" } small { "{event.reason}" } }
                    span { class: "status-badge good", "Succeeded" }
                    span { class: "mono-value", "{short_id(&event.operator_id)}" }
                    span { "{format_time(&event.occurred_at)}" }
                }
            }
        }
    }
}

#[component]
fn FleetPageHeading(
    eyebrow: &'static str,
    title: &'static str,
    detail: &'static str,
    #[props(default)] action: Option<&'static str>,
    #[props(default)] on_action: Option<EventHandler<()>>,
) -> Element {
    rsx! {
        section { class: "page-heading",
            div { p { class: "eyebrow", "{eyebrow}" } h2 { "{title}" } p { "{detail}" } }
            if let Some(label) = action {
                button { class: "button secondary", r#type: "button", onclick: move |_| if let Some(handler) = on_action { handler.call(()) },
                    Icon { icon: TablerIcon::Plus, size: 17 } "{label}"
                }
            }
        }
    }
}

#[component]
fn FleetEmpty(title: &'static str, detail: &'static str) -> Element {
    rsx! { div { class: "fleet-empty", Icon { icon: TablerIcon::Database, size: 28 } strong { "{title}" } span { "{detail}" } } }
}

#[component]
fn FleetPostureRow(label: String, value: String, good: bool) -> Element {
    let state_class = if good {
        "state-icon good"
    } else {
        "state-icon"
    };
    rsx! {
        div { class: "posture-row",
            span { class: state_class,
                if good { Icon { icon: TablerIcon::Check, size: 15 } }
                else { Icon { icon: TablerIcon::Refresh, size: 15 } }
            }
            strong { "{label}" }
            small { "{value}" }
        }
    }
}

#[component]
fn FleetCreateDialog(
    kind: FleetDialogKind,
    can_create: bool,
    preview: bool,
    on_close: EventHandler<()>,
    on_submit: EventHandler<FleetMutation>,
) -> Element {
    let mut name = use_signal(String::new);
    let mut slug = use_signal(String::new);
    let mut endpoint = use_signal(|| "http://127.0.0.1:8080".to_string());
    let mut pairing_code = use_signal(String::new);
    let (title, detail) = match kind {
        FleetDialogKind::Organization => {
            ("New organization", "Create an isolated tenant boundary.")
        }
        FleetDialogKind::Project => ("New project", "Create an app or product boundary."),
        FleetDialogKind::Environment => (
            "New environment",
            "Create an independently deployed realm target.",
        ),
        FleetDialogKind::Connection => (
            "Pair a realm",
            "Exchange a single-use code directly between servers.",
        ),
    };
    rsx! {
        div { class: "modal-backdrop", onclick: move |_| on_close.call(()),
            section { class: "modal fleet-dialog", onclick: move |event| event.stop_propagation(),
                header { div { p { class: "eyebrow", "Fleet setup" } h3 { "{title}" } } button { class: "icon-button", r#type: "button", onclick: move |_| on_close.call(()), Icon { icon: TablerIcon::X, size: 18 } } }
                p { class: "fleet-dialog-detail", "{detail}" }
                if !can_create {
                    p { class: "form-error", "Select the parent resource before continuing." }
                }
                form { onsubmit: move |event| {
                    event.prevent_default();
                    if !can_create { return; }
                    let mutation = match kind {
                        FleetDialogKind::Organization => FleetMutation::Organization { slug: slug(), name: name() },
                        FleetDialogKind::Project => FleetMutation::Project { slug: slug(), name: name() },
                        FleetDialogKind::Environment => FleetMutation::Environment { slug: slug(), name: name() },
                        FleetDialogKind::Connection => FleetMutation::Connection { endpoint: endpoint(), pairing_code: pairing_code() },
                    };
                    on_submit.call(mutation);
                },
                    if kind == FleetDialogKind::Connection {
                        label { "Management endpoint" input { r#type: "url", required: true, value: endpoint(), oninput: move |event| endpoint.set(event.value()) } }
                        label { "Single-use pairing code" input { r#type: "password", required: !preview, placeholder: if preview { "Optional in preview" } else { "rpair_…" }, value: pairing_code(), oninput: move |event| pairing_code.set(event.value()) } }
                        p { class: "form-hint", "The code is sent to the control plane once and is never stored by this dashboard." }
                    } else {
                        label { "Name" input { required: true, maxlength: 120, value: name(), oninput: move |event| name.set(event.value()) } }
                        label { "Slug" input { required: true, maxlength: 63, pattern: "[a-z0-9]+(?:-[a-z0-9]+)*", value: slug(), oninput: move |event| slug.set(event.value().to_lowercase().replace(' ', "-")) } }
                    }
                    div { class: "form-actions", button { class: "button secondary", r#type: "button", onclick: move |_| on_close.call(()), "Cancel" } button { class: "button primary", r#type: "submit", disabled: !can_create, if kind == FleetDialogKind::Connection { "Pair realm" } else { "Create" } } }
                }
            }
        }
    }
}

fn short_id(value: &str) -> String {
    value.chars().take(8).collect()
}

fn environment_label(value: buffa::EnumValue<EnvironmentKind>) -> &'static str {
    match value.as_known().unwrap_or(EnvironmentKind::Unspecified) {
        EnvironmentKind::Development => "Development",
        EnvironmentKind::Preview => "Preview",
        EnvironmentKind::Staging => "Staging",
        EnvironmentKind::Production => "Production",
        EnvironmentKind::Unspecified => "Unspecified",
    }
}

fn connection_label(value: buffa::EnumValue<ConnectionState>) -> &'static str {
    match value.as_known().unwrap_or(ConnectionState::Unspecified) {
        ConnectionState::Healthy => "Healthy",
        ConnectionState::Degraded => "Degraded",
        ConnectionState::Offline => "Offline",
        ConnectionState::Pending => "Pending",
        ConnectionState::Verifying => "Verifying",
        ConnectionState::Revoked => "Revoked",
        ConnectionState::Unspecified => "Unknown",
    }
}

fn format_time(value: &str) -> String {
    if value.is_empty() {
        "Never".into()
    } else {
        value.replace('T', " ").trim_end_matches('Z').to_owned()
    }
}

#[component]
fn OverviewPage(
    organization: OrganizationView,
    accounts: Vec<ServiceAccountView>,
    on_navigate: EventHandler<NavKey>,
) -> Element {
    let mut selected_user = use_signal(|| None::<UserView>);
    let active_accounts = accounts
        .iter()
        .filter(|account| account.status == "Active")
        .count();

    rsx! {
        div { class: "content-stack",
            section { class: "page-heading",
                div {
                    p { class: "eyebrow", "Instance intelligence" }
                    h2 { "{organization.name}" }
                    p { "Authentication health and operational posture across the last 24 hours." }
                }
                button { r#type: "button", class: "button secondary", onclick: move |_| on_navigate.call(NavKey::Metrics),
                    "Explore metrics "
                    Icon { icon: TablerIcon::ArrowUpRight, size: 17 }
                }
            }
            section { class: "metric-grid compact",
                MetricCard { label: "Authentication success", value: "98.72%", change: "+0.34%", tone: "good" }
                MetricCard { label: "Active users", value: "8,402", change: "+6.8%", tone: "good" }
                MetricCard { label: "Passkey latency p95", value: "284 ms", change: "−18 ms", tone: "good" }
                MetricCard { label: "Failed challenges", value: "193", change: "+12", tone: "warn" }
            }
            div { class: "overview-grid",
                section { class: "panel volume-panel",
                    PanelHeader { eyebrow: "Authentication volume", title: "24-hour activity", action: "Metrics", on_action: move |_| on_navigate.call(NavKey::Metrics) }
                    div { class: "bar-chart", aria_label: "Hourly authentication volume",
                        for (index, value) in AUTH_VOLUME.iter().enumerate() {
                            {
                                let height = (f32::from(*value) / 1.6).round() as u16;
                                let delay = 70 + index * 18;
                                rsx! {
                                    span {
                                        style: "height: {height}%; animation-delay: {delay}ms",
                                        title: "{index}:00 · {value} authentications",
                                    }
                                }
                            }
                        }
                    }
                    div { class: "chart-axis",
                        span { "00:00" } span { "06:00" } span { "12:00" } span { "18:00" } span { "Now" }
                    }
                }
                section { class: "panel posture-panel",
                    PanelHeader { eyebrow: "Security posture", title: "Healthy configuration" }
                    PostureRow { label: "Signing keys", value: "Active + staged", good: true }
                    PostureRow { label: "Encrypted backup", value: "43 minutes ago", good: true }
                    PostureRow { label: "Service credentials", value: "{active_accounts} active", good: true }
                    PostureRow { label: "Webhook backlog", value: "2 retrying", good: false }
                }
            }
            section { class: "panel",
                PanelHeader { eyebrow: "Recent accounts", title: "Latest identity activity", action: "View users", on_action: move |_| on_navigate.call(NavKey::Users) }
                UserTable { users: preview_users(), on_select: move |user| selected_user.set(Some(user)) }
            }
        }
        if let Some(user) = selected_user() {
            UserDrawer { user, on_close: move |_| selected_user.set(None), on_open_directory: move |_| {
                selected_user.set(None);
                on_navigate.call(NavKey::Users);
            } }
        }
    }
}

#[component]
fn MetricCard(label: String, value: String, change: String, tone: String) -> Element {
    let change_class = if tone == "good" {
        "positive"
    } else {
        "warning"
    };
    rsx! {
        article { class: "metric-card",
            p { "{label}" }
            strong { "{value}" }
            span { class: change_class, "{change}" }
            small { "vs previous period" }
        }
    }
}

#[component]
fn PanelHeader(
    eyebrow: &'static str,
    title: String,
    #[props(default)] action: Option<&'static str>,
    #[props(default)] on_action: Option<EventHandler<()>>,
) -> Element {
    rsx! {
        header { class: "panel-header",
            div {
                p { class: "eyebrow", "{eyebrow}" }
                h3 { "{title}" }
            }
            if let Some(action_label) = action {
                button { r#type: "button", class: "text-button", onclick: move |_| {
                    if let Some(handler) = on_action { handler.call(()); }
                },
                    "{action_label}"
                    Icon { icon: TablerIcon::ChevronRight, size: 15 }
                }
            }
        }
    }
}

#[component]
fn PostureRow(label: &'static str, value: String, #[props(default)] good: bool) -> Element {
    let state_class = if good {
        "state-icon good"
    } else {
        "state-icon"
    };
    rsx! {
        div { class: "posture-row",
            span { class: state_class,
                if good { Icon { icon: TablerIcon::Check, size: 15 } }
                else { Icon { icon: TablerIcon::Refresh, size: 15 } }
            }
            strong { "{label}" }
            small { "{value}" }
        }
    }
}

#[component]
fn UsersPage() -> Element {
    let mut term = use_signal(String::new);
    let mut status_filter = use_signal(|| "all".to_string());
    let mut sort_by = use_signal(|| "activity".to_string());
    let mut selected = use_signal(|| None::<UserView>);

    let query = term().trim().to_lowercase();
    let mut users = preview_users()
        .into_iter()
        .filter(|user| {
            let matches_query = query.is_empty()
                || format!("{} {} {}", user.name, user.primary_identifier, user.id)
                    .to_lowercase()
                    .contains(&query);
            let matches_status = status_filter() == "all"
                || (status_filter() == "active" && user.status == "Active")
                || (status_filter() == "verification" && user.status == "Needs verification");
            matches_query && matches_status
        })
        .collect::<Vec<_>>();
    if sort_by() == "name" {
        users.sort_by_key(|user| user.name);
    }
    let identifiers = users.iter().map(|user| user.identifiers).sum::<usize>();
    let passkeys = users.iter().map(|user| user.passkeys).sum::<usize>();
    let count = users.len();
    let account_label = if count == 1 { "account" } else { "accounts" };
    let identifier_label = if identifiers == 1 {
        "identifier"
    } else {
        "identifiers"
    };
    let passkey_label = if passkeys == 1 { "passkey" } else { "passkeys" };

    rsx! {
        div { class: "content-stack",
            section { class: "page-heading",
                div {
                    p { class: "eyebrow", "Identity directory" }
                    h2 { "Find an account" }
                    p { "Search exact identifiers, UUIDs, passkeys and profile fields without exposing credential material." }
                }
            }
            form { class: "search-panel", onsubmit: move |event| event.prevent_default(),
                Icon { icon: TablerIcon::Search, size: 20 }
                input {
                    value: term(),
                    oninput: move |event| term.set(event.value()),
                    placeholder: "Email, phone, display name or user UUID",
                    aria_label: "Search users",
                }
                button { class: "button primary", r#type: "submit", "Search" }
            }
            section { class: "panel table-panel",
                header { class: "directory-toolbar",
                    div { class: "directory-summary",
                        strong { "{count} {account_label}" }
                        span { "{identifiers} {identifier_label} · {passkeys} {passkey_label}" }
                    }
                    div { class: "directory-controls",
                        label {
                            span { "Status" }
                            select {
                                aria_label: "Filter users by status",
                                value: status_filter(),
                                onchange: move |event| status_filter.set(event.value()),
                                option { value: "all", "All statuses" }
                                option { value: "active", "Active" }
                                option { value: "verification", "Needs verification" }
                            }
                        }
                        label {
                            span { "Order" }
                            select {
                                aria_label: "Sort users",
                                value: sort_by(),
                                onchange: move |event| sort_by.set(event.value()),
                                option { value: "activity", "Last active" }
                                option { value: "name", "Name" }
                            }
                        }
                        span { class: "directory-updated", "Indexed just now" }
                    }
                }
                if users.is_empty() {
                    EmptyState { icon: TablerIcon::Users, title: "No matching accounts", detail: "Try a different search term." }
                } else {
                    UserTable { users, on_select: move |user| selected.set(Some(user)) }
                }
            }
        }
        if let Some(user) = selected() {
            UserDrawer { user, on_close: move |_| selected.set(None) }
        }
    }
}

#[component]
fn UserTable(users: Vec<UserView>, on_select: EventHandler<UserView>) -> Element {
    rsx! {
        div { class: "data-table user-table",
            div { class: "table-head",
                span { "User" }
                span { "Status" }
                span { "Passkeys" }
                span { "Last active" }
                span {}
            }
            for (index, user) in users.into_iter().enumerate() {
                {
                    let selected_user = user.clone();
                    let delay = index * 28;
                    rsx! {
                        button {
                            r#type: "button",
                            class: "table-row",
                            aria_label: "Open {user.name} account",
                            style: "animation-delay: {delay}ms",
                            onclick: move |_| on_select.call(selected_user.clone()),
                            span { class: "user-cell",
                                i { "{initials(user.name)}" }
                                span {
                                    strong { "{user.name}" }
                                    small { "{user.primary_identifier}" }
                                }
                            }
                            span { StatusBadge { status: user.status } }
                            span { class: "mono-value", "{user.passkeys}" }
                            span { "{user.last_active}" }
                            Icon { icon: TablerIcon::ChevronRight, size: 17 }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn UserDrawer(
    user: UserView,
    on_close: EventHandler<()>,
    #[props(default)] on_open_directory: Option<EventHandler<()>>,
) -> Element {
    rsx! {
        div { class: "drawer-backdrop", onclick: move |_| on_close.call(()),
            aside {
                class: "drawer wide-drawer user-drawer",
                role: "dialog",
                aria_modal: "true",
                aria_label: "User account details",
                onclick: move |event| event.stop_propagation(),
                header {
                    div {
                        p { class: "eyebrow", "Identity record" }
                        h3 { "{user.name}" }
                    }
                    button { r#type: "button", class: "icon-button", aria_label: "Close user inspector", onclick: move |_| on_close.call(()),
                        Icon { icon: TablerIcon::X, size: 20 }
                    }
                }
                div { class: "profile-hero user-profile-hero",
                    span { "{initials(user.name)}" }
                    div {
                        strong { "{user.name}" }
                        small { "{user.primary_identifier}" }
                    }
                    StatusBadge { status: user.status }
                }
                div { class: "user-signal-strip",
                    article { span { "Last active" } strong { "{user.last_active}" } }
                    article { span { "Identifiers" } strong { "{user.identifiers}" } }
                    article { span { "Passkeys" } strong { "{user.passkeys}" } }
                }
                Definition { label: "User UUID", value: user.id, mono: true }
                Definition { label: "Created", value: format_date(user.created_at) }
                div { class: "drawer-section",
                    p { class: "eyebrow", "Credential boundary" }
                    div { class: "policy-note",
                        Icon { icon: TablerIcon::ShieldCheck, size: 19 }
                        span { "Public keys, counters and assertions remain private. This inspector exposes account metadata only." }
                    }
                }
                div { class: "drawer-actions user-drawer-actions",
                    button { r#type: "button", class: "button secondary", onclick: move |_| on_close.call(()), "Done" }
                    if let Some(open_directory) = on_open_directory {
                        button { r#type: "button", class: "button primary", onclick: move |_| open_directory.call(()),
                            "Open user directory "
                            Icon { icon: TablerIcon::ArrowUpRight, size: 16 }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn OrganizationPage(organization: OrganizationView, on_update: EventHandler<String>) -> Element {
    let mut name = use_signal(|| organization.name.clone());
    let mut saved = use_signal(|| false);

    rsx! {
        div { class: "content-stack narrow-stack",
            section { class: "page-heading",
                div {
                    p { class: "eyebrow", "Instance ownership" }
                    h2 { "Organization settings" }
                    p { "The single administrative organization for this RustyAuth deployment." }
                }
            }
            section { class: "panel form-panel",
                PanelHeader { eyebrow: "Organization", title: "General details" }
                form { onsubmit: move |event| {
                    event.prevent_default();
                    on_update.call(name().trim().to_string());
                    saved.set(true);
                },
                    label { "Display name"
                        input { value: name(), maxlength: 120, oninput: move |event| {
                            saved.set(false);
                            name.set(event.value());
                        } }
                    }
                    label { "Instance slug" input { value: organization.slug, disabled: true } }
                    label { "Organization ID"
                        div { class: "copy-field",
                            code { "{organization.id}" }
                            Icon { icon: TablerIcon::Copy, size: 16 }
                        }
                    }
                    div { class: "form-actions",
                        if saved() {
                            span { class: "saved-state", Icon { icon: TablerIcon::Check, size: 16 } " Saved" }
                        }
                        button { r#type: "submit", class: "button primary", "Save changes" }
                    }
                }
            }
            section { class: "panel",
                PanelHeader { eyebrow: "Operators", title: "Administrative access" }
                div { class: "operator-row",
                    span { "LO" }
                    div {
                        strong { "Local owner" }
                        small { "admin@rustyauth.local" }
                    }
                    StatusBadge { status: "Owner" }
                    button { r#type: "button", class: "icon-button", Icon { icon: TablerIcon::Dots, size: 19 } }
                }
                div { class: "section-note",
                    Icon { icon: TablerIcon::ShieldCheck, size: 18 }
                    p { "Operator access always requires a passkey-authenticated RustyAuth session. Agent handoffs and service credentials are rejected." }
                }
            }
        }
    }
}

#[component]
fn ServiceAccountsPage(accounts: Vec<ServiceAccountView>) -> Element {
    let mut selected = use_signal(|| None::<ServiceAccountView>);
    let mut create_open = use_signal(|| false);
    let active_count = accounts
        .iter()
        .filter(|account| account.status == "Active")
        .count();
    let disabled_count = accounts.len() - active_count;
    let credential_count = accounts
        .iter()
        .flat_map(|account| account.credentials.iter())
        .filter(|credential| credential.revoked_at.is_empty())
        .count();
    let account_count = accounts.len();

    rsx! {
        div { class: "content-stack",
            section { class: "page-heading",
                div {
                    p { class: "eyebrow", "Machine identity" }
                    h2 { "Service accounts" }
                    p { "Issue narrowly scoped, independently rotatable credentials for gRPC and Connect clients." }
                }
                button { r#type: "button", class: "button primary", onclick: move |_| create_open.set(true),
                    Icon { icon: TablerIcon::Plus, size: 17 }
                    "New service account"
                }
            }
            section { class: "metric-grid service-summary",
                MetricCard { label: "Active accounts", value: "{active_count}", change: "{disabled_count} disabled", tone: "good" }
                MetricCard { label: "Live credentials", value: "{credential_count}", change: "Rotatable", tone: "good" }
                MetricCard { label: "RPC calls · 24h", value: "18,402", change: "+12.4%", tone: "good" }
            }
            section { class: "panel table-panel",
                PanelHeader { eyebrow: "Principals", title: "{account_count} service accounts" }
                div { class: "data-table service-table",
                    div { class: "table-head",
                        span { "Service account" }
                        span { "Status" }
                        span { "Scopes" }
                        span { "Last used" }
                        span {}
                    }
                    for account in accounts {
                        {
                            let selected_account = account.clone();
                            rsx! {
                                button { r#type: "button", class: "table-row", onclick: move |_| selected.set(Some(selected_account.clone())),
                                    span { class: "service-cell",
                                        i { Icon { icon: TablerIcon::Key, size: 18 } }
                                        span {
                                            strong { "{account.name}" }
                                            small { "{account.description}" }
                                        }
                                    }
                                    span { StatusBadge { status: account.status } }
                                    span { class: "scope-count", "{account.scopes.len()} scopes" }
                                    span { "{account.last_used_at}" }
                                    Icon { icon: TablerIcon::ChevronRight, size: 17 }
                                }
                            }
                        }
                    }
                }
            }
        }
        if create_open() {
            CreateServiceAccountModal { on_close: move |_| create_open.set(false) }
        }
        if let Some(account) = selected() {
            ServiceAccountDrawer { account, on_close: move |_| selected.set(None) }
        }
    }
}

#[component]
fn CreateServiceAccountModal(on_close: EventHandler<()>) -> Element {
    let mut name = use_signal(String::new);
    let mut description = use_signal(String::new);
    let mut credential_name = use_signal(|| "Primary credential".to_string());
    let mut scopes = use_signal(|| vec!["identity.read", "events.read"]);
    let service_scopes = [
        "identity.read",
        "identity.write",
        "events.read",
        "metrics.read",
        "webhooks.manage",
    ];

    rsx! {
        div { class: "modal-backdrop", onclick: move |_| on_close.call(()),
            section { class: "modal", role: "dialog", aria_modal: "true", aria_label: "Create service account", onclick: move |event| event.stop_propagation(),
                header {
                    div {
                        p { class: "eyebrow", "Machine identity" }
                        h3 { "New service account" }
                    }
                    button { r#type: "button", class: "icon-button", aria_label: "Close create service account", onclick: move |_| on_close.call(()),
                        Icon { icon: TablerIcon::X, size: 20 }
                    }
                }
                form { onsubmit: move |event| { event.prevent_default(); on_close.call(()); },
                    label { "Name"
                        input { value: name(), oninput: move |event| name.set(event.value()), placeholder: "production-api", required: true }
                    }
                    label { "Description"
                        textarea { value: description(), oninput: move |event| description.set(event.value()), placeholder: "What this machine identity is allowed to do" }
                    }
                    fieldset {
                        legend { "Scopes" }
                        div { class: "scope-options",
                            for scope in service_scopes {
                                label {
                                    input {
                                        r#type: "checkbox",
                                        checked: scopes().contains(&scope),
                                        onchange: move |_| {
                                            let mut next = scopes();
                                            if next.contains(&scope) { next.retain(|value| *value != scope); }
                                            else { next.push(scope); }
                                            scopes.set(next);
                                        },
                                    }
                                    code { "{scope}" }
                                }
                            }
                        }
                    }
                    label { "First credential name"
                        input { value: credential_name(), oninput: move |event| credential_name.set(event.value()) }
                    }
                    div { class: "modal-note",
                        Icon { icon: TablerIcon::ShieldCheck, size: 18 }
                        span { "The credential secret is shown once after creation and cannot be recovered." }
                    }
                    footer {
                        button { r#type: "button", class: "button secondary", onclick: move |_| on_close.call(()), "Cancel" }
                        button { r#type: "submit", class: "button primary", disabled: name().trim().is_empty() || scopes().is_empty(), "Create account" }
                    }
                }
            }
        }
    }
}

#[component]
fn ServiceAccountDrawer(account: ServiceAccountView, on_close: EventHandler<()>) -> Element {
    rsx! {
        div { class: "drawer-backdrop", onclick: move |_| on_close.call(()),
            aside { class: "drawer wide-drawer service-account-drawer", role: "dialog", aria_modal: "true", aria_label: "Service account details", onclick: move |event| event.stop_propagation(),
                header {
                    div {
                        p { class: "eyebrow", "Service account" }
                        h3 { "{account.name}" }
                    }
                    button { r#type: "button", class: "icon-button", aria_label: "Close service account details", onclick: move |_| on_close.call(()),
                        Icon { icon: TablerIcon::X, size: 20 }
                    }
                }
                div { class: "profile-hero service-hero",
                    span { Icon { icon: TablerIcon::Key, size: 25 } }
                    div {
                        StatusBadge { status: account.status }
                        small { "{account.description}" }
                    }
                }
                div { class: "drawer-section",
                    p { class: "eyebrow", "Granted scopes" }
                    div { class: "scope-list",
                        for scope in &account.scopes { code { "{scope}" } }
                    }
                }
                div { class: "drawer-section",
                    p { class: "eyebrow", "Credentials" }
                    if account.credentials.is_empty() {
                        p { class: "muted", "No credentials have been issued." }
                    }
                    for credential in &account.credentials {
                        div { class: "credential-row",
                            div {
                                strong { "{credential.name}" }
                                small { "Ends in " code { "{credential.hint}" } " · {credential.last_used_at}" }
                            }
                            if credential.revoked_at.is_empty() {
                                button { r#type: "button", class: "danger-text", "Revoke" }
                            } else {
                                StatusBadge { status: "Revoked" }
                            }
                        }
                    }
                }
                Definition { label: "Service account ID", value: account.id, mono: true }
                Definition { label: "Created", value: format_date(account.created_at) }
            }
        }
    }
}

#[component]
fn WebhooksPage() -> Element {
    let webhooks = use_signal(preview_webhooks);
    let mut selected = use_signal(|| None::<WebhookView>);
    let mut creating = use_signal(|| false);
    let webhook_count = webhooks().len();

    rsx! {
        div { class: "content-stack",
            section { class: "page-heading",
                div {
                    p { class: "eyebrow", "Event delivery" }
                    h2 { "Webhooks" }
                    p { "Signed, observable delivery with bounded retries and replayable failures." }
                }
                button { r#type: "button", class: "button primary", onclick: move |_| {
                    selected.set(None);
                    creating.set(true);
                },
                    Icon { icon: TablerIcon::Plus, size: 17 }
                    "New endpoint"
                }
            }
            div { class: "roadmap-callout",
                Icon { icon: TablerIcon::Webhook, size: 21 }
                div {
                    strong { "Contract-backed preview" }
                    span { "Webhook storage and the durable delivery outbox are the next Rust implementation boundary." }
                }
            }
            section { class: "panel table-panel",
                PanelHeader { eyebrow: "Destinations", title: "{webhook_count} configured endpoints" }
                div { class: "data-table webhook-table",
                    div { class: "table-head",
                        span { "Endpoint" } span { "Status" } span { "Events" } span { "Success rate" } span { "Last delivery" } span { "Manage" }
                    }
                    for webhook in webhooks() {
                        {
                            let selected_webhook = webhook.clone();
                            rsx! {
                                button { r#type: "button", class: "table-row webhook-row", aria_label: "Edit {webhook.name} endpoint", onclick: move |_| {
                                    creating.set(false);
                                    selected.set(Some(selected_webhook.clone()));
                                },
                                    span { class: "service-cell",
                                        i { Icon { icon: TablerIcon::Webhook, size: 18 } }
                                        span { strong { "{webhook.name}" } small { "{webhook.url}" } }
                                    }
                                    span { StatusBadge { status: webhook.status } }
                                    span { "{webhook.events.len()}" }
                                    strong { "{webhook.success_rate}" }
                                    span { "{webhook.last_delivery}" }
                                    span { class: "row-action", "Edit" Icon { icon: TablerIcon::ChevronRight, size: 16 } }
                                }
                            }
                        }
                    }
                }
            }
        }
        if creating() || selected().is_some() {
            WebhookEditorDrawer { webhook: selected(), on_close: move |_| {
                selected.set(None);
                creating.set(false);
            } }
        }
    }
}

#[component]
fn WebhookEditorDrawer(webhook: Option<WebhookView>, on_close: EventHandler<()>) -> Element {
    let is_new = webhook.is_none();
    let mut name = use_signal(|| {
        webhook
            .as_ref()
            .map(|item| item.name)
            .unwrap_or("")
            .to_string()
    });
    let mut url = use_signal(|| {
        webhook
            .as_ref()
            .map(|item| item.url)
            .unwrap_or("")
            .to_string()
    });
    let mut enabled = use_signal(|| webhook.as_ref().is_none_or(|item| item.status != "Paused"));
    let events = webhook
        .as_ref()
        .map(|item| item.events.clone())
        .unwrap_or_else(|| {
            vec![
                "user.created",
                "user.updated",
                "user.disabled",
                "session.created",
            ]
        });
    let title = webhook
        .as_ref()
        .map(|item| format!("Edit {}", item.name))
        .unwrap_or_else(|| "Create endpoint".to_string());

    rsx! {
        div { class: "drawer-backdrop", onclick: move |_| on_close.call(()),
            aside { class: "drawer webhook-editor-drawer", role: "dialog", aria_modal: "true", aria_label: "Webhook editor", onclick: move |event| event.stop_propagation(),
                header {
                    div {
                        p { class: "eyebrow", if is_new { "New destination" } else { "Webhook destination" } }
                        h3 { "{title}" }
                    }
                    button { r#type: "button", class: "icon-button", aria_label: "Close webhook editor", onclick: move |_| on_close.call(()),
                        Icon { icon: TablerIcon::X, size: 20 }
                    }
                }
                form { class: "webhook-editor-form", onsubmit: move |event| { event.prevent_default(); on_close.call(()); },
                    div { class: "webhook-editor-scroll",
                        section { class: "drawer-section webhook-editor-section",
                            p { class: "eyebrow", "Destination" }
                            div { class: "webhook-field-stack",
                                label { "Display name"
                                    input { value: name(), oninput: move |event| name.set(event.value()), placeholder: "Application lifecycle", required: true, maxlength: 100 }
                                }
                                label { "HTTPS endpoint"
                                    input { r#type: "url", value: url(), oninput: move |event| url.set(event.value()), placeholder: "https://api.example.com/hooks/rustyauth", required: true }
                                }
                            }
                        }
                        section { class: "drawer-section webhook-editor-section",
                            fieldset {
                                legend {
                                    span { class: "eyebrow", "Subscribed events" }
                                    strong { "{events.len()} selected" }
                                }
                                div { class: "event-options",
                                    for event_name in events {
                                        label { class: "selected",
                                            input { r#type: "checkbox", checked: true }
                                            span { Icon { icon: TablerIcon::Check, size: 13 } }
                                            code { "{event_name}" }
                                        }
                                    }
                                }
                            }
                        }
                        section { class: "drawer-section webhook-editor-section",
                            p { class: "eyebrow", "Delivery" }
                            label { class: "delivery-state-control", "State"
                                select { value: if enabled() { "active" } else { "paused" }, onchange: move |event| enabled.set(event.value() == "active"),
                                    option { value: "active", "Active — accept deliveries" }
                                    option { value: "paused", "Paused — retain queued events" }
                                }
                            }
                            p { class: "field-hint", "Signing secrets rotate separately so destination edits never expose credential material." }
                        }
                    }
                    footer { class: "webhook-editor-actions",
                        button { r#type: "button", class: "button secondary", onclick: move |_| on_close.call(()), "Cancel" }
                        button { r#type: "submit", class: "button primary", disabled: name().trim().is_empty(),
                            Icon { icon: TablerIcon::Check, size: 16 }
                            if is_new { "Create endpoint" } else { "Save changes" }
                        }
                    }
                }
            }
        }
    }
}

#[component]
fn MetricsPage() -> Element {
    let mut range = use_signal(|| "24 hours");

    rsx! {
        div { class: "content-stack",
            section { class: "page-heading",
                div {
                    p { class: "eyebrow", "Auth telemetry" }
                    h2 { "Authentication metrics" }
                    p { "Bounded-cardinality aggregates with no user, identifier, credential or webhook URL dimensions." }
                }
                div { class: "segmented",
                    for option in ["24 hours", "7 days", "28 days"] {
                        button {
                            r#type: "button",
                            class: if range() == option { "active" } else { "" },
                            onclick: move |_| range.set(option),
                            "{option}"
                        }
                    }
                }
            }
            section { class: "metric-grid metrics-full",
                for metric in PREVIEW_METRICS {
                    article { class: "metric-card",
                        p { "{metric.label}" }
                        strong { "{metric.value}" }
                        span { class: if metric.direction == "up" { "positive" } else { "warning" }, "{metric.change}" }
                        small { "{metric.note}" }
                    }
                }
            }
            div { class: "overview-grid metrics-grid",
                section { class: "panel volume-panel",
                    PanelHeader { eyebrow: "Authentication attempts", title: "Volume and outcome" }
                    div { class: "bar-chart tall", aria_label: "Authentication attempts by hour",
                        for (index, value) in AUTH_VOLUME.iter().enumerate() {
                            {
                                let height = (f32::from(*value) / 1.6).round() as u16;
                                rsx! { span { style: "height: {height}%", title: "{index}:00 · {value}" } }
                            }
                        }
                    }
                    div { class: "chart-legend",
                        span { i { class: "copper" } "Successful" }
                        span { i { class: "graphite" } "Failed" }
                        strong { "98.72% success" }
                    }
                }
                section { class: "panel",
                    PanelHeader { eyebrow: "Passkey funnel", title: "Ceremony completion" }
                    FunnelRow { label: "Options started", value: "12,940", percent: 100 }
                    FunnelRow { label: "Authenticator opened", value: "12,611", percent: 97 }
                    FunnelRow { label: "Assertions returned", value: "12,402", percent: 96 }
                    FunnelRow { label: "Verified", value: "12,238", percent: 95 }
                }
            }
            section { class: "panel failure-panel",
                PanelHeader { eyebrow: "Failure analysis", title: "Top rejection classes" }
                div { class: "failure-grid",
                    FunnelRow { label: "Challenge expired", value: "84", percent: 44 }
                    FunnelRow { label: "Origin mismatch", value: "41", percent: 21 }
                    FunnelRow { label: "Counter regression", value: "9", percent: 5 }
                    FunnelRow { label: "User verification absent", value: "59", percent: 31 }
                }
            }
        }
    }
}

#[component]
fn FunnelRow(label: &'static str, value: &'static str, percent: u16) -> Element {
    rsx! {
        div { class: "funnel-row",
            div { strong { "{label}" } span { "{value}" } }
            meter { min: 0, max: 100, value: percent, "{percent}%" }
            small { "{percent}%" }
        }
    }
}

#[component]
fn EmptyState(icon: TablerIcon, title: &'static str, detail: &'static str) -> Element {
    rsx! {
        div { class: "empty-state",
            Icon { icon, size: 28 }
            strong { "{title}" }
            p { "{detail}" }
        }
    }
}

#[component]
fn StatusBadge(status: &'static str) -> Element {
    let tone = if ["Active", "Healthy", "Owner", "Administrator"].contains(&status) {
        "good"
    } else if ["Retrying", "Needs verification"].contains(&status) {
        "warn"
    } else {
        "neutral"
    };
    rsx! { span { class: "status-badge {tone}", i {} "{status}" } }
}

#[component]
fn Definition(label: &'static str, value: String, #[props(default)] mono: bool) -> Element {
    rsx! {
        div { class: "definition",
            span { "{label}" }
            strong { class: if mono { "mono" } else { "" }, "{value}" }
            if mono {
                button { r#type: "button", class: "icon-button", aria_label: "Copy value",
                    Icon { icon: TablerIcon::Copy, size: 16 }
                }
            }
        }
    }
}

fn initials(value: &str) -> String {
    value
        .split_whitespace()
        .filter_map(|part| part.chars().next())
        .take(2)
        .collect::<String>()
        .to_uppercase()
}

fn format_date(value: &str) -> String {
    match value {
        "2026-08-02T10:18:00Z" => "2 Aug 2026, 10:18".to_string(),
        "2026-07-29T15:06:00Z" => "29 Jul 2026, 15:06".to_string(),
        "2026-07-21T08:31:00Z" => "21 Jul 2026, 08:31".to_string(),
        "2026-07-16T13:47:00Z" => "16 Jul 2026, 13:47".to_string(),
        "2026-07-22T11:14:00Z" => "22 Jul 2026, 11:14".to_string(),
        "2026-07-18T08:22:00Z" => "18 Jul 2026, 08:22".to_string(),
        "2026-06-04T16:40:00Z" => "4 Jun 2026, 16:40".to_string(),
        _ => value.to_string(),
    }
}
