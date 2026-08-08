use base64::Engine as _;
use dioxus::prelude::*;
use dx_icons_tabler::{Icon, TablerIcon};

use crate::fixtures::{
    AUTH_VOLUME, PREVIEW_METRICS, PREVIEW_OPERATOR, preview_organization, preview_service_accounts,
    preview_users, preview_webhooks,
};
use crate::models::{NavKey, OrganizationView, ServiceAccountView, UserView, WebhookView};

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
    Preview,
    SignIn(SignInVariant),
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
    let mut active = use_signal(|| NavKey::Overview);
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
        document::Title { "Control plane · RustyAuth" }
        style { dangerous_inner_html: embedded_styles }
        match view() {
            AppView::SignIn(SignInVariant::Classic) => rsx! {
                SignInScreen {
                    on_preview: move |_| navigate_to(&mut view, AppView::Preview),
                }
            },
            AppView::SignIn(SignInVariant::Aperture) => rsx! {
                ApertureSignInScreen {
                    on_preview: move |_| navigate_to(&mut view, AppView::Preview),
                }
            },
            AppView::Preview => rsx! {
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
                        mobile_open: mobile_nav(),
                        on_navigate: move |key| {
                            active.set(key);
                            mobile_nav.set(false);
                        },
                        on_sign_out: move |_| navigate_to(&mut view, AppView::SignIn(SignInVariant::Classic)),
                    }
                    main { class: "main-stage",
                        Topbar {
                            title: active().label(),
                            on_menu: move |_| mobile_nav.toggle(),
                            on_navigate: move |key| active.set(key),
                            on_sign_out: move |_| navigate_to(&mut view, AppView::SignIn(SignInVariant::Classic)),
                        }
                        div { class: "page-canvas",
                            PreviewBanner {
                                on_connect: move |_| navigate_to(&mut view, AppView::SignIn(SignInVariant::Classic)),
                            }
                            match active() {
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
            return AppView::Preview;
        }
        if search.contains("login=aperture") {
            return AppView::SignIn(SignInVariant::Aperture);
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
            AppView::Preview => "/?preview=1",
            AppView::SignIn(SignInVariant::Classic) => "/",
            AppView::SignIn(SignInVariant::Aperture) => "/?login=aperture",
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
fn SignInScreen(on_preview: EventHandler<()>) -> Element {
    let mut email = use_signal(|| "admin@rustyauth.local".to_string());
    let mut error = use_signal(String::new);
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
                        error.set("Connect this console to RustyAuth to continue with a registered passkey.".to_string());
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
                    button { class: "button primary wide", r#type: "submit",
                        Icon { icon: TablerIcon::ShieldCheck, size: 18 }
                        "Continue with passkey"
                    }
                }
                div { class: "auth-divider", span { "Local evaluation" } }
                button { class: "button secondary wide", r#type: "button", onclick: move |_| on_preview.call(()),
                    "Open populated preview "
                    Icon { icon: TablerIcon::ArrowUpRight, size: 17 }
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
fn ApertureSignInScreen(on_preview: EventHandler<()>) -> Element {
    let mut email = use_signal(|| "admin@rustyauth.local".to_string());
    let mut error = use_signal(String::new);
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
                            error.set("Connect this console to RustyAuth to continue with a registered passkey.".to_string());
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
                        button { class: "aperture-submit", r#type: "submit",
                            Icon { icon: TablerIcon::ShieldCheck, size: 19 }
                            span { "Continue with passkey" }
                        }
                    }
                    div { class: "aperture-divider", span { "Local evaluation" } }
                    button { class: "aperture-preview", r#type: "button", onclick: move |_| on_preview.call(()),
                        span { "Open populated preview" }
                        Icon { icon: TablerIcon::ArrowUpRight, size: 18 }
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
                span { class: "instance-mark", "RL" }
                div {
                    strong { "RustyAuth Local" }
                    small { "Development instance" }
                }
                Icon { icon: TablerIcon::ChevronRight, size: 16 }
            }
            nav { class: "side-nav", aria_label: "Control plane",
                p { "Workspace" }
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
fn PreviewBanner(on_connect: EventHandler<()>) -> Element {
    rsx! {
        div { class: "preview-context", role: "status",
            span { class: "preview-context-label", "Preview" }
            div {
                strong { "Sample data is active" }
                span { "Changes stay in this browser until you connect the live Rust handlers." }
            }
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
fn MetricCard(label: &'static str, value: String, change: String, tone: &'static str) -> Element {
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
