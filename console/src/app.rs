use base64::Engine as _;
use dioxus::prelude::*;
use dx_icons_tabler::{Icon, TablerIcon};

use crate::benchmarks;
use crate::fixtures::{
    AUTH_VOLUME, PREVIEW_METRICS, PREVIEW_OPERATOR, preview_fleet_connections,
    preview_fleet_environments, preview_fleet_organizations, preview_fleet_projects,
    preview_organization, preview_service_accounts, preview_users, preview_webhooks,
};
use crate::fleet_client::{self, DeploymentRole, EnrollmentCredential};
use crate::models::{NavKey, OrganizationView, ServiceAccountView, UserView, WebhookView};
use crate::proto::rustyauth::analytics::v1::{
    AnalyticsMetric, AnalyticsOverview, AnalyticsPolicy, AnalyticsScope, AnalyticsScopeKind,
    AuthenticationFunnel, CompareScopesResponse, FailureBreakdown, MetricSeries,
};
use crate::proto::rustyauth::fleet::v1::{
    AuditEvent, ConnectionMode, ConnectionState, Environment as FleetEnvironment, EnvironmentKind,
    FleetOverview, FleetRealmOperations, Organization as FleetOrganization,
    Project as FleetProject, RealmConnection,
};
use crate::proto::rustyauth::management::v1::RemoteMutationOperation;

const BRAND_LOCKUP: &[u8] = include_bytes!("../../site/public/brand/rustyauth-lockup.png");
const BRAND_LOCKUP_DARK: &[u8] =
    include_bytes!("../../site/public/brand/rustyauth-lockup-dark.png");
const BRAND_MARK: &[u8] = include_bytes!("../../site/public/brand/rustyauth-mark.png");
const BRAND_MARK_TRANSPARENT: &[u8] =
    include_bytes!("../../site/public/brand/rustyauth-mark-transparent.png");

#[derive(Clone, Copy, PartialEq)]
enum AppView {
    Dashboard(DashboardMode),
    SignIn(SignInVariant),
    Setup,
    Recovery,
}

#[derive(Clone, Copy, PartialEq)]
enum DashboardMode {
    Preview,
    Live(DeploymentRole),
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
    let mut active = use_signal(initial_nav_key);
    let mut mobile_nav = use_signal(|| false);
    let mut organization = use_signal(preview_organization);
    let accounts = use_signal(preview_service_accounts);
    rsx! {
        document::Stylesheet { href: asset!("/assets/styles.css") }
        match view() {
            AppView::SignIn(SignInVariant::Classic) => rsx! {
                SignInScreen {
                    on_authenticated: move |role| {
                        active.set(if role == DeploymentRole::Realm { NavKey::Overview } else { NavKey::FleetOverview });
                        navigate_to(&mut view, AppView::Dashboard(DashboardMode::Live(role)));
                    },
                    on_preview: move |_| {
                        active.set(NavKey::FleetOverview);
                        navigate_to(&mut view, AppView::Dashboard(DashboardMode::Preview));
                    },
                    on_setup: move |_| navigate_to(&mut view, AppView::Setup),
                    on_recovery: move |_| navigate_to(&mut view, AppView::Recovery),
                }
            },
            AppView::SignIn(SignInVariant::Aperture) => rsx! {
                ApertureSignInScreen {
                    on_authenticated: move |role| {
                        active.set(if role == DeploymentRole::Realm { NavKey::Overview } else { NavKey::FleetOverview });
                        navigate_to(&mut view, AppView::Dashboard(DashboardMode::Live(role)));
                    },
                    on_preview: move |_| {
                        active.set(NavKey::FleetOverview);
                        navigate_to(&mut view, AppView::Dashboard(DashboardMode::Preview));
                    },
                    on_setup: move |_| navigate_to(&mut view, AppView::Setup),
                    on_recovery: move |_| navigate_to(&mut view, AppView::Recovery),
                }
            },
            AppView::Setup => rsx! {
                OperatorSetupScreen {
                    on_registered: move |role| {
                        active.set(if role == DeploymentRole::Realm { NavKey::Overview } else { NavKey::FleetOverview });
                        navigate_to(&mut view, AppView::Dashboard(DashboardMode::Live(role)));
                    },
                    on_back: move |_| navigate_to(&mut view, AppView::SignIn(SignInVariant::Classic)),
                }
            },
            AppView::Recovery => rsx! {
                OperatorRecoveryScreen {
                    on_recovered: move |role| {
                        active.set(if role == DeploymentRole::Realm { NavKey::Security } else { NavKey::FleetOverview });
                        navigate_to(&mut view, AppView::Dashboard(DashboardMode::Live(role)));
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
                        deployment_role: match mode { DashboardMode::Live(role) => Some(role), DashboardMode::Preview => None },
                        mobile_open: mobile_nav(),
                        on_navigate: move |key| {
                            active.set(key);
                            mobile_nav.set(false);
                        },
                        on_sign_out: move |_| {
                            if matches!(mode, DashboardMode::Live(_)) {
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
                                if matches!(mode, DashboardMode::Live(_)) {
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
                            if active() == NavKey::Benchmarks {
                                BenchmarksPage {}
                            } else if mode == DashboardMode::Live(DeploymentRole::Realm) {
                                RealmWorkspace {
                                    active: active(),
                                    on_navigate: move |key| active.set(key),
                                    on_session_revoked: move |_| navigate_to(&mut view, AppView::SignIn(SignInVariant::Classic)),
                                }
                            } else { match active() {
                                NavKey::FleetOverview | NavKey::Organizations | NavKey::Projects | NavKey::Environments | NavKey::Connections | NavKey::Audit | NavKey::Metrics => rsx! {
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
                                NavKey::Benchmarks => rsx! { BenchmarksPage {} },
                                NavKey::Security => rsx! { section { class: "panel empty-panel", h2 { "Account security is available on a live realm." } } },
                            } }
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
            return AppView::Dashboard(DashboardMode::Live(DeploymentRole::FleetControlPlane));
        }
        if search.contains("login=aperture") {
            return AppView::SignIn(SignInVariant::Aperture);
        }
        if search.contains("setup=1") {
            return AppView::Setup;
        }
        if search.contains("recovery=1") {
            return AppView::Recovery;
        }
    }

    AppView::SignIn(SignInVariant::Classic)
}

fn initial_nav_key() -> NavKey {
    #[cfg(target_arch = "wasm32")]
    if web_sys::window()
        .and_then(|window| window.location().search().ok())
        .is_some_and(|search| search.contains("benchmarks=1"))
    {
        return NavKey::Benchmarks;
    }

    NavKey::FleetOverview
}

fn navigate_to(view: &mut Signal<AppView>, next: AppView) {
    view.set(next);

    #[cfg(target_arch = "wasm32")]
    if let Some(window) = web_sys::window()
        && let Ok(history) = window.history()
    {
        let path = match next {
            AppView::Dashboard(DashboardMode::Preview) => "/?preview=1",
            AppView::Dashboard(DashboardMode::Live(DeploymentRole::FleetControlPlane)) => {
                "/?fleet=1"
            }
            AppView::Dashboard(DashboardMode::Live(DeploymentRole::Realm)) => "/?realm=1",
            AppView::SignIn(SignInVariant::Classic) => "/",
            AppView::SignIn(SignInVariant::Aperture) => "/?login=aperture",
            AppView::Setup => "/?setup=1",
            AppView::Recovery => "/?recovery=1",
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

#[cfg(target_arch = "wasm32")]
fn operator_credential_initial() -> String {
    "admin@rustyauth.local".into()
}

#[cfg(not(target_arch = "wasm32"))]
fn operator_credential_initial() -> String {
    String::new()
}

#[cfg(target_arch = "wasm32")]
const fn operator_credential_ui() -> (&'static str, &'static str, &'static str, &'static str) {
    (
        "Operator email",
        "email",
        "username webauthn",
        "Continue with passkey",
    )
}

#[cfg(not(target_arch = "wasm32"))]
const fn operator_credential_ui() -> (&'static str, &'static str, &'static str, &'static str) {
    (
        "Native-console token",
        "password",
        "off",
        "Connect this device",
    )
}

#[cfg(target_arch = "wasm32")]
const fn operator_credential_missing() -> &'static str {
    "Enter the operator email bound to your passkey."
}

#[cfg(not(target_arch = "wasm32"))]
const fn operator_credential_missing() -> &'static str {
    "Paste the short-lived token minted from the browser dashboard."
}

#[component]
fn SignInScreen(
    on_authenticated: EventHandler<DeploymentRole>,
    on_preview: EventHandler<()>,
    on_setup: EventHandler<()>,
    on_recovery: EventHandler<()>,
) -> Element {
    let mut email = use_signal(operator_credential_initial);
    let mut error = use_signal(String::new);
    let mut authenticating = use_signal(|| false);
    let brand_mark = png_data(BRAND_MARK);
    let (credential_label, credential_type, credential_autocomplete, submit_label) =
        operator_credential_ui();

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
                        error.set(operator_credential_missing().to_string());
                    } else {
                        authenticating.set(true);
                        error.set(String::new());
                        let operator_email = email().trim().to_owned();
                        spawn(async move {
                            match fleet_client::authenticate_passkey(&operator_email).await {
                                Ok(()) => match fleet_client::deployment_role().await {
                                    Ok(role) => on_authenticated.call(role),
                                    Err(reason) => error.set(reason.0),
                                },
                                Err(reason) => error.set(reason.0),
                            }
                            authenticating.set(false);
                        });
                    }
                },
                    label { r#for: "operator-email", "{credential_label}" }
                    input {
                        id: "operator-email",
                        r#type: credential_type,
                        autocomplete: credential_autocomplete,
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
                        if authenticating() { "Verifying…" } else { "{submit_label}" }
                    }
                }
                div { class: "auth-divider", span { "Local evaluation" } }
                button { class: "button secondary wide", r#type: "button", onclick: move |_| on_preview.call(()),
                    "Open populated preview "
                    Icon { icon: TablerIcon::ArrowUpRight, size: 17 }
                }
                if cfg!(target_arch = "wasm32") {
                    button { class: "auth-setup-link", r#type: "button", onclick: move |_| on_setup.call(()),
                        "Set up the first operator passkey"
                    }
                    button { class: "auth-setup-link", r#type: "button", onclick: move |_| on_recovery.call(()),
                        "Recover access with an offline code"
                    }
                }
                p { class: "auth-footnote",
                    if cfg!(target_arch = "wasm32") {
                        "Only users listed in " code { "AUTH_OPERATOR_EMAILS" } " can bootstrap operator access."
                    } else {
                        "Tokens expire after at most 15 minutes and remain bound to the passkey that minted them."
                    }
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
fn OperatorRecoveryScreen(
    on_recovered: EventHandler<DeploymentRole>,
    on_back: EventHandler<()>,
) -> Element {
    let mut email = use_signal(String::new);
    let mut recovery_code = use_signal(String::new);
    let mut label = use_signal(|| "Recovered passkey".to_string());
    let mut error = use_signal(String::new);
    let mut recovering = use_signal(|| false);
    let brand_mark = png_data(BRAND_MARK);

    rsx! {
        main { class: "auth-stage",
            section { class: "auth-card setup-card",
                header { class: "auth-brand",
                    img { src: brand_mark, width: "48", height: "48", alt: "" }
                    div { strong { "Rusty" span { "Auth" } } small { "Offline account recovery" } }
                }
                div { class: "auth-copy",
                    p { class: "eyebrow", "One-time recovery" }
                    h1 { "Replace a lost authenticator." }
                    p { "Use one offline recovery code to enrol a new passkey. Existing sessions and all remaining recovery codes will be revoked." }
                }
                form { onsubmit: move |event| {
                    event.prevent_default();
                    if email().trim().is_empty() || recovery_code().trim().is_empty() || label().trim().is_empty() {
                        error.set("Email, recovery code, and passkey label are required.".into());
                        return;
                    }
                    recovering.set(true);
                    error.set(String::new());
                    let account_email = email().trim().to_owned();
                    let code = recovery_code().trim().to_owned();
                    let passkey_label = label().trim().to_owned();
                    recovery_code.set(String::new());
                    spawn(async move {
                        match fleet_client::recover_operator_passkey(&account_email, &code, &passkey_label).await {
                            Ok(()) => match fleet_client::deployment_role().await {
                                Ok(role) => on_recovered.call(role),
                                Err(reason) => error.set(reason.0),
                            },
                            Err(reason) => error.set(reason.0),
                        }
                        recovering.set(false);
                    });
                },
                    label { r#for: "recovery-email", "Account email" }
                    input { id: "recovery-email", r#type: "email", autocomplete: "username", value: email(), required: true, oninput: move |event| email.set(event.value()) }
                    label { r#for: "recovery-code", "Offline recovery code" }
                    input { id: "recovery-code", r#type: "password", autocomplete: "one-time-code", value: recovery_code(), required: true, oninput: move |event| recovery_code.set(event.value()) }
                    label { r#for: "recovery-label", "New passkey label" }
                    input { id: "recovery-label", value: label(), maxlength: 100, required: true, oninput: move |event| label.set(event.value()) }
                    if !error().is_empty() {
                        p { class: "form-error", role: "alert", Icon { icon: TablerIcon::AlertTriangle, size: 16 } "{error}" }
                    }
                    button { class: "button primary wide", r#type: "submit", disabled: recovering(),
                        Icon { icon: TablerIcon::ShieldCheck, size: 18 }
                        if recovering() { "Creating replacement passkey…" } else { "Recover account" }
                    }
                }
                button { class: "auth-setup-link", r#type: "button", onclick: move |_| on_back.call(()), "Back to operator sign in" }
            }
            aside { class: "auth-aside",
                p { class: "eyebrow", "Containment" }
                div { class: "boundary-stack",
                    AuthBoundaryItem { icon: TablerIcon::Key, label: "Recovery code", detail: "Consumed exactly once" }
                    AuthBoundaryItem { icon: TablerIcon::ShieldCheck, label: "New passkey", detail: "User-verified enrolment", class: "accent" }
                    AuthBoundaryItem { icon: TablerIcon::Logout, label: "Old sessions", detail: "Revoked on success", class: "dark" }
                }
            }
        }
    }
}

#[component]
fn OperatorSetupScreen(
    on_registered: EventHandler<DeploymentRole>,
    on_back: EventHandler<()>,
) -> Element {
    let mut email = use_signal(|| "admin@rustyauth.local".to_string());
    let mut display_name = use_signal(|| "Local owner".to_string());
    let mut bootstrap_token = use_signal(String::new);
    let mut invitation_code = use_signal(String::new);
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
                    let has_bootstrap = !bootstrap_token().trim().is_empty();
                    let has_invitation = !invitation_code().trim().is_empty();
                    if email().trim().is_empty() || display_name().trim().is_empty() || has_bootstrap == has_invitation {
                        error.set("Complete the identity fields and provide exactly one invitation or development bootstrap token.".into());
                        return;
                    }
                    registering.set(true);
                    error.set(String::new());
                    let operator_email = email().trim().to_owned();
                    let operator_name = display_name().trim().to_owned();
                    let enrolment = if has_invitation {
                        EnrollmentCredential::ProductionInvitation(invitation_code().trim().to_owned())
                    } else {
                        EnrollmentCredential::DevelopmentBootstrap(bootstrap_token().trim().to_owned())
                    };
                    bootstrap_token.set(String::new());
                    invitation_code.set(String::new());
                    spawn(async move {
                        match fleet_client::register_operator_passkey(&operator_email, &operator_name, &enrolment).await {
                            Ok(()) => match fleet_client::deployment_role().await {
                                Ok(role) => on_registered.call(role),
                                Err(reason) => error.set(reason.0),
                            },
                            Err(reason) => error.set(reason.0),
                        }
                        registering.set(false);
                    });
                },
                    label { r#for: "setup-name", "Display name" }
                    input { id: "setup-name", value: display_name(), required: true, autocomplete: "name", oninput: move |event| display_name.set(event.value()) }
                    label { r#for: "setup-email", "Allowlisted operator email" }
                    input { id: "setup-email", r#type: "email", value: email(), required: true, autocomplete: "username", oninput: move |event| email.set(event.value()) }
                    label { r#for: "setup-invitation", "Production invitation code" }
                    input { id: "setup-invitation", r#type: "password", value: invitation_code(), autocomplete: "off", oninput: move |event| { invitation_code.set(event.value()); bootstrap_token.set(String::new()); } }
                    div { class: "auth-divider", span { "or local development" } }
                    label { r#for: "setup-token", "Development bootstrap token" }
                    input { id: "setup-token", r#type: "password", value: bootstrap_token(), autocomplete: "off", oninput: move |event| { bootstrap_token.set(event.value()); invitation_code.set(String::new()); } }
                    if !error().is_empty() {
                        p { class: "form-error", role: "alert", Icon { icon: TablerIcon::AlertTriangle, size: 16 } "{error}" }
                    }
                    button { class: "button primary wide", r#type: "submit", disabled: registering(),
                        Icon { icon: TablerIcon::ShieldCheck, size: 18 }
                        if registering() { "Creating passkey…" } else { "Create operator passkey" }
                    }
                }
                button { class: "auth-setup-link", r#type: "button", onclick: move |_| on_back.call(()), "Back to operator sign in" }
                p { class: "auth-footnote", "Production invitations are identifier-bound and one-time. Local setup may read the bootstrap token from " code { ".env.fleet.local" } "." }
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
    on_authenticated: EventHandler<DeploymentRole>,
    on_preview: EventHandler<()>,
    on_setup: EventHandler<()>,
    on_recovery: EventHandler<()>,
) -> Element {
    let mut email = use_signal(operator_credential_initial);
    let mut error = use_signal(String::new);
    let mut authenticating = use_signal(|| false);
    let brand_lockup = png_data(BRAND_LOCKUP_DARK);
    let emboss_mark = png_data(BRAND_MARK_TRANSPARENT);
    let (credential_label, credential_type, credential_autocomplete, submit_label) =
        operator_credential_ui();

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
                            error.set(operator_credential_missing().to_string());
                        } else {
                            authenticating.set(true);
                            error.set(String::new());
                            let operator_email = email().trim().to_owned();
                            spawn(async move {
                                match fleet_client::authenticate_passkey(&operator_email).await {
                                    Ok(()) => match fleet_client::deployment_role().await {
                                        Ok(role) => on_authenticated.call(role),
                                        Err(reason) => error.set(reason.0),
                                    },
                                    Err(reason) => error.set(reason.0),
                                }
                                authenticating.set(false);
                            });
                        }
                    },
                        label { r#for: "aperture-operator-email", "{credential_label}" }
                        input {
                            id: "aperture-operator-email",
                            r#type: credential_type,
                            autocomplete: credential_autocomplete,
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
                            span { if authenticating() { "Verifying…" } else { "{submit_label}" } }
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
                    button { class: "aperture-setup-link", r#type: "button", onclick: move |_| on_recovery.call(()),
                        "Recover access with an offline code"
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
    deployment_role: Option<DeploymentRole>,
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
                    strong { if deployment_role == Some(DeploymentRole::Realm) { "RustyAuth Realm" } else { "RustyAuth Fleet" } }
                    small { if preview { "Sample control plane" } else { "Connected control plane" } }
                }
                Icon { icon: TablerIcon::ChevronRight, size: 16 }
            }
            nav { class: "side-nav", aria_label: "Control plane",
                if deployment_role != Some(DeploymentRole::Realm) {
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
                if deployment_role == Some(DeploymentRole::Realm) {
                    NavButton {
                        active: active == NavKey::Security,
                        icon: TablerIcon::ShieldCheck,
                        label: "Account security",
                        onclick: move |_| on_navigate.call(NavKey::Security),
                    }
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
                            role: "menuitem",
                            onclick: move |_| {
                                menu_open.set(false);
                                on_navigate.call(NavKey::Benchmarks);
                            },
                            Icon { icon: TablerIcon::Gauge, size: 17 }
                            "Release benchmarks"
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
        outbound: bool,
    },
}

#[component]
fn RealmWorkspace(
    active: NavKey,
    on_navigate: EventHandler<NavKey>,
    on_session_revoked: EventHandler<()>,
) -> Element {
    use crate::proto::rustyauth::{
        identity::v1::User as RealmUser,
        metrics::v1::{AuthenticationFunnel, FailureBreakdown, MetricSeries, MetricsOverview},
        organization::v1::{Operator, Organization},
        service_accounts::v1::ServiceAccount,
        webhooks::v1::Webhook,
    };

    let mut organization = use_signal(|| None::<Organization>);
    let mut operator = use_signal(|| None::<Operator>);
    let mut users = use_signal(Vec::<RealmUser>::new);
    let mut accounts = use_signal(Vec::<ServiceAccount>::new);
    let mut webhooks = use_signal(Vec::<Webhook>::new);
    let mut metrics_overview = use_signal(MetricsOverview::default);
    let mut metric_attempts = use_signal(MetricSeries::default);
    let mut metric_funnel = use_signal(AuthenticationFunnel::default);
    let mut metric_failures = use_signal(FailureBreakdown::default);
    let mut metric_period_seconds = use_signal(|| 24 * 60 * 60_i64);
    let mut loading = use_signal(|| true);
    let mut error = use_signal(String::new);
    let mut invitation_type = use_signal(|| "email".to_string());
    let mut invitation_value = use_signal(String::new);
    let mut invitation_code = use_signal(String::new);
    let mut organization_name = use_signal(String::new);
    let mut service_account_name = use_signal(String::new);
    let mut service_account_description = use_signal(String::new);
    let mut service_account_scopes = use_signal(|| "identity.read".to_string());
    let mut service_credential_secret = use_signal(String::new);
    let mut webhook_name = use_signal(String::new);
    let mut webhook_url = use_signal(String::new);
    let mut webhook_events = use_signal(|| "identity.created,session.created".to_string());
    let mut webhook_secret = use_signal(String::new);
    let mut webhook_operation = use_signal(String::new);
    let mut recovery_codes = use_signal(Vec::<String>::new);
    let mut verification_identifier = use_signal(String::new);
    let mut verification_challenge =
        use_signal(|| None::<fleet_client::IdentifierVerificationChallenge>);
    let mut verification_code = use_signal(String::new);
    let mut security_notice = use_signal(String::new);
    let mut device_token = use_signal(|| None::<fleet_client::DeviceToken>);

    use_effect(move || {
        let selected_metric_period = metric_period_seconds();
        spawn(async move {
            loading.set(true);
            let result = async {
                let new_organization = fleet_client::realm_organization().await?;
                let new_operator = fleet_client::current_operator().await?;
                let new_users = fleet_client::users().await?;
                let new_accounts = fleet_client::service_accounts().await?;
                let new_webhooks = fleet_client::webhooks().await?;
                let new_metrics = fleet_client::realm_metrics(selected_metric_period).await?;
                Ok::<_, fleet_client::ClientError>((
                    new_organization,
                    new_operator,
                    new_users,
                    new_accounts,
                    new_webhooks,
                    new_metrics,
                ))
            }
            .await;
            match result {
                Ok((
                    new_organization,
                    new_operator,
                    new_users,
                    new_accounts,
                    new_webhooks,
                    new_metrics,
                )) => {
                    organization_name.set(new_organization.name.clone());
                    organization.set(Some(new_organization));
                    verification_identifier.set(new_operator.email.clone());
                    operator.set(Some(new_operator));
                    users.set(new_users);
                    accounts.set(new_accounts);
                    webhooks.set(new_webhooks);
                    metrics_overview.set(new_metrics.overview);
                    metric_attempts.set(new_metrics.attempts);
                    metric_funnel.set(new_metrics.funnel);
                    metric_failures.set(new_metrics.failures);
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
            loading.set(false);
        });
    });

    let save_organization = move |_| {
        let name = organization_name().trim().to_owned();
        if name.is_empty() {
            error.set("Organization name is required.".into());
            return;
        }
        spawn(async move {
            let result = async {
                fleet_client::step_up_passkey().await?;
                fleet_client::update_realm_organization(&name).await
            }
            .await;
            match result {
                Ok(record) => {
                    organization.set(Some(record));
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
        });
    };
    let issue_invitation = move |_| {
        let kind = invitation_type();
        let value = invitation_value().trim().to_owned();
        if value.is_empty() {
            error.set("Invitation identifier is required.".into());
            return;
        }
        invitation_code.set(String::new());
        spawn(async move {
            let result = async {
                fleet_client::step_up_passkey().await?;
                fleet_client::create_invitation(&kind, &value, 86_400).await
            }
            .await;
            match result {
                Ok(response) => {
                    invitation_code.set(response.invitation_code);
                    invitation_value.set(String::new());
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
        });
    };
    let create_service_account = move |_| {
        let name = service_account_name().trim().to_owned();
        let description = service_account_description().trim().to_owned();
        let scopes = comma_separated(&service_account_scopes());
        if name.is_empty() || scopes.is_empty() {
            error.set("Service-account name and at least one scope are required.".into());
            return;
        }
        spawn(async move {
            let result = async {
                fleet_client::step_up_passkey().await?;
                fleet_client::create_service_account(&name, &description, scopes).await
            }
            .await;
            match result {
                Ok(record) => {
                    accounts.write().insert(0, record);
                    service_account_name.set(String::new());
                    service_account_description.set(String::new());
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
        });
    };
    let create_webhook = move |_| {
        let name = webhook_name().trim().to_owned();
        let url = webhook_url().trim().to_owned();
        let events = comma_separated(&webhook_events());
        if name.is_empty() || url.is_empty() || events.is_empty() {
            error.set("Webhook name, HTTPS URL, and at least one event are required.".into());
            return;
        }
        webhook_secret.set(String::new());
        spawn(async move {
            let result = async {
                fleet_client::step_up_passkey().await?;
                fleet_client::create_webhook(&name, &url, events).await
            }
            .await;
            match result {
                Ok(response) => {
                    if let Some(record) = response.webhook.as_option() {
                        webhooks.write().insert(0, record.clone());
                    }
                    webhook_secret.set(response.signing_secret);
                    webhook_name.set(String::new());
                    webhook_url.set(String::new());
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
        });
    };
    let rotate_codes = move |_| {
        recovery_codes.set(Vec::new());
        security_notice.set(String::new());
        spawn(async move {
            let result = async {
                fleet_client::step_up_passkey().await?;
                fleet_client::rotate_recovery_codes().await
            }
            .await;
            match result {
                Ok(codes) => {
                    recovery_codes.set(codes);
                    security_notice.set(
                        "The previous recovery-code set is revoked. Store this replacement set offline now."
                            .into(),
                    );
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
        });
    };
    let request_verification = move |_| {
        let identifier = verification_identifier().trim().to_owned();
        if identifier.is_empty() {
            error.set("Enter the email identifier to verify.".into());
            return;
        }
        verification_challenge.set(None);
        verification_code.set(String::new());
        spawn(async move {
            match fleet_client::request_identifier_verification("email", &identifier).await {
                Ok(challenge) => {
                    if let Some(code) = challenge.development_code.as_ref() {
                        verification_code.set(code.clone());
                    }
                    verification_challenge.set(Some(challenge));
                    security_notice.set("A one-time verification challenge was created.".into());
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
        });
    };
    let complete_verification = move |_| {
        let Some(challenge) = verification_challenge() else {
            error.set("Request a verification challenge first.".into());
            return;
        };
        let code = verification_code().trim().to_owned();
        if code.is_empty() {
            error.set("Enter the delivered verification code.".into());
            return;
        }
        spawn(async move {
            match fleet_client::complete_identifier_verification(&challenge.challenge_id, &code)
                .await
            {
                Ok(()) => {
                    verification_challenge.set(None);
                    verification_code.set(String::new());
                    security_notice.set("The identifier is now verified.".into());
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
        });
    };
    let revoke_sessions = move |_| {
        spawn(async move {
            let result = async {
                fleet_client::step_up_passkey().await?;
                fleet_client::revoke_all_sessions().await
            }
            .await;
            match result {
                Ok(()) => on_session_revoked.call(()),
                Err(reason) => error.set(reason.0),
            }
        });
    };
    let mint_device_token = move |_| {
        device_token.set(None);
        security_notice.set(String::new());
        spawn(async move {
            let result = async {
                fleet_client::step_up_passkey().await?;
                fleet_client::mint_device_token().await
            }
            .await;
            match result {
                Ok(token) => {
                    device_token.set(Some(token));
                    security_notice.set(
                        "A short-lived native-console token was minted. It is shown only in this page state."
                            .into(),
                    );
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
        });
    };

    if loading() {
        return rsx! { section { class: "panel empty-panel", h2 { "Loading realm…" } } };
    }

    rsx! {
        div { class: "content-stack",
            if !error().is_empty() {
                div { class: "inline-error", role: "alert",
                    Icon { icon: TablerIcon::AlertTriangle, size: 18 }
                    span { "{error}" }
                }
            }
            match active {
                NavKey::Overview => rsx! {
                    section { class: "page-heading",
                        div { p { class: "eyebrow", "Live realm" } h2 { "Identity operations" }
                            p { "Current state loaded from the authorized Rust control plane." }
                        }
                    }
                    section { class: "metric-grid",
                        MetricCard { label: "Users", value: users().len().to_string(), change: "Durable accounts", tone: "good" }
                        MetricCard { label: "Service accounts", value: accounts().len().to_string(), change: "Machine identities", tone: "neutral" }
                        MetricCard { label: "Webhooks", value: webhooks().len().to_string(), change: "Signed destinations", tone: "neutral" }
                    }
                    section { class: "panel",
                        PanelHeader { eyebrow: "Operator", title: "Authenticated control-plane session" }
                        if let Some(current) = operator() {
                            div { class: "operator-row",
                                span { "{initials(&current.display_name)}" }
                                div { strong { "{current.display_name}" } small { "{current.email}" } }
                                StatusBadge { status: "Passkey verified" }
                            }
                        }
                        div { class: "form-actions",
                            button { class: "button secondary", onclick: move |_| on_navigate.call(NavKey::Users), "Open users" }
                            button { class: "button secondary", onclick: move |_| on_navigate.call(NavKey::Organization), "Manage access" }
                        }
                    }
                },
                NavKey::Users => rsx! {
                    section { class: "page-heading", div { p { class: "eyebrow", "Identity directory" } h2 { "Users" }
                        p { "Bounded account metadata; credential material never leaves RustyAuth." }
                    } }
                    section { class: "panel table-panel",
                        PanelHeader { eyebrow: "Accounts", title: format!("{} users", users().len()) }
                        div { class: "table-scroll", table { thead { tr { th { "User" } th { "Primary identifier" } th { "Identifiers" } th { "Passkeys" } th { "Created" } th { "Support actions" } } }
                            tbody { for user in users() {
                                {
                                    let display_name = user.profile.as_option().map(|profile| {
                                        if !profile.display_name.is_empty() { profile.display_name.clone() }
                                        else { format!("{} {}", profile.given_name, profile.family_name).trim().to_owned() }
                                    }).filter(|value| !value.is_empty()).unwrap_or_else(|| "Unnamed account".into());
                                    let primary = user.identifiers.iter().find(|identifier| identifier.primary).or_else(|| user.identifiers.first()).map(|identifier| identifier.value.clone()).unwrap_or_default();
                                    let user_id = user.id.clone();
                                    let identifiers = user.identifiers.clone();
                                    let passkeys = user.passkeys.clone();
                                    let passkey_count = passkeys.len();
                                    rsx! { tr { td { strong { "{display_name}" } small { class: "mono-value", "{user.id}" } } td { "{primary}" } td { "{user.identifiers.len()}" } td { "{user.passkeys.len()}" } td { "{format_date(&user.created_at)}" }
                                        td {
                                            for identifier in identifiers {
                                                {
                                                    let target_user_id = user_id.clone();
                                                    let target_identifier = identifier.clone();
                                                    rsx! { button { class: "button secondary", title: "Change verification for {identifier.value}", onclick: move |_| {
                                                        let user_id = target_user_id.clone();
                                                        let identifier = target_identifier.clone();
                                                        spawn(async move {
                                                            let result = async { fleet_client::step_up_passkey().await?; fleet_client::set_identifier_verification(&user_id, &identifier, !identifier.verified).await }.await;
                                                            match result { Ok(updated) => { if let Some(slot) = users.write().iter_mut().find(|item| item.id == updated.id) { *slot = updated; } error.set(String::new()); }, Err(reason) => error.set(reason.0) }
                                                        });
                                                    }, if identifier.verified { "Unverify" } else { "Verify" } } }
                                                }
                                            }
                                            if passkey_count > 1 {
                                                for passkey in passkeys {
                                                    {
                                                        let target_user_id = user_id.clone();
                                                        let credential_id = passkey.credential_id.clone();
                                                        rsx! { button { class: "button secondary", title: "Revoke {passkey.label}", onclick: move |_| {
                                                            let user_id = target_user_id.clone();
                                                            let credential_id = credential_id.clone();
                                                            spawn(async move {
                                                                let result = async { fleet_client::step_up_passkey().await?; fleet_client::revoke_user_passkey(&user_id, &credential_id).await }.await;
                                                                match result { Ok(updated) => { if let Some(slot) = users.write().iter_mut().find(|item| item.id == updated.id) { *slot = updated; } error.set(String::new()); }, Err(reason) => error.set(reason.0) }
                                                            });
                                                        }, "Revoke key" } }
                                                    }
                                                }
                                            }
                                        }
                                    } }
                                }
                            } }
                        } }
                    }
                },
                NavKey::Organization => rsx! {
                    section { class: "page-heading", div { p { class: "eyebrow", "Instance ownership" } h2 { "Organization & invitations" }
                        p { "Administrative settings and identifier-bound production enrolment." }
                    } }
                    section { class: "panel form-panel",
                        PanelHeader { eyebrow: "Organization", title: organization().map(|value| value.name).unwrap_or_else(|| "Organization".into()) }
                        label { "Display name" input { value: organization_name(), maxlength: 120, oninput: move |event| organization_name.set(event.value()) } }
                        div { class: "form-actions", button { class: "button primary", onclick: save_organization, "Save changes" } }
                    }
                    section { class: "panel form-panel",
                        PanelHeader { eyebrow: "Production enrolment", title: "Issue account invitation" }
                        label { "Identifier type" select { value: invitation_type(), onchange: move |event| invitation_type.set(event.value()), option { value: "email", "Email" } option { value: "phone", "Phone (E.164)" } } }
                        label { "Identifier" input { value: invitation_value(), autocomplete: "off", oninput: move |event| invitation_value.set(event.value()) } }
                        div { class: "form-actions", button { class: "button primary", onclick: issue_invitation, "Issue 24-hour invitation" } }
                        if !invitation_code().is_empty() {
                            div { class: "policy-note", Icon { icon: TablerIcon::Key, size: 19 } div { strong { "Copy this code now" } code { "{invitation_code}" } small { "It cannot be shown again." } } }
                        }
                    }
                },
                NavKey::ServiceAccounts => rsx! {
                    section { class: "page-heading", div { p { class: "eyebrow", "Machine identity" } h2 { "Service accounts" } p { "Live, redacted account and credential state." } } }
                    section { class: "panel form-panel",
                        PanelHeader { eyebrow: "New principal", title: "Create service account" }
                        label { "Name" input { value: service_account_name(), maxlength: 100, oninput: move |event| service_account_name.set(event.value()) } }
                        label { "Description" input { value: service_account_description(), maxlength: 500, oninput: move |event| service_account_description.set(event.value()) } }
                        label { "Scopes (comma separated)" input { value: service_account_scopes(), oninput: move |event| service_account_scopes.set(event.value()) } }
                        div { class: "form-actions", button { class: "button primary", onclick: create_service_account, "Create account" } }
                        if !service_credential_secret().is_empty() {
                            div { class: "policy-note", Icon { icon: TablerIcon::Key, size: 19 } div { strong { "Copy this credential now" } code { "{service_credential_secret}" } small { "It cannot be shown again." } } }
                        }
                    }
                    section { class: "panel", PanelHeader { eyebrow: "Principals", title: format!("{} service accounts", accounts().len()) }
                        for account in accounts() {
                            {
                                let account_for_toggle = account.clone();
                                let enabled = account.status.as_known() == Some(crate::proto::rustyauth::service_accounts::v1::ServiceAccountStatus::Active);
                                let account_status: &'static str = if enabled { "Active" } else { "Disabled" };
                                let account_id = account.id.clone();
                                let credential_account_id = account.id.clone();
                                let credentials = account.credentials.clone();
                                let scopes_label = account.scopes.join(", ");
                                rsx! { div { class: "operator-row", span { "SA" } div { strong { "{account.name}" } small { "{account.description} · {scopes_label}" } }
                                    StatusBadge { status: account_status }
                                    button { class: "button secondary", onclick: move |_| {
                                        let account = account_for_toggle.clone();
                                        spawn(async move {
                                            let result = async { fleet_client::step_up_passkey().await?; fleet_client::set_service_account_enabled(&account, !enabled).await }.await;
                                            match result { Ok(updated) => { if let Some(slot) = accounts.write().iter_mut().find(|item| item.id == updated.id) { *slot = updated; } error.set(String::new()); }, Err(reason) => error.set(reason.0) }
                                        });
                                    }, if enabled { "Disable" } else { "Enable" } }
                                    button { class: "button secondary", onclick: move |_| {
                                        let id = account_id.clone();
                                        service_credential_secret.set(String::new());
                                        spawn(async move {
                                            let result = async { fleet_client::step_up_passkey().await?; fleet_client::create_service_credential(&id, "Dashboard credential").await }.await;
                                            match result { Ok(response) => { service_credential_secret.set(response.secret); error.set(String::new()); }, Err(reason) => error.set(reason.0) }
                                        });
                                    }, "Create credential" }
                                    for credential in credentials {
                                        if credential.revoked_at.is_empty() {
                                            {
                                                let account_id = credential_account_id.clone();
                                                let credential_id = credential.id.clone();
                                                rsx! { button { class: "button secondary", title: "Revoke {credential.name}", onclick: move |_| {
                                                    let account_id = account_id.clone();
                                                    let credential_id = credential_id.clone();
                                                    spawn(async move {
                                                        let result = async { fleet_client::step_up_passkey().await?; fleet_client::revoke_service_credential(&account_id, &credential_id).await?; fleet_client::service_accounts().await }.await;
                                                        match result { Ok(records) => { accounts.set(records); error.set(String::new()); }, Err(reason) => error.set(reason.0) }
                                                    });
                                                }, "Revoke {credential.secret_hint}" } }
                                            }
                                        }
                                    }
                                } }
                            }
                        }
                    }
                },
                NavKey::Webhooks => rsx! {
                    section { class: "page-heading", div { p { class: "eyebrow", "Event delivery" } h2 { "Signed webhooks" } p { "Live destination ownership and delivery state." } } }
                    section { class: "panel form-panel",
                        PanelHeader { eyebrow: "New destination", title: "Create signed webhook" }
                        label { "Name" input { value: webhook_name(), maxlength: 100, oninput: move |event| webhook_name.set(event.value()) } }
                        label { "HTTPS URL" input { value: webhook_url(), autocomplete: "off", oninput: move |event| webhook_url.set(event.value()) } }
                        label { "Event types (comma separated)" input { value: webhook_events(), oninput: move |event| webhook_events.set(event.value()) } }
                        div { class: "form-actions", button { class: "button primary", onclick: create_webhook, "Create webhook" } }
                        if !webhook_secret().is_empty() {
                            div { class: "policy-note", Icon { icon: TablerIcon::Key, size: 19 } div { strong { "Copy this signing secret now" } code { "{webhook_secret}" } small { "It cannot be shown again." } } }
                        }
                        if !webhook_operation().is_empty() { p { class: "policy-note", "{webhook_operation}" } }
                    }
                    section { class: "panel", PanelHeader { eyebrow: "Destinations", title: format!("{} webhooks", webhooks().len()) }
                        for webhook in webhooks() {
                            {
                                let configuration_managed = webhook.management_source.as_known() == Some(crate::proto::rustyauth::webhooks::v1::WebhookManagementSource::Configuration);
                                let status: &'static str = if configuration_managed { "Managed by YAML" } else { "Dashboard managed" };
                                let test_id = webhook.id.clone();
                                let rotate_id = webhook.id.clone();
                                let history_id = webhook.id.clone();
                                let delete_id = webhook.id.clone();
                                let event_types_label = webhook.event_types.join(", ");
                                rsx! { div { class: "operator-row", span { "WH" } div { strong { "{webhook.name}" } small { "{webhook.url} · {event_types_label}" } } StatusBadge { status }
                                    button { class: "button secondary", onclick: move |_| { let id = test_id.clone(); spawn(async move { let result = async { fleet_client::step_up_passkey().await?; fleet_client::test_webhook(&id).await }.await; match result { Ok(delivery) => { webhook_operation.set(format!("Test delivery {}: {:?}", delivery.id, delivery.status.as_known())); error.set(String::new()); }, Err(reason) => error.set(reason.0) } }); }, "Test" }
                                    button { class: "button secondary", onclick: move |_| { let id = history_id.clone(); spawn(async move { match fleet_client::webhook_deliveries(&id).await { Ok(deliveries) => { webhook_operation.set(format!("{} delivery records for {id}", deliveries.len())); error.set(String::new()); }, Err(reason) => error.set(reason.0) } }); }, "History" }
                                    if !configuration_managed {
                                        button { class: "button secondary", onclick: move |_| { let id = rotate_id.clone(); webhook_secret.set(String::new()); spawn(async move { let result = async { fleet_client::step_up_passkey().await?; fleet_client::rotate_webhook_secret(&id).await }.await; match result { Ok(response) => { webhook_secret.set(response.signing_secret); error.set(String::new()); }, Err(reason) => error.set(reason.0) } }); }, "Rotate secret" }
                                        button { class: "button secondary", onclick: move |_| { let id = delete_id.clone(); spawn(async move { let result = async { fleet_client::step_up_passkey().await?; fleet_client::delete_webhook(&id).await }.await; match result { Ok(()) => { webhooks.write().retain(|item| item.id != id); error.set(String::new()); }, Err(reason) => error.set(reason.0) } }); }, "Delete" }
                                    }
                                } }
                            }
                        }
                    }
                },
                NavKey::Metrics => rsx! {
                    RealmMetricsPage {
                        overview: metrics_overview(),
                        attempts: metric_attempts(),
                        funnel: metric_funnel(),
                        failures: metric_failures(),
                        period_seconds: metric_period_seconds(),
                        on_period: move |value| metric_period_seconds.set(value),
                    }
                },
                NavKey::Security => rsx! {
                    section { class: "page-heading",
                        div {
                            p { class: "eyebrow", "Passkey-protected account" }
                            h2 { "Account security & recovery" }
                            p { "Rotate offline recovery codes, prove identifier control, or revoke every active session." }
                        }
                    }
                    if !security_notice().is_empty() {
                        div { class: "policy-note", role: "status", Icon { icon: TablerIcon::ShieldCheck, size: 19 } div { strong { "Security state changed" } small { "{security_notice}" } } }
                    }
                    section { class: "panel form-panel",
                        PanelHeader { eyebrow: "Offline recovery", title: "Recovery-code set" }
                        p { "Rotating requires a fresh passkey step-up and immediately invalidates the previous set." }
                        div { class: "form-actions", button { class: "button primary", onclick: rotate_codes, "Rotate recovery codes" } }
                        if !recovery_codes().is_empty() {
                            div { class: "policy-note",
                                Icon { icon: TablerIcon::Key, size: 19 }
                                div {
                                    strong { "Copy all codes now — they cannot be shown again" }
                                    for code in recovery_codes() { code { "{code}" } }
                                    small { "Each code is single-use. Keep them away from the devices that hold your passkeys." }
                                }
                            }
                        }
                    }
                    if cfg!(target_arch = "wasm32") {
                        section { class: "panel form-panel",
                            PanelHeader { eyebrow: "Native console", title: "Connect a desktop or mobile device" }
                            p { "A fresh passkey step-up mints a credential valid for at most 15 minutes. Revoking this passkey or all sessions invalidates it immediately." }
                            div { class: "form-actions", button { class: "button primary", onclick: mint_device_token, "Mint native-console token" } }
                            if let Some(token) = device_token() {
                                div { class: "policy-note",
                                    Icon { icon: TablerIcon::Key, size: 19 }
                                    div {
                                        strong { "Copy this token now — it is not shown again after leaving this page" }
                                        code { "{token.token}" }
                                        small { "Expires at Unix second {token.expires_at}. The native app stores it in the operating-system credential vault." }
                                    }
                                }
                            }
                        }
                    }
                    section { class: "panel form-panel",
                        PanelHeader { eyebrow: "Identity proof", title: "Verify your operator email" }
                        label { "Email identifier" input { r#type: "email", value: verification_identifier(), autocomplete: "email", oninput: move |event| verification_identifier.set(event.value()) } }
                        div { class: "form-actions", button { class: "button secondary", onclick: request_verification, "Send verification code" } }
                        if let Some(challenge) = verification_challenge() {
                            p { class: "policy-note",
                                if challenge.delivered { "The code was delivered through the configured signed webhook." }
                                else { "Development mode returned the code locally." }
                                " Expires at Unix second {challenge.expires_at}."
                            }
                            label { "Verification code" input { autocomplete: "one-time-code", value: verification_code(), oninput: move |event| verification_code.set(event.value()) } }
                            div { class: "form-actions", button { class: "button primary", onclick: complete_verification, "Verify identifier" } }
                        }
                    }
                    section { class: "panel danger-panel",
                        PanelHeader { eyebrow: "Containment", title: "Revoke all sessions" }
                        p { "A fresh passkey step-up is required. This browser is signed out together with every other active session." }
                        div { class: "form-actions", button { class: "button danger", onclick: revoke_sessions, "Revoke every session" } }
                    }
                },
                _ => rsx! { section { class: "panel empty-panel", h2 { "This view belongs to Fleet mode." } } },
            }
        }
    }
}

#[component]
fn RealmMetricsPage(
    overview: crate::proto::rustyauth::metrics::v1::MetricsOverview,
    attempts: crate::proto::rustyauth::metrics::v1::MetricSeries,
    funnel: crate::proto::rustyauth::metrics::v1::AuthenticationFunnel,
    failures: crate::proto::rustyauth::metrics::v1::FailureBreakdown,
    period_seconds: i64,
    on_period: EventHandler<i64>,
) -> Element {
    let success_rate = format!("{:.2}%", overview.authentication_success_rate * 100.0);
    let latency = format!("{:.0} ms", overview.authentication_latency_p95_milliseconds);
    let maximum_attempts = attempts
        .points
        .iter()
        .map(|point| point.value)
        .fold(0.0_f64, f64::max)
        .max(1.0);
    let registration_completion = percentage(
        funnel.registrations_completed,
        funnel.registration_options_started,
    );
    let authentication_completion = percentage(
        funnel.authentications_completed,
        funnel.authentication_options_started,
    );
    let total_failures = failures
        .failures
        .iter()
        .fold(0_u64, |total, failure| total.saturating_add(failure.count));

    rsx! {
        div { class: "content-stack",
            section { class: "page-heading",
                div {
                    p { class: "eyebrow", "Live realm telemetry" }
                    h2 { "Authentication metrics" }
                    p { "Durable five-minute aggregates; identity and credential dimensions remain inside the realm." }
                }
                div { class: "segmented",
                    for (label, seconds) in [("24 hours", 86_400_i64), ("7 days", 604_800_i64), ("28 days", 2_419_200_i64)] {
                        button {
                            r#type: "button",
                            class: if period_seconds == seconds { "active" } else { "" },
                            onclick: move |_| on_period.call(seconds),
                            "{label}"
                        }
                    }
                }
            }
            section { class: "metric-grid metrics-full",
                MetricCard { label: "Authentication attempts", value: overview.authentication_attempts.to_string(), change: "Selected period", tone: "neutral" }
                MetricCard { label: "Success rate", value: success_rate.clone(), change: "Completed / attempts", tone: "good" }
                MetricCard { label: "Latency p95", value: latency, change: "Merged histogram", tone: "neutral" }
                MetricCard { label: "Active users", value: overview.active_users.to_string(), change: "Distinct realm accounts", tone: "neutral" }
            }
            div { class: "overview-grid metrics-grid",
                section { class: "panel volume-panel",
                    PanelHeader { eyebrow: "Authentication attempts", title: "Volume" }
                    if attempts.points.is_empty() {
                        div { class: "empty-state", p { "No authentication activity in this period." } }
                    } else {
                        div { class: "bar-chart tall", aria_label: "Authentication attempts over time",
                            for point in attempts.points {
                                {
                                    let height = ((point.value / maximum_attempts) * 100.0).round() as u16;
                                    let height = ((height.max(5) + 2) / 5 * 5).min(100);
                                    rsx! { span { class: "bar-height-{height}", title: "{point.starts_at} · {point.value:.0}" } }
                                }
                            }
                        }
                    }
                    div { class: "chart-legend",
                        span { i { class: "copper" } "Durable projected events" }
                        strong { "{success_rate} success" }
                    }
                }
                section { class: "panel",
                    PanelHeader { eyebrow: "Passkey funnel", title: "Ceremony completion" }
                    LiveFunnelRow { label: "Registration options", value: funnel.registration_options_started, percent: 100 }
                    LiveFunnelRow { label: "Registrations completed", value: funnel.registrations_completed, percent: registration_completion }
                    LiveFunnelRow { label: "Authentication options", value: funnel.authentication_options_started, percent: 100 }
                    LiveFunnelRow { label: "Authentications completed", value: funnel.authentications_completed, percent: authentication_completion }
                }
            }
            section { class: "panel failure-panel",
                PanelHeader { eyebrow: "Failure analysis", title: "Bounded rejection classes" }
                if failures.failures.is_empty() {
                    div { class: "empty-state", p { "No classified authentication failures in this period." } }
                } else {
                    div { class: "failure-grid",
                        for failure in failures.failures {
                            LiveFunnelRow {
                                label: failure.error_class,
                                value: failure.count,
                                percent: percentage(failure.count, total_failures),
                            }
                        }
                    }
                }
            }
            section { class: "panel",
                PanelHeader { eyebrow: "Operations", title: "Delivery and recovery posture" }
                div { class: "metric-grid",
                    MetricCard { label: "Registrations", value: overview.registrations.to_string(), change: "Completed", tone: "neutral" }
                    MetricCard { label: "Service accounts", value: overview.active_service_accounts.to_string(), change: "Active", tone: "neutral" }
                    MetricCard { label: "Webhook backlog", value: overview.webhook_delivery_backlog.to_string(), change: "Pending or retrying", tone: if overview.webhook_delivery_backlog == 0 { "good" } else { "warning" } }
                    MetricCard { label: "Backup", value: if overview.backup_healthy { "Healthy".to_string() } else { "Attention".to_string() }, change: if overview.last_backup_at.is_empty() { "No successful backup".to_string() } else { overview.last_backup_at }, tone: if overview.backup_healthy { "good" } else { "warning" } }
                }
            }
        }
    }
}

#[component]
fn LiveFunnelRow(label: String, value: u64, percent: u16) -> Element {
    rsx! {
        div { class: "funnel-row",
            div { strong { "{label}" } span { "{value}" } }
            meter { min: 0, max: 100, value: percent, "{percent}%" }
            small { "{percent}%" }
        }
    }
}

fn percentage(numerator: u64, denominator: u64) -> u16 {
    if denominator == 0 {
        0
    } else {
        numerator.saturating_mul(100).div_ceil(denominator).min(100) as u16
    }
}

fn comma_separated(value: &str) -> Vec<String> {
    let mut values = value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    values.sort_unstable();
    values.dedup();
    values
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
    let mut notice = use_signal(String::new);

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
                FleetMutation::Connection {
                    endpoint, outbound, ..
                } => {
                    let record = RealmConnection {
                        id: uuid::Uuid::new_v4().to_string(),
                        organization_id: selected_organization(),
                        project_id: selected_project(),
                        environment_id: selected_environment(),
                        realm_id: "preview-realm".into(),
                        display_name: "Preview realm".into(),
                        mode: if outbound {
                            ConnectionMode::OutboundConnector
                        } else {
                            ConnectionMode::PublicEndpoint
                        }
                        .into(),
                        management_endpoint: endpoint,
                        deployment_version: "1.0.0".into(),
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
                    outbound,
                } => {
                    match fleet_client::begin_connection(
                        &selected_organization(),
                        &selected_project(),
                        &selected_environment(),
                        &endpoint,
                        if outbound {
                            ConnectionMode::OutboundConnector
                        } else {
                            ConnectionMode::PublicEndpoint
                        },
                        if outbound { &pairing_code } else { "" },
                    )
                    .await
                    {
                        Ok(attempt) if outbound => {
                            notice.set(format!(
                                "Outbound attempt {} is ready. On the private realm host, provide the same code through RUSTYAUTH_FLEET_PAIRING_CODE_FILE and run: rustyauth fleet pair-outbound <control-plane-origin> {}",
                                attempt.id, attempt.id
                            ));
                            Ok(())
                        }
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
        if !notice().is_empty() {
            div { class: "fleet-alert", role: "status",
                Icon { icon: TablerIcon::PlugConnected, size: 17 }
                span { "{notice}" }
                button { r#type: "button", onclick: move |_| notice.set(String::new()), Icon { icon: TablerIcon::X, size: 15 } }
            }
        }
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
            NavKey::Metrics if preview => rsx! { MetricsPage {} },
            NavKey::Metrics => rsx! {
                FleetAnalyticsPage {
                    organization_id: selected_organization(),
                    project_id: selected_project(),
                    environment_id: selected_environment(),
                    projects: projects(),
                    environments: environments(),
                    connections: connections(),
                }
            },
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
    let mut operations = use_signal(|| None::<FleetRealmOperations>);
    let mut inspected_connection = use_signal(|| None::<RealmConnection>);
    let mut inspecting = use_signal(|| None::<String>);
    let mut inspection_error = use_signal(String::new);
    let mut mutation_operation = use_signal(|| "revoke-user-passkey".to_string());
    let mut mutation_target = use_signal(String::new);
    let mut mutation_secondary = use_signal(String::new);
    let mut mutation_reason = use_signal(String::new);
    let mut mutation_enabled = use_signal(|| true);
    let mut mutation_confirmed = use_signal(|| false);
    let mut mutation_status = use_signal(String::new);
    let mut mutating = use_signal(|| false);
    let mut rotation_reason = use_signal(String::new);
    let mut rotation_status = use_signal(String::new);
    let mut rotating = use_signal(|| false);
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
                {
                    let inspect_record = record.clone();
                    let inspect_id = record.id.clone();
                    rsx! {
                        div { class: "fleet-row",
                            span { class: "fleet-row-mark", Icon { icon: TablerIcon::ShieldCheck, size: 18 } }
                            span { strong { "{record.display_name}" } small { "{record.management_endpoint}" } }
                            span { class: if record.state == ConnectionState::Healthy { "status-badge good" } else { "status-badge warn" }, "{connection_label(record.state)}" }
                            span { class: "mono-value", "v{record.deployment_version}" }
                            button {
                                class: "button secondary",
                                r#type: "button",
                                disabled: inspecting().is_some(),
                                onclick: move |_| {
                                    let connection = inspect_record.clone();
                                    let connection_id = inspect_id.clone();
                                    spawn(async move {
                                        inspecting.set(Some(connection_id));
                                        match fleet_client::realm_operations(&connection, 24 * 60 * 60).await {
                                            Ok(snapshot) => {
                                                operations.set(Some(snapshot));
                                                inspected_connection.set(Some(connection));
                                                inspection_error.set(String::new());
                                            }
                                            Err(reason) => inspection_error.set(reason.0),
                                        }
                                        inspecting.set(None);
                                    });
                                },
                                if inspecting().as_deref() == Some(record.id.as_str()) { "Loading…" } else { "Inspect" }
                            }
                        }
                    }
                }
            }
        }
        if !inspection_error().is_empty() {
            p { class: "form-error", role: "alert", "{inspection_error}" }
        }
        if let Some(operations) = operations()
            && let Some(snapshot) = operations.snapshot.as_option()
            && let Some(summary) = snapshot.summary.as_option()
            && let Some(metrics) = snapshot.metrics.as_option()
        {
            section { class: "panel fleet-list-panel",
                PanelHeader { eyebrow: "Live realm read", title: format!("{} operational snapshot", snapshot.realm_id) }
                p { class: "fleet-scope-label", "Source / " strong { "{operations.source}" } " · observed {format_time(&operations.observed_at)}" }
                section { class: "metric-grid compact",
                    MetricCard { label: "Users", value: summary.users.to_string(), change: format!("{} passkeys", summary.passkeys), tone: "good" }
                    MetricCard { label: "Active sessions", value: summary.active_sessions.to_string(), change: format!("{} recent auth attempts", metrics.authentication_attempts), tone: "good" }
                    MetricCard { label: "Service accounts", value: summary.service_accounts.to_string(), change: format!("{} active", metrics.active_service_accounts), tone: "neutral" }
                    MetricCard { label: "Webhook backlog", value: metrics.webhook_delivery_backlog.to_string(), change: if metrics.backup_healthy { "Backup healthy".to_string() } else { "Backup needs attention".to_string() }, tone: if metrics.backup_healthy { "good".to_string() } else { "warn".to_string() } }
                }
                div { class: "overview-grid",
                    div {
                        h3 { "Recent users" }
                        if let Some(users) = snapshot.users.as_option() {
                            for user in users.users.iter().take(5) {
                                div { class: "posture-row", strong { "{short_id(&user.id)}" } small { {format!("{} identifiers · {} passkeys", user.identifiers.len(), user.passkeys.len())} } }
                            }
                            if users.users.is_empty() { p { class: "form-hint", "No users in this page." } }
                        }
                    }
                    div {
                        h3 { "Recent events" }
                        for event in snapshot.events.iter().rev().take(5) {
                            div { class: "posture-row", strong { "{event.r#type}" } small { "{format_time(&event.occurred_at)}" } }
                        }
                        if snapshot.events.is_empty() { p { class: "form-hint", "No retained events after this cursor." } }
                    }
                }
                div { class: "posture-row", strong { "Signing keys" } small { "{summary.signing_key_state}" } }
                div { class: "posture-row", strong { "Last backup" } small { "{format_time(&summary.latest_backup_at)}" } }
                form { class: "search-panel", onsubmit: move |event| {
                    event.prevent_default();
                    let Some(connection) = inspected_connection() else { return; };
                    let reason = rotation_reason();
                    if reason.trim().len() < 10 { return; }
                    spawn(async move {
                        rotating.set(true);
                        let result = async {
                            fleet_client::step_up_passkey().await?;
                            fleet_client::rotate_connection(&connection, &reason).await
                        }
                        .await;
                        match result {
                            Ok(updated) => {
                                inspected_connection.set(Some(updated));
                                rotation_status.set("Realm connector credential rotated with two-phase recovery fencing.".into());
                                rotation_reason.set(String::new());
                                inspection_error.set(String::new());
                            }
                            Err(reason) => inspection_error.set(reason.0),
                        }
                        rotating.set(false);
                    });
                },
                    h3 { "Connector credential rotation" }
                    p { class: "form-hint", "Stages the new credential, updates the realm, and commits only after both sides agree." }
                    label { "Human reason" input { required: true, minlength: 10, maxlength: 500, value: rotation_reason(), oninput: move |event| rotation_reason.set(event.value()), placeholder: "Why rotation is required" } }
                    button { class: "button secondary", r#type: "submit", disabled: rotating(), if rotating() { "Rotating…" } else { "Step up and rotate" } }
                    if !rotation_status().is_empty() { p { class: "status-badge good", "{rotation_status}" } }
                }
                form { class: "search-panel", onsubmit: move |event| {
                    event.prevent_default();
                    let Some(connection) = inspected_connection() else { return; };
                    if !mutation_confirmed() || mutation_reason().trim().len() < 10 { return; }
                    let operation = match mutation_operation().as_str() {
                        "set-service-account-enabled" => RemoteMutationOperation::SetServiceAccountEnabled,
                        "revoke-service-account-credential" => RemoteMutationOperation::RevokeServiceAccountCredential,
                        "pause-webhook" => RemoteMutationOperation::PauseWebhook,
                        "delete-webhook" => RemoteMutationOperation::DeleteWebhook,
                        _ => RemoteMutationOperation::RevokeUserPasskey,
                    };
                    let target = mutation_target();
                    let secondary = mutation_secondary();
                    let reason = mutation_reason();
                    let enabled = mutation_enabled();
                    spawn(async move {
                        mutating.set(true);
                        let result = async {
                            fleet_client::step_up_passkey().await?;
                            fleet_client::execute_realm_mutation(
                                &connection,
                                operation,
                                &target,
                                &secondary,
                                enabled,
                                &reason,
                            )
                            .await
                        }
                        .await;
                        match result {
                            Ok(result) => {
                                let summary = result
                                    .result
                                    .as_option()
                                    .map(|result| result.summary.clone())
                                    .unwrap_or_else(|| "Remote mutation completed and was centrally audited.".into());
                                mutation_status.set(summary);
                                mutation_confirmed.set(false);
                                inspection_error.set(String::new());
                            }
                            Err(reason) => inspection_error.set(reason.0),
                        }
                        mutating.set(false);
                    });
                },
                    div {
                        label { "Controlled remote operation"
                            select { value: mutation_operation(), onchange: move |event| mutation_operation.set(event.value()),
                                option { value: "revoke-user-passkey", "Revoke user passkey" }
                                option { value: "set-service-account-enabled", "Enable or disable service account" }
                                option { value: "revoke-service-account-credential", "Revoke service-account credential" }
                                option { value: "pause-webhook", "Pause webhook" }
                                option { value: "delete-webhook", "Delete webhook" }
                            }
                        }
                        if mutation_operation() == "set-service-account-enabled" {
                            label { "Desired state"
                                select { value: if mutation_enabled() { "enabled" } else { "disabled" }, onchange: move |event| mutation_enabled.set(event.value() == "enabled"),
                                    option { value: "enabled", "Enabled" }
                                    option { value: "disabled", "Disabled" }
                                }
                            }
                        }
                    }
                    label { "Target ID" input { required: true, maxlength: 1024, value: mutation_target(), oninput: move |event| mutation_target.set(event.value()) } }
                    if matches!(mutation_operation().as_str(), "revoke-user-passkey" | "revoke-service-account-credential") {
                        label { "Credential ID" input { required: true, maxlength: 1024, value: mutation_secondary(), oninput: move |event| mutation_secondary.set(event.value()) } }
                    }
                    label { "Human reason" input { required: true, minlength: 10, maxlength: 500, value: mutation_reason(), oninput: move |event| mutation_reason.set(event.value()), placeholder: "Why this production-safe change is necessary" } }
                    label { class: "form-hint", input { r#type: "checkbox", required: true, checked: mutation_confirmed(), onchange: move |event| mutation_confirmed.set(event.checked()) } " I confirm the target and understand this is audited in Fleet and the realm." }
                    button { class: "button primary", r#type: "submit", disabled: mutating(), if mutating() { "Applying…" } else { "Step up and apply" } }
                }
                if !mutation_status().is_empty() { p { class: "status-badge good", "{mutation_status}" } }
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
    let mut outbound = use_signal(|| false);
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
                        FleetDialogKind::Connection => FleetMutation::Connection { endpoint: endpoint(), pairing_code: pairing_code(), outbound: outbound() },
                    };
                    on_submit.call(mutation);
                },
                    if kind == FleetDialogKind::Connection {
                        label { "Connection mode"
                            select { value: if outbound() { "outbound" } else { "public" }, onchange: move |event| outbound.set(event.value() == "outbound"),
                                option { value: "public", "Public realm endpoint" }
                                option { value: "outbound", "Private outbound connector" }
                            }
                        }
                        if !outbound() {
                            label { "Management endpoint" input { r#type: "url", required: true, value: endpoint(), oninput: move |event| endpoint.set(event.value()) } }
                        }
                        label { "Single-use pairing code" input { r#type: "password", required: !preview, placeholder: if preview { "Optional in preview" } else { "rpair_…" }, value: pairing_code(), oninput: move |event| pairing_code.set(event.value()) } }
                        p { class: "form-hint",
                            if outbound() {
                                "Fleet stores only the code digest. Complete the returned attempt from the private realm host; no inbound realm route is required."
                            } else {
                                "The code is sent to the realm once and is never stored by this dashboard."
                            }
                        }
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
                                let height = ((height + 2) / 5 * 5).clamp(5, 100);
                                rsx! {
                                    span {
                                        class: "bar-height-{height}",
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
            for user in users {
                {
                    let selected_user = user.clone();
                    rsx! {
                        button {
                            r#type: "button",
                            class: "table-row",
                            aria_label: "Open {user.name} account",
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AnalyticsPresentationState {
    Loading,
    Forbidden,
    Error,
    Disabled,
    Unsupported,
    Stale,
    Partial,
    Empty,
    Ready,
}

fn analytics_presentation_state(
    has_organization: bool,
    loading: bool,
    error: &str,
    overview: &AnalyticsOverview,
    policy: &AnalyticsPolicy,
    series_points: usize,
) -> AnalyticsPresentationState {
    if loading {
        return AnalyticsPresentationState::Loading;
    }
    if !error.is_empty() {
        let message = error.to_ascii_lowercase();
        return if ["forbidden", "permission", "not authorized", "unauthorized"]
            .iter()
            .any(|needle| message.contains(needle))
        {
            AnalyticsPresentationState::Forbidden
        } else {
            AnalyticsPresentationState::Error
        };
    }
    if !has_organization {
        return AnalyticsPresentationState::Empty;
    }
    if !policy.enabled {
        return AnalyticsPresentationState::Disabled;
    }
    let coverage = overview.coverage.first().cloned().unwrap_or_default();
    if coverage.unsupported_realms > 0 && coverage.expected_realms == 0 {
        return AnalyticsPresentationState::Unsupported;
    }
    if coverage.stale_realms > 0 {
        return AnalyticsPresentationState::Stale;
    }
    if coverage.partial {
        return AnalyticsPresentationState::Partial;
    }
    if !overview.authentication.is_set() && series_points == 0 {
        return AnalyticsPresentationState::Empty;
    }
    AnalyticsPresentationState::Ready
}

#[component]
fn FleetAnalyticsPage(
    organization_id: String,
    project_id: String,
    environment_id: String,
    projects: Vec<FleetProject>,
    environments: Vec<FleetEnvironment>,
    connections: Vec<RealmConnection>,
) -> Element {
    let has_organization = !organization_id.is_empty();
    let mut period_seconds = use_signal(|| 86_400_i64);
    let mut analytics = use_signal(AnalyticsOverview::default);
    let mut series = use_signal(MetricSeries::default);
    let mut funnel = use_signal(AuthenticationFunnel::default);
    let mut failures = use_signal(FailureBreakdown::default);
    let mut policy = use_signal(AnalyticsPolicy::default);
    let mut comparison = use_signal(CompareScopesResponse::default);
    let mut mutating_policy = use_signal(|| false);
    let mut policy_status = use_signal(String::new);
    let mut loading = use_signal(|| true);
    let mut error = use_signal(String::new);

    use_effect(move || {
        let period = period_seconds();
        let organization_id = organization_id.clone();
        let project_id = project_id.clone();
        let environment_id = environment_id.clone();
        let projects = projects.clone();
        let environments = environments.clone();
        let connections = connections.clone();
        spawn(async move {
            if organization_id.is_empty() {
                analytics.set(AnalyticsOverview::default());
                error.set(String::new());
                loading.set(false);
                return;
            }
            loading.set(true);
            let project = (!project_id.is_empty()).then_some(project_id.as_str());
            let environment = (!environment_id.is_empty()).then_some(environment_id.as_str());
            let result = async {
                let overview = fleet_client::analytics_overview(
                    &organization_id,
                    project,
                    environment,
                    None,
                    period,
                )
                .await?;
                let volume = fleet_client::analytics_series(
                    &organization_id,
                    project,
                    environment,
                    None,
                    period,
                    AnalyticsMetric::AuthenticationAttempts,
                )
                .await?;
                let registration_funnel = fleet_client::analytics_funnel(
                    &organization_id,
                    project,
                    environment,
                    None,
                    period,
                )
                .await?;
                let failure_breakdown = fleet_client::analytics_failures(
                    &organization_id,
                    project,
                    environment,
                    None,
                    period,
                )
                .await?;
                let organization_policy = fleet_client::analytics_policy(&organization_id).await?;
                let scopes = comparison_scopes(
                    &organization_id,
                    &project_id,
                    &environment_id,
                    &projects,
                    &environments,
                    &connections,
                );
                let scope_comparison = if scopes.len() >= 2 {
                    fleet_client::analytics_compare(scopes, period).await?
                } else {
                    CompareScopesResponse::default()
                };
                Ok::<_, fleet_client::ClientError>((
                    overview,
                    volume,
                    registration_funnel,
                    failure_breakdown,
                    organization_policy,
                    scope_comparison,
                ))
            }
            .await;
            match result {
                Ok((
                    overview,
                    volume,
                    registration_funnel,
                    failure_breakdown,
                    organization_policy,
                    scope_comparison,
                )) => {
                    analytics.set(overview);
                    series.set(volume);
                    funnel.set(registration_funnel);
                    failures.set(failure_breakdown);
                    policy.set(organization_policy);
                    comparison.set(scope_comparison);
                    error.set(String::new());
                }
                Err(reason) => error.set(reason.0),
            }
            loading.set(false);
        });
    });

    let snapshot = analytics();
    let authentication = snapshot
        .authentication
        .as_option()
        .cloned()
        .unwrap_or_default();
    let coverage = snapshot.coverage.first().cloned().unwrap_or_default();
    let success_rate = percentage(
        authentication.success_rate_numerator,
        authentication.success_rate_denominator,
    );
    let chart_points = series().points;
    let funnel_snapshot = funnel();
    let failures_snapshot = failures();
    let comparison_snapshot = comparison();
    let maximum_attempts = chart_points
        .iter()
        .map(|point| point.numerator)
        .max()
        .unwrap_or(1)
        .max(1);
    let policy_snapshot = policy();
    let presentation_state = analytics_presentation_state(
        has_organization,
        loading(),
        &error(),
        &snapshot,
        &policy_snapshot,
        chart_points.len(),
    );
    let authentication_available = snapshot.authentication.is_set();
    let attempts_value = if authentication_available {
        authentication.attempts.to_string()
    } else {
        "Unavailable".into()
    };
    let success_rate_value = if authentication_available {
        format!("{success_rate}%")
    } else {
        "Unavailable".into()
    };
    let reporting_value = if coverage.total_realms > 0 {
        format!(
            "{} / {}",
            coverage.reporting_realms, coverage.expected_realms
        )
    } else {
        "Unavailable".into()
    };

    rsx! {
        div { class: "content-stack",
            section { class: "page-heading",
                div {
                    p { class: "eyebrow", "Fleet Analytics V1" }
                    h2 { "Hierarchy analytics" }
                    p { "Authorized, identity-free rollups with explicit coverage, bounded failures, and policy status." }
                }
                div { class: "segmented",
                    for (label, seconds) in [("24 hours", 86_400_i64), ("7 days", 604_800_i64), ("28 days", 2_419_200_i64)] {
                        button {
                            r#type: "button",
                            class: if period_seconds() == seconds { "active" } else { "" },
                            onclick: move |_| period_seconds.set(seconds),
                            "{label}"
                        }
                    }
                }
            }
            if presentation_state == AnalyticsPresentationState::Forbidden {
                div { class: "fleet-alert", role: "alert", Icon { icon: TablerIcon::AlertTriangle, size: 17 } span { "You do not have permission to view analytics for this hierarchy." } }
            } else if presentation_state == AnalyticsPresentationState::Error {
                div { class: "fleet-alert", role: "alert", Icon { icon: TablerIcon::AlertTriangle, size: 17 } span { "{error}" } }
            }
            if presentation_state == AnalyticsPresentationState::Loading {
                div { class: "fleet-loading", span {} "Loading canonical Fleet analytics…" }
            }
            if presentation_state == AnalyticsPresentationState::Disabled {
                div { class: "fleet-alert", role: "status", Icon { icon: TablerIcon::InfoCircle, size: 17 } span { "Central analytics is disabled by organization policy. Realm authentication and Fleet management remain available." } }
            } else if presentation_state == AnalyticsPresentationState::Unsupported {
                div { class: "fleet-alert", role: "status", Icon { icon: TablerIcon::InfoCircle, size: 17 } span { "The realms in this hierarchy do not advertise Fleet Analytics V1." } }
            } else if presentation_state == AnalyticsPresentationState::Stale {
                div { class: "fleet-alert", role: "status", Icon { icon: TablerIcon::AlertTriangle, size: 17 } span { "Stale result: {coverage.stale_realms} expected realm(s) missed the last complete window." } }
            } else if presentation_state == AnalyticsPresentationState::Partial {
                div { class: "fleet-alert", role: "status",
                    Icon { icon: TablerIcon::AlertTriangle, size: 17 }
                    span { "Partial result: {coverage.reporting_realms} reporting, {coverage.stale_realms} stale, {coverage.disabled_realms} disabled, {coverage.unsupported_realms} unsupported." }
                }
            } else if presentation_state == AnalyticsPresentationState::Empty {
                div { class: "empty-state", role: "status", p { "No analytics sources are available for the selected hierarchy and window." } }
            }
            section { class: "metric-grid metrics-full",
                MetricCard { label: "Authentication attempts", value: attempts_value, change: "Selected hierarchy", tone: "neutral" }
                MetricCard { label: "Success rate", value: success_rate_value, change: "Ratio of summed counts", tone: if authentication_available && success_rate >= 95 { "good" } else if authentication_available { "warning" } else { "neutral" } }
                MetricCard { label: "Reporting realms", value: reporting_value, change: "Registry-derived coverage", tone: if coverage.total_realms > 0 && coverage.reporting_realms == coverage.expected_realms { "good" } else if coverage.total_realms > 0 { "warning" } else { "neutral" } }
                MetricCard { label: "Authentication p95", value: if authentication.latency_p95_available { format!("{} ms", authentication.latency_p95_upper_bound_milliseconds) } else { "Unavailable".into() }, change: "Merged histogram", tone: "neutral" }
            }
            div { class: "overview-grid metrics-grid",
                section { class: "panel volume-panel",
                    PanelHeader { eyebrow: "Authentication attempts", title: "Effective-granularity volume" }
                    if chart_points.is_empty() {
                        div { class: "empty-state", p { "No reporting realm supplied this metric in the selected window." } }
                    } else {
                        div { class: "bar-chart tall", aria_label: "Fleet authentication attempts over time",
                            for point in chart_points {
                                {
                                    let height = point.numerator.saturating_mul(100).div_ceil(maximum_attempts) as u16;
                                    let height = ((height.max(5) + 2) / 5 * 5).min(100);
                                    let title = format!("{} · {}", format_millisecond_time(point.starts_at_unix_milliseconds), point.numerator);
                                    rsx! { span { class: "bar-height-{height}", title: "{title}" } }
                                }
                            }
                        }
                    }
                    div { class: "chart-legend",
                        span { i { class: "copper" } "{snapshot.source}" }
                        strong { "{success_rate}% success" }
                    }
                }
                section { class: "panel",
                    PanelHeader { eyebrow: "Registration", title: "Bounded funnel" }
                    if funnel_snapshot.stages.is_empty() {
                        div { class: "empty-state", p { "Registration telemetry is unavailable for this scope." } }
                    } else {
                        for stage in funnel_snapshot.stages {
                            LiveFunnelRow { label: stage.stage, value: stage.count, percent: percentage(stage.count, authentication.attempts.max(1)) }
                        }
                    }
                }
            }
            div { class: "overview-grid metrics-grid",
                section { class: "panel",
                    PanelHeader { eyebrow: "Failure contribution", title: "Bounded failure classes" }
                    if failures_snapshot.failures.is_empty() {
                        div { class: "empty-state", p { "No classified authentication failures were reported." } }
                    } else {
                        for failure in failures_snapshot.failures {
                            LiveFunnelRow {
                                label: failure_label(failure.failure_class.as_known()),
                                value: failure.count,
                                percent: (failure.contribution * 100.0).round().clamp(0.0, 100.0) as u16,
                            }
                        }
                    }
                }
                section { class: "panel",
                    PanelHeader { eyebrow: "Organization policy", title: "Retention and residency" }
                    div { class: "connection-list",
                        article { class: "connection-row",
                            div { strong { "Central analytics" } small { "Organization-controlled" } }
                            span { class: if policy_snapshot.enabled { "status-badge good" } else { "status-badge warn" }, if policy_snapshot.enabled { "Enabled" } else { "Disabled" } }
                            small { "{policy_snapshot.canonical_retention_days} day canonical retention" }
                        }
                        article { class: "connection-row",
                            div { strong { "Residency" } small { "Archive path remains policy-bound" } }
                            span { class: "status-badge", "{residency_label(policy_snapshot.residency_mode.as_known())}" }
                            small { "{policy_snapshot.max_buckets_per_minute_per_realm} buckets/minute/realm" }
                        }
                    }
                    button {
                        r#type: "button",
                        class: "button secondary",
                        disabled: mutating_policy(),
                        onclick: move |_| {
                            let current = policy();
                            mutating_policy.set(true);
                            policy_status.set(String::new());
                            spawn(async move {
                                match fleet_client::update_analytics_policy(&current, !current.enabled).await {
                                    Ok(updated) => {
                                        let state = if updated.enabled { "enabled" } else { "disabled" };
                                        policy.set(updated);
                                        policy_status.set(format!("Central analytics {state}."));
                                    }
                                    Err(reason) => policy_status.set(reason.0),
                                }
                                mutating_policy.set(false);
                            });
                        },
                        if mutating_policy() { "Saving…" } else if policy_snapshot.enabled { "Disable central analytics" } else { "Enable central analytics" }
                    }
                    if !policy_status().is_empty() {
                        p { class: "field-hint", role: "status", "{policy_status}" }
                    }
                }
            }
            section { class: "panel",
                PanelHeader { eyebrow: "Sibling comparison", title: "Trace contribution within the selected hierarchy" }
                if comparison_snapshot.comparisons.is_empty() {
                    div { class: "empty-state", p { "Select a hierarchy level with at least two children to compare contribution." } }
                } else {
                    div { class: "connection-list",
                        for item in comparison_snapshot.comparisons {
                            {
                                let scope = item.scope.as_option().cloned().unwrap_or_default();
                                let metrics = item.authentication.as_option().cloned().unwrap_or_default();
                                let rate = percentage(metrics.success_rate_numerator, metrics.success_rate_denominator);
                                let label = comparison_scope_label(&scope);
                                rsx! {
                                    article { class: "connection-row",
                                        div { strong { "{label}" } small { "Authorized sibling scope" } }
                                        span { class: "status-badge", "{metrics.attempts} attempts" }
                                        small { "{rate}% success" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            section { class: "panel",
                PanelHeader { eyebrow: "Coverage", title: "Missing telemetry is never rendered as zero" }
                div { class: "connection-list",
                    article { class: "connection-row",
                        div { strong { "Expected" } small { "Reporting + stale" } }
                        span { class: "status-badge", "{coverage.expected_realms}" }
                        small { "Total registry scope: {coverage.total_realms}" }
                    }
                    article { class: "connection-row",
                        div { strong { "Last complete window" } small { "Minimum across reporting realms" } }
                        span { class: if coverage.last_complete_window_start_unix_milliseconds > 0 { "status-badge good" } else { "status-badge warn" },
                            "{format_millisecond_time(coverage.last_complete_window_start_unix_milliseconds)}"
                        }
                        small { "Disabled: {coverage.disabled_realms} · Unsupported: {coverage.unsupported_realms}" }
                    }
                }
            }
        }
    }
}

fn format_millisecond_time(value: i64) -> String {
    time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(value).saturating_mul(1_000_000))
        .ok()
        .and_then(|value| {
            value
                .format(&time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "Unavailable".into())
}

fn failure_label(
    value: Option<crate::proto::rustyauth::analytics::v1::FailureClass>,
) -> &'static str {
    use crate::proto::rustyauth::analytics::v1::FailureClass;
    match value {
        Some(FailureClass::InvalidCredential) => "Invalid credential",
        Some(FailureClass::ChallengeExpired) => "Challenge expired",
        Some(FailureClass::OriginRejected) => "Origin rejected",
        Some(FailureClass::PolicyDenied) => "Policy denied",
        Some(FailureClass::RateLimited) => "Rate limited",
        Some(FailureClass::StoreUnavailable) => "Store unavailable",
        Some(FailureClass::UpstreamUnavailable) => "Upstream unavailable",
        Some(FailureClass::Internal) => "Internal",
        Some(FailureClass::Other) => "Other",
        _ => "Unknown",
    }
}

fn residency_label(
    value: Option<crate::proto::rustyauth::analytics::v1::AnalyticsResidencyMode>,
) -> &'static str {
    use crate::proto::rustyauth::analytics::v1::AnalyticsResidencyMode;
    match value {
        Some(AnalyticsResidencyMode::RollupsOnly) => "Rollups only",
        Some(AnalyticsResidencyMode::CustomerOwnedArchive) => "Customer-owned archive",
        Some(AnalyticsResidencyMode::CentralLandingArchive) => "Central landing archive",
        _ => "Unspecified",
    }
}

fn comparison_scopes(
    organization_id: &str,
    project_id: &str,
    environment_id: &str,
    projects: &[FleetProject],
    environments: &[FleetEnvironment],
    connections: &[RealmConnection],
) -> Vec<AnalyticsScope> {
    if !environment_id.is_empty() {
        return connections
            .iter()
            .filter(|connection| connection.environment_id == environment_id)
            .take(8)
            .map(|connection| AnalyticsScope {
                kind: AnalyticsScopeKind::Realm.into(),
                organization_id: organization_id.into(),
                project_id: project_id.into(),
                environment_id: environment_id.into(),
                connection_id: connection.id.clone(),
                ..Default::default()
            })
            .collect();
    }
    if !project_id.is_empty() {
        return environments
            .iter()
            .filter(|environment| environment.project_id == project_id)
            .take(8)
            .map(|environment| AnalyticsScope {
                kind: AnalyticsScopeKind::Environment.into(),
                organization_id: organization_id.into(),
                project_id: project_id.into(),
                environment_id: environment.id.clone(),
                ..Default::default()
            })
            .collect();
    }
    projects
        .iter()
        .filter(|project| project.organization_id == organization_id)
        .take(8)
        .map(|project| AnalyticsScope {
            kind: AnalyticsScopeKind::Project.into(),
            organization_id: organization_id.into(),
            project_id: project.id.clone(),
            ..Default::default()
        })
        .collect()
}

fn comparison_scope_label(scope: &AnalyticsScope) -> String {
    match scope.kind.as_known() {
        Some(AnalyticsScopeKind::Project) => format!("Project {}", short_id(&scope.project_id)),
        Some(AnalyticsScopeKind::Environment) => {
            format!("Environment {}", short_id(&scope.environment_id))
        }
        Some(AnalyticsScopeKind::Realm) => format!("Realm {}", short_id(&scope.connection_id)),
        Some(AnalyticsScopeKind::Organization) => {
            format!("Organization {}", short_id(&scope.organization_id))
        }
        Some(AnalyticsScopeKind::Fleet) => "Fleet".into(),
        _ => "Unknown scope".into(),
    }
}

#[cfg(test)]
mod analytics_presentation_tests {
    use super::{AnalyticsPresentationState, analytics_presentation_state};
    use crate::proto::rustyauth::analytics::v1::{
        AnalyticsOverview, AnalyticsPolicy, AuthenticationAggregate, ReportingCoverage,
    };

    fn enabled_policy() -> AnalyticsPolicy {
        AnalyticsPolicy {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn analytics_states_never_collapse_missing_or_denied_data_into_zero() {
        let policy = enabled_policy();
        let empty = AnalyticsOverview::default();
        assert_eq!(
            analytics_presentation_state(true, true, "", &empty, &policy, 0),
            AnalyticsPresentationState::Loading
        );
        assert_eq!(
            analytics_presentation_state(true, false, "Permission denied", &empty, &policy, 0),
            AnalyticsPresentationState::Forbidden
        );
        assert_eq!(
            analytics_presentation_state(true, false, "", &empty, &policy, 0),
            AnalyticsPresentationState::Empty
        );

        let mut disabled = policy.clone();
        disabled.enabled = false;
        assert_eq!(
            analytics_presentation_state(true, false, "", &empty, &disabled, 0),
            AnalyticsPresentationState::Disabled
        );

        let mut unsupported = empty.clone();
        unsupported.coverage.push(ReportingCoverage {
            total_realms: 2,
            unsupported_realms: 2,
            ..Default::default()
        });
        assert_eq!(
            analytics_presentation_state(true, false, "", &unsupported, &policy, 0),
            AnalyticsPresentationState::Unsupported
        );

        let mut partial = empty.clone();
        partial.coverage.push(ReportingCoverage {
            total_realms: 2,
            expected_realms: 2,
            reporting_realms: 1,
            partial: true,
            ..Default::default()
        });
        assert_eq!(
            analytics_presentation_state(true, false, "", &partial, &policy, 1),
            AnalyticsPresentationState::Partial
        );

        let mut stale = partial.clone();
        stale.coverage[0].stale_realms = 1;
        assert_eq!(
            analytics_presentation_state(true, false, "", &stale, &policy, 1),
            AnalyticsPresentationState::Stale
        );

        let mut ready = empty;
        ready.authentication = AuthenticationAggregate::default().into();
        assert_eq!(
            analytics_presentation_state(true, false, "", &ready, &policy, 1),
            AnalyticsPresentationState::Ready
        );
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
                                let height = ((height + 2) / 5 * 5).clamp(5, 100);
                                rsx! { span { class: "bar-height-{height}", title: "{index}:00 · {value}" } }
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
fn BenchmarksPage() -> Element {
    let Ok(catalogue) = benchmarks::catalogue() else {
        return rsx! {
            section { class: "panel empty-panel",
                h2 { "Benchmark catalogue unavailable" }
                p { "The embedded release evidence did not pass its schema contract." }
            }
        };
    };
    let Some(realm) = catalogue
        .programs
        .iter()
        .find(|program| program.id == "single-realm-capacity")
        .cloned()
    else {
        return rsx! {
            section { class: "panel empty-panel", h2 { "Single-realm benchmark programme unavailable" } }
        };
    };
    let realm_report_count = catalogue
        .reports
        .iter()
        .filter(|report| report.program_id == realm.id)
        .count();
    let primary_chart = catalogue
        .reports
        .iter()
        .find(|report| report.program_id == realm.id && report.status == "passed")
        .and_then(|report| report.charts.first())
        .cloned();
    let state_label = if realm.state == "awaiting-baseline" {
        "Awaiting first baseline"
    } else {
        "Active"
    };

    rsx! {
        div { class: "content-stack benchmark-console",
            section { class: "page-heading",
                div {
                    p { class: "eyebrow", "Release evidence" }
                    h2 { "Capacity & latency benchmarks" }
                    p { "Published synthetic evidence from the isolated benchmark project, tied to explicit datasets, resource ceilings and release artifacts." }
                }
                a {
                    class: "button secondary",
                    href: "https://rustyauth.dev/benchmarks/",
                    target: "_blank",
                    rel: "noreferrer",
                    "Public benchmark page "
                    Icon { icon: TablerIcon::ArrowUpRight, size: 17 }
                }
            }

            section { class: "benchmark-console-summary",
                article { class: "panel benchmark-console-state",
                    span { class: if realm.state == "awaiting-baseline" { "status-badge warn" } else { "status-badge good" }, i {} "{state_label}" }
                    strong { "{realm_report_count}" }
                    small { "published single-realm runs" }
                    p { "{realm.summary}" }
                }
                article { class: "panel benchmark-console-policy",
                    PanelHeader { eyebrow: "Isolation boundary", title: "Not part of customer installs" }
                    p { "{catalogue.publication_policy.isolation}" }
                    div { class: "benchmark-console-meta",
                        span { "Schema" strong { "v{catalogue.schema_version}" } }
                        span { "Updated" strong { "{catalogue.updated_at}" } }
                    }
                }
            }

            section { class: "panel benchmark-console-decision",
                PanelHeader { eyebrow: "Decision brief", title: "Measured, modelled and not yet proven" }
                p { class: "benchmark-console-headline", "{realm.decision_guide.headline}" }
                div { class: "benchmark-console-confidence-grid",
                    article { class: "measured", small { "Measured" } h4 { "Safe for decisions" } p { "{realm.decision_guide.measured}" } }
                    article { class: "modelled", small { "Modelled" } h4 { "Assumptions apply" } p { "{realm.decision_guide.inferred}" } }
                    article { class: "unproven", small { "Not demonstrated" } h4 { "Do not claim yet" } p { "{realm.decision_guide.not_demonstrated}" } }
                }
            }

            section { class: "panel benchmark-console-enterprise",
                PanelHeader { eyebrow: "Enterprise profile v2", title: "High-traffic product journey" }
                p { "{realm.enterprise_profile.timing}" }
                div { class: "benchmark-console-mix",
                    for item in realm.enterprise_profile.mix {
                        article {
                            strong { "{item.percent}%" }
                            span { "{item.operation}" }
                            meter { min: 0, max: 100, value: item.percent, "{item.percent}%" }
                        }
                    }
                }
            }

            if let Some(chart) = primary_chart {
                section { class: "panel benchmark-console-chart",
                    PanelHeader { eyebrow: "Measured curve", title: chart.title.clone() }
                    p { "{chart.description}" }
                    div { class: "benchmark-console-chart-legend",
                        span { "{chart.y_unit} by {chart.x_unit}" }
                        for series in chart.series {
                            article {
                                strong { "{series.name}" }
                                div {
                                    for point in series.points {
                                        span {
                                            title: format!("{} {} · {:.1} {}", point.x, chart.x_unit, point.y, chart.y_unit),
                                            i { style: format!("height: {}%", (point.y / 150.0 * 100.0).clamp(2.0, 100.0)) }
                                            small { "{format_benchmark_value(point.x)}" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            section { class: "panel",
                PanelHeader { eyebrow: "Qualified shapes", title: "Single-writer realm tiers" }
                div { class: "benchmark-console-tier-grid",
                    for tier in realm.resource_tiers {
                        article {
                            span { "{tier.name}" }
                            strong { "{format_grouped_u64(tier.dataset_accounts)}" }
                            small { "seeded accounts" }
                            dl {
                                div { dt { "Realm API" } dd { "{tier.api}" } }
                                div { dt { "SableDB" } dd { "{tier.sable_db}" } }
                            }
                        }
                    }
                }
            }

            section { class: "panel",
                PanelHeader { eyebrow: "User translation", title: "Active-user workload profiles" }
                div { class: "benchmark-console-profile-grid",
                    for profile in realm.user_profiles {
                        article {
                            strong { "{profile.requests_per_minute}" span { " / minute" } }
                            h4 { "{profile.name}" }
                            p { "{profile.description}" }
                        }
                    }
                }
                code { class: "benchmark-console-formula", "active users = sustainable authenticated RPS × 60 × 0.70 ÷ requests per user per minute" }
            }

            section { class: "panel benchmark-console-gates",
                PanelHeader { eyebrow: "Promotion policy", title: "Required publication gates" }
                ol {
                    for (index, gate) in realm.gates.iter().enumerate() {
                        li { span { "{index + 1:02}" } "{gate}" }
                    }
                }
            }

            section { class: "panel benchmark-console-reports",
                PanelHeader { eyebrow: "Retained evidence", title: format!("{} published reports", catalogue.reports.len()) }
                for report in catalogue.reports {
                    article {
                        header {
                            div { small { "{report.qualification}" } h3 { "{report.title}" } }
                            span { class: if report.status == "passed" { "status-badge good" } else { "status-badge warn" }, i {} "{report.status}" }
                        }
                        p { "{report.summary}" }
                        div { class: "benchmark-console-result-grid",
                            for result in report.results {
                                div {
                                    small { "{result.label}" }
                                    strong { "{format_benchmark_value(result.value)} " span { "{result.unit}" } }
                                    em { "{result.threshold} · {result.outcome}" }
                                }
                            }
                            for datum in report.dataset {
                                div {
                                    small { "{datum.label}" }
                                    strong { "{format_benchmark_value(datum.value)} " span { "{datum.unit}" } }
                                    em { "Measured dataset" }
                                }
                            }
                        }
                        footer {
                            span { "{report.release} · {report.environment} · methodology {report.methodology_version}" }
                            nav {
                                for evidence in report.evidence {
                                    a { href: "{evidence.url}", target: "_blank", rel: "noreferrer", "{evidence.label} ↗" }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

fn format_grouped_u64(value: u64) -> String {
    let raw = value.to_string();
    let mut grouped = String::with_capacity(raw.len() + raw.len() / 3);
    for (index, character) in raw.chars().enumerate() {
        if index > 0 && (raw.len() - index).is_multiple_of(3) {
            grouped.push(',');
        }
        grouped.push(character);
    }
    grouped
}

fn format_benchmark_value(value: f64) -> String {
    if value.fract() == 0.0 && value <= u64::MAX as f64 {
        format_grouped_u64(value as u64)
    } else {
        format!("{value:.4}").trim_end_matches('0').to_owned()
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
