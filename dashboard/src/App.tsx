import { createQuery } from "@tanstack/solid-query";
import { connectQueryOptions } from "@rustyauth/connect-solid";
import { OrganizationService, ServiceAccountService } from "@rustyauth/protocol";
import {
  TbOutlineAlertTriangle,
  TbOutlineArrowUpRight,
  TbOutlineBuilding,
  TbOutlineChartHistogram,
  TbOutlineCheck,
  TbOutlineChevronRight,
  TbOutlineClipboard,
  TbOutlineCopy,
  TbOutlineDatabase,
  TbOutlineDots,
  TbOutlineKey,
  TbOutlineLayoutDashboard,
  TbOutlineLogout,
  TbOutlineMenu2,
  TbOutlinePlus,
  TbOutlineRefresh,
  TbOutlineSearch,
  TbOutlineShieldCheck,
  TbOutlineUserCircle,
  TbOutlineUsers,
  TbOutlineWebhook,
  TbOutlineX,
} from "solid-icons/tb";
import {
  type Component,
  createMemo,
  createSignal,
  For,
  Match,
  onCleanup,
  onMount,
  Show,
  Switch,
} from "solid-js";
import {
  createServiceAccount,
  createServiceCredential,
  getCurrentOperator,
  getOrganization,
  listServiceAccounts,
  revokeServiceCredential,
  searchUsers,
  signInWithPasskey,
  updateOrganization,
} from "./api.ts";
import {
  authVolume,
  previewMetrics,
  previewOperator,
  previewOrganization,
  previewServiceAccounts,
  previewUsers,
  previewWebhooks,
} from "./fixtures.ts";
import type {
  NavKey,
  OperatorView,
  OrganizationView,
  ServiceAccountView,
  UserView,
  WebhookView,
} from "./models.ts";

type IconComponent = Component<
  { size?: number | string; strokeWidth?: number | string }
>;

const navItems: Array<{ key: NavKey; label: string; icon: IconComponent }> = [
  { key: "overview", label: "Overview", icon: TbOutlineLayoutDashboard },
  { key: "users", label: "Users", icon: TbOutlineUsers },
  { key: "organization", label: "Organization", icon: TbOutlineBuilding },
  { key: "service-accounts", label: "Service accounts", icon: TbOutlineKey },
  { key: "webhooks", label: "Webhooks", icon: TbOutlineWebhook },
  { key: "metrics", label: "Metrics", icon: TbOutlineChartHistogram },
];

const serviceScopes = [
  "identity.read",
  "identity.write",
  "events.read",
  "metrics.read",
  "webhooks.manage",
];

const webhookEvents = [
  "user.created",
  "user.updated",
  "user.disabled",
  "session.created",
  "session.revoked",
  "passkey.registered",
  "passkey.removed",
  "passkey.challenge.failed",
  "operator.session.created",
  "service_account.created",
  "service_account.credential.created",
  "service_account.credential.revoked",
];

function useDialogSurface(
  panel: () => HTMLElement | undefined,
  initialFocus: () => HTMLElement | undefined,
  onClose: () => void,
) {
  onMount(() => {
    const previouslyFocused = document.activeElement as HTMLElement | null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }

      const currentPanel = panel();
      if (event.key !== "Tab" || !currentPanel) return;
      const focusable = Array.from(
        currentPanel.querySelectorAll<HTMLElement>(
          "button:not([disabled]), a[href], input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])",
        ),
      ).filter((element) => !element.hasAttribute("hidden"));
      const first = focusable.at(0);
      const last = focusable.at(-1);
      if (!first || !last) return;

      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    requestAnimationFrame(() => initialFocus()?.focus());

    onCleanup(() => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
      requestAnimationFrame(() => previouslyFocused?.focus());
    });
  });
}

export default function App() {
  const searchParams = new URLSearchParams(globalThis.location.search);
  const preview = searchParams.get("preview") === "1";
  const loginVariant = searchParams.get("login");
  const [active, setActive] = createSignal<NavKey>("overview");
  const [mobileNav, setMobileNav] = createSignal(false);
  const [signInEmail, setSignInEmail] = createSignal("admin@rustyauth.local");
  const [signInError, setSignInError] = createSignal("");
  const [signingIn, setSigningIn] = createSignal(false);

  const operatorQuery = createQuery(() =>
    connectQueryOptions({
      service: OrganizationService.typeName,
      method: "GetCurrentOperator",
      input: {},
      enabled: !preview,
      staleTime: 30_000,
      call: (_input, signal) => getCurrentOperator(signal),
    })
  );
  const organizationQuery = createQuery(() =>
    connectQueryOptions({
      service: OrganizationService.typeName,
      method: "GetOrganization",
      input: {},
      enabled: !preview && operatorQuery.isSuccess,
      staleTime: 30_000,
      call: (_input, signal) => getOrganization(signal),
    })
  );
  const serviceAccountsQuery = createQuery(() =>
    connectQueryOptions({
      service: ServiceAccountService.typeName,
      method: "ListServiceAccounts",
      input: { pageSize: 100 },
      enabled: !preview && operatorQuery.isSuccess,
      staleTime: 15_000,
      call: (_input, signal) => listServiceAccounts(signal),
    })
  );

  const [previewOrganizationState, setPreviewOrganizationState] = createSignal(
    previewOrganization,
  );
  const [previewAccounts, setPreviewAccounts] = createSignal(
    previewServiceAccounts,
  );
  const operator = (): OperatorView | undefined => preview ? previewOperator : operatorQuery.data;
  const organization = (): OrganizationView | undefined =>
    preview ? previewOrganizationState() : organizationQuery.data;
  const accounts = (): ServiceAccountView[] => preview ? previewAccounts() : serviceAccountsQuery.data ?? [];

  async function passkeySignIn(event: SubmitEvent) {
    event.preventDefault();
    setSignInError("");
    setSigningIn(true);
    try {
      await signInWithPasskey(signInEmail());
      await operatorQuery.refetch();
    } catch (error) {
      setSignInError(
        error instanceof Error ? error.message : "Passkey sign-in failed.",
      );
    } finally {
      setSigningIn(false);
    }
  }

  function openPreview() {
    const url = new URL(globalThis.location.href);
    url.searchParams.set("preview", "1");
    globalThis.location.assign(url);
  }

  async function signOut() {
    if (preview) {
      globalThis.location.assign("/");
      return;
    }
    await fetch("/v1/sign-out", { method: "POST", credentials: "include" });
    await operatorQuery.refetch();
  }

  const pageTitle = createMemo(() => navItems.find((item) => item.key === active())?.label ?? "Overview");

  return (
    <Switch>
      <Match when={!preview && operatorQuery.isPending}>
        <LoadingScreen />
      </Match>
      <Match when={!preview && operatorQuery.isError}>
        <Show
          when={loginVariant === "aperture"}
          fallback={
            <SignInScreen
              email={signInEmail()}
              error={signInError()}
              pending={signingIn()}
              onEmail={setSignInEmail}
              onSubmit={passkeySignIn}
              onPreview={openPreview}
            />
          }
        >
          <ApertureSignInScreen
            email={signInEmail()}
            error={signInError()}
            pending={signingIn()}
            onEmail={setSignInEmail}
            onSubmit={passkeySignIn}
            onPreview={openPreview}
          />
        </Show>
      </Match>
      <Match when={operator()}>
        <div class="app-shell">
          <Show when={mobileNav()}>
            <button
              type="button"
              class="mobile-nav-scrim"
              aria-label="Close navigation"
              onClick={() => setMobileNav(false)}
            />
          </Show>
          <Sidebar
            active={active()}
            mobileOpen={mobileNav()}
            operator={operator()!}
            preview={preview}
            onNavigate={(key) => {
              setActive(key);
              setMobileNav(false);
            }}
            onSignOut={signOut}
          />
          <main class="main-stage">
            <Topbar
              title={pageTitle()}
              operator={operator()!}
              preview={preview}
              onMenu={() => setMobileNav(!mobileNav())}
              onNavigate={setActive}
              onSignOut={signOut}
            />
            <div class="page-canvas">
              <Show when={preview}>
                <PreviewBanner />
              </Show>
              <Switch>
                <Match when={active() === "overview"}>
                  <OverviewPage
                    organization={organization()}
                    accounts={accounts()}
                    onNavigate={setActive}
                  />
                </Match>
                <Match when={active() === "users"}>
                  <UsersPage preview={preview} />
                </Match>
                <Match when={active() === "organization"}>
                  <OrganizationPage
                    organization={organization()}
                    operator={operator()!}
                    preview={preview}
                    onPreviewUpdate={setPreviewOrganizationState}
                    onLiveUpdate={async (name) => {
                      await updateOrganization(name);
                      await organizationQuery.refetch();
                    }}
                  />
                </Match>
                <Match when={active() === "service-accounts"}>
                  <ServiceAccountsPage
                    accounts={accounts()}
                    preview={preview}
                    onPreviewAccounts={setPreviewAccounts}
                    onRefresh={() => serviceAccountsQuery.refetch()}
                  />
                </Match>
                <Match when={active() === "webhooks"}>
                  <WebhooksPage />
                </Match>
                <Match when={active() === "metrics"}>
                  <MetricsPage />
                </Match>
              </Switch>
            </div>
          </main>
        </div>
      </Match>
    </Switch>
  );
}

function LoadingScreen() {
  return (
    <main class="auth-stage">
      <div class="auth-card loading-card">
        <img src="/brand/rustyauth-mark.png" width="46" height="46" alt="" />
        <div class="loading-line" />
        <p>Opening the control plane…</p>
      </div>
    </main>
  );
}

function SignInScreen(props: {
  email: string;
  error: string;
  pending: boolean;
  onEmail: (value: string) => void;
  onSubmit: (event: SubmitEvent) => void;
  onPreview: () => void;
}) {
  return (
    <main class="auth-stage">
      <section class="auth-card">
        <header class="auth-brand">
          <img src="/brand/rustyauth-mark.png" width="48" height="48" alt="" />
          <div>
            <strong>
              Rusty<span>Auth</span>
            </strong>
            <small>Operator control plane</small>
          </div>
        </header>
        <div class="auth-copy">
          <p class="eyebrow">Passkey-protected administration</p>
          <h1>Operate your identity boundary.</h1>
          <p>
            Search accounts, rotate service credentials and inspect delivery health without exposing SableDB.
          </p>
        </div>
        <form onSubmit={props.onSubmit}>
          <label for="operator-email">Operator email</label>
          <input
            id="operator-email"
            type="email"
            autocomplete="username webauthn"
            value={props.email}
            onInput={(event) => props.onEmail(event.currentTarget.value)}
          />
          <Show when={props.error}>
            <p class="form-error">
              <TbOutlineAlertTriangle size={16} />
              {props.error}
            </p>
          </Show>
          <button
            class="button primary wide"
            type="submit"
            disabled={props.pending}
          >
            <TbOutlineShieldCheck size={18} />
            {props.pending ? "Waiting for passkey…" : "Continue with passkey"}
          </button>
        </form>
        <div class="auth-divider">
          <span>Local evaluation</span>
        </div>
        <button
          class="button secondary wide"
          type="button"
          onClick={props.onPreview}
        >
          Open populated preview <TbOutlineArrowUpRight size={17} />
        </button>
        <p class="auth-footnote">
          Only users listed in <code>AUTH_OPERATOR_EMAILS</code> can bootstrap operator access.
        </p>
      </section>
      <aside class="auth-aside">
        <p class="eyebrow">Trust boundary</p>
        <div class="boundary-stack">
          <BoundaryItem
            icon={TbOutlineUserCircle}
            label="Operator"
            detail="Passkey + HttpOnly session"
          />
          <BoundaryItem
            icon={TbOutlineShieldCheck}
            label="RustyAuth"
            detail="Authorization and audit policy"
            accent
          />
          <BoundaryItem
            icon={TbOutlineDatabase}
            label="SableDB"
            detail="Private durable state"
            dark
          />
        </div>
      </aside>
    </main>
  );
}

function ApertureSignInScreen(props: {
  email: string;
  error: string;
  pending: boolean;
  onEmail: (value: string) => void;
  onSubmit: (event: SubmitEvent) => void;
  onPreview: () => void;
}) {
  return (
    <main class="aperture-auth-stage">
      <div class="aperture-atmosphere" aria-hidden="true" />
      <section class="aperture-console" aria-labelledby="aperture-title">
        <aside class="aperture-trust-rail">
          <header class="aperture-brand">
            <img
              src="/brand/rustyauth-lockup-dark.png"
              width="210"
              height="73"
              alt="RustyAuth"
            />
            <p>Operator control plane</p>
          </header>

          <div class="aperture-boundary">
            <p class="aperture-kicker">Trust boundary</p>
            <ol>
              <li>
                <span class="aperture-boundary-icon">
                  <TbOutlineUserCircle size={22} />
                </span>
                <span>
                  <strong>Operator</strong>
                  <small>Passkey + device</small>
                </span>
              </li>
              <li class="active">
                <span class="aperture-boundary-icon">
                  <TbOutlineShieldCheck size={22} />
                </span>
                <span>
                  <strong>RustyAuth</strong>
                  <small>Authorization and audit policy</small>
                </span>
              </li>
              <li>
                <span class="aperture-boundary-icon">
                  <TbOutlineDatabase size={22} />
                </span>
                <span>
                  <strong>SableDB</strong>
                  <small>Private durable state</small>
                </span>
              </li>
            </ol>
          </div>
        </aside>

        <div class="aperture-form-panel">
          <header class="aperture-copy">
            <p class="aperture-kicker">Passkey-protected administration</p>
            <h1 id="aperture-title">
              Operator access.
              <br />
              Identity-bound by design.
            </h1>
            <p>
              Search accounts, rotate service credentials and inspect delivery health without exposing
              SableDB.
            </p>
          </header>

          <form onSubmit={props.onSubmit}>
            <label for="aperture-operator-email">Operator email</label>
            <input
              id="aperture-operator-email"
              type="email"
              autocomplete="username webauthn"
              value={props.email}
              onInput={(event) => props.onEmail(event.currentTarget.value)}
            />
            <Show when={props.error}>
              <p class="aperture-error" role="alert">
                <TbOutlineAlertTriangle size={16} />
                {props.error}
              </p>
            </Show>
            <button
              class="aperture-submit"
              type="submit"
              disabled={props.pending}
            >
              <TbOutlineShieldCheck size={19} />
              <span>
                {props.pending ? "Waiting for passkey…" : "Continue with passkey"}
              </span>
            </button>
          </form>

          <div class="aperture-divider">
            <span>Local evaluation</span>
          </div>
          <button
            class="aperture-preview"
            type="button"
            onClick={props.onPreview}
          >
            <span>Open populated preview</span>
            <TbOutlineArrowUpRight size={18} />
          </button>
          <p class="aperture-footnote">
            Only users listed in <code>AUTH_OPERATOR_EMAILS</code> can bootstrap operator access.
          </p>
        </div>
      </section>
    </main>
  );
}

function BoundaryItem(
  props: {
    icon: IconComponent;
    label: string;
    detail: string;
    accent?: boolean;
    dark?: boolean;
  },
) {
  return (
    <div
      classList={{
        "boundary-item": true,
        accent: props.accent,
        dark: props.dark,
      }}
    >
      <props.icon size={20} />
      <div>
        <strong>{props.label}</strong>
        <span>{props.detail}</span>
      </div>
    </div>
  );
}

function Sidebar(props: {
  active: NavKey;
  mobileOpen: boolean;
  operator: OperatorView;
  preview: boolean;
  onNavigate: (key: NavKey) => void;
  onSignOut: () => void;
}) {
  return (
    <aside classList={{ sidebar: true, open: props.mobileOpen }}>
      <a class="dashboard-brand" href="/" aria-label="RustyAuth control plane">
        <img
          src="/brand/rustyauth-lockup.png"
          width="154"
          height="54"
          alt="RustyAuth"
        />
      </a>
      <div class="instance-switcher">
        <span class="instance-mark">RL</span>
        <div>
          <strong>RustyAuth Local</strong>
          <small>Development instance</small>
        </div>
        <TbOutlineChevronRight size={16} />
      </div>
      <nav class="side-nav" aria-label="Control plane">
        <p>Workspace</p>
        <For each={navItems}>
          {(item) => (
            <button
              type="button"
              classList={{ active: props.active === item.key }}
              onClick={() => props.onNavigate(item.key)}
            >
              <item.icon size={18} />
              <span>{item.label}</span>
              <Show when={item.key === "webhooks"}>
                <i>3</i>
              </Show>
            </button>
          )}
        </For>
      </nav>
      <div class="sidebar-foot">
        <div class="system-state">
          <span class="status-dot" />
          <div>
            <strong>All systems nominal</strong>
            <small>SableDB · 12 ms</small>
          </div>
        </div>
        <button
          type="button"
          class="operator-mini"
          onClick={props.onSignOut}
          title={props.preview ? "Close preview" : "Sign out"}
        >
          <span>{initials(props.operator.displayName)}</span>
          <div>
            <strong>{props.operator.displayName}</strong>
            <small>{props.operator.role}</small>
          </div>
          <TbOutlineLogout size={17} />
        </button>
      </div>
    </aside>
  );
}

function Topbar(
  props: {
    title: string;
    operator: OperatorView;
    preview: boolean;
    onMenu: () => void;
    onNavigate: (key: NavKey) => void;
    onSignOut: () => void;
  },
) {
  const [menuOpen, setMenuOpen] = createSignal(false);
  const [profileOpen, setProfileOpen] = createSignal(false);

  return (
    <>
      <header class="topbar">
        <button
          type="button"
          class="icon-button mobile-menu"
          onClick={props.onMenu}
          aria-label="Open navigation"
        >
          <TbOutlineMenu2 size={20} />
        </button>
        <div>
          <p class="eyebrow">RustyAuth / Control plane</p>
          <h1>{props.title}</h1>
        </div>
        <div class="topbar-actions">
          <div class="runtime-meta" aria-label="Runtime environment">
            <Show when={props.preview}>
              <span class="workspace-mode">Sample workspace</span>
            </Show>
            <span class="runtime-state">
              <i /> Local
            </span>
          </div>
          <button
            type="button"
            class="avatar-button"
            title={props.operator.email}
            aria-haspopup="menu"
            aria-expanded={menuOpen()}
            onClick={() => setMenuOpen(!menuOpen())}
          >
            {initials(props.operator.displayName)}
          </button>
          <Show when={menuOpen()}>
            <button
              type="button"
              class="popover-dismiss"
              aria-label="Close operator menu"
              onClick={() => setMenuOpen(false)}
            />
            <div class="operator-popover" role="menu">
              <header>
                <span>{initials(props.operator.displayName)}</span>
                <div>
                  <strong>{props.operator.displayName}</strong>
                  <small>{props.operator.email}</small>
                </div>
              </header>
              <p>{props.operator.role} operator</p>
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setMenuOpen(false);
                  setProfileOpen(true);
                }}
              >
                <TbOutlineUserCircle size={17} />
                Operator profile
                <TbOutlineChevronRight size={15} />
              </button>
              <button
                type="button"
                role="menuitem"
                onClick={() => {
                  setMenuOpen(false);
                  props.onNavigate("organization");
                }}
              >
                <TbOutlineBuilding size={17} />
                Organization settings
                <TbOutlineChevronRight size={15} />
              </button>
              <button
                type="button"
                class="operator-signout"
                role="menuitem"
                onClick={() => props.onSignOut()}
              >
                <TbOutlineLogout size={17} />
                {props.preview ? "Exit preview" : "Sign out"}
              </button>
            </div>
          </Show>
        </div>
      </header>
      <Show when={profileOpen()}>
        <OperatorProfileDrawer
          operator={props.operator}
          preview={props.preview}
          onClose={() => setProfileOpen(false)}
          onOrganization={() => {
            setProfileOpen(false);
            props.onNavigate("organization");
          }}
          onSignOut={props.onSignOut}
        />
      </Show>
    </>
  );
}

function PreviewBanner() {
  return (
    <div class="preview-context" role="status">
      <span class="preview-context-label">Preview</span>
      <div>
        <strong>Sample data is active</strong>
        <span>
          Changes stay in this browser until you connect the live Rust handlers.
        </span>
      </div>
      <a href="/">
        Connect live <TbOutlineArrowUpRight size={14} />
      </a>
    </div>
  );
}

function OperatorProfileDrawer(props: {
  operator: OperatorView;
  preview: boolean;
  onClose: () => void;
  onOrganization: () => void;
  onSignOut: () => void;
}) {
  return (
    <div
      class="drawer-backdrop"
      onClick={(event) => event.target === event.currentTarget && props.onClose()}
    >
      <aside class="drawer operator-drawer" aria-label="Operator profile">
        <header>
          <div>
            <p class="eyebrow">Operator session</p>
            <h3>Profile &amp; access</h3>
          </div>
          <button
            type="button"
            class="icon-button"
            onClick={props.onClose}
            aria-label="Close operator profile"
          >
            <TbOutlineX size={18} />
          </button>
        </header>
        <div class="profile-hero operator-profile-hero">
          <span>{initials(props.operator.displayName)}</span>
          <div>
            <strong>{props.operator.displayName}</strong>
            <small>{props.operator.email}</small>
          </div>
        </div>
        <div class="definition">
          <span>Operator ID</span>
          <strong class="mono-value">{props.operator.id}</strong>
        </div>
        <div class="definition">
          <span>Access</span>
          <strong>{props.operator.role}</strong>
        </div>
        <div class="definition">
          <span>Authentication</span>
          <strong>{props.preview ? "Preview session" : "Passkey"}</strong>
        </div>
        <div class="operator-session-note">
          <TbOutlineShieldCheck size={18} />
          <div>
            <strong>{props.preview ? "Local preview session" : "Passkey verified"}</strong>
            <span>
              {props.preview
                ? "No control-plane changes leave this browser."
                : "This operator session is bound to a registered passkey."}
            </span>
          </div>
        </div>
        <div class="drawer-actions operator-drawer-actions">
          <button type="button" class="button secondary" onClick={props.onOrganization}>
            Organization settings
          </button>
          <button type="button" class="danger-text" onClick={props.onSignOut}>
            <TbOutlineLogout size={15} />
            {props.preview ? "Exit preview" : "Sign out"}
          </button>
        </div>
      </aside>
    </div>
  );
}

function OverviewPage(
  props: {
    organization?: OrganizationView;
    accounts: ServiceAccountView[];
    onNavigate: (key: NavKey) => void;
  },
) {
  const [selectedUser, setSelectedUser] = createSignal<UserView>();

  return (
    <>
      <div class="content-stack">
        <section class="page-heading">
          <div>
            <p class="eyebrow">Instance intelligence</p>
            <h2>{props.organization?.name ?? "RustyAuth"}</h2>
            <p>
              Authentication health and operational posture across the last 24 hours.
            </p>
          </div>
          <button
            type="button"
            class="button secondary"
            onClick={() => props.onNavigate("metrics")}
          >
            Explore metrics <TbOutlineArrowUpRight size={17} />
          </button>
        </section>
        <section class="metric-grid compact">
          <MetricCard
            label="Authentication success"
            value="98.72%"
            change="+0.34%"
            tone="good"
          />
          <MetricCard
            label="Active users"
            value="8,402"
            change="+6.8%"
            tone="good"
          />
          <MetricCard
            label="Passkey latency p95"
            value="284 ms"
            change="−18 ms"
            tone="good"
          />
          <MetricCard
            label="Failed challenges"
            value="193"
            change="+12"
            tone="warn"
          />
        </section>
        <div class="overview-grid">
          <section class="panel volume-panel">
            <PanelHeader
              eyebrow="Authentication volume"
              title="24-hour activity"
              action="Metrics"
              onAction={() => props.onNavigate("metrics")}
            />
            <div class="bar-chart" aria-label="Hourly authentication volume">
              <For each={authVolume}>
                {(value, index) => (
                  <span
                    style={{
                      height: `${Math.round(value / 1.6)}%`,
                      "animation-delay": `${70 + index() * 18}ms`,
                    }}
                    title={`${index()}:00 · ${value} authentications`}
                  />
                )}
              </For>
            </div>
            <div class="chart-axis">
              <span>00:00</span>
              <span>06:00</span>
              <span>12:00</span>
              <span>18:00</span>
              <span>Now</span>
            </div>
          </section>
          <section class="panel posture-panel">
            <PanelHeader
              eyebrow="Security posture"
              title="Healthy configuration"
            />
            <PostureRow label="Signing keys" value="Active + staged" good />
            <PostureRow label="Encrypted backup" value="43 minutes ago" good />
            <PostureRow
              label="Service credentials"
              value={`${props.accounts.filter((item) => item.status === "Active").length} active`}
              good
            />
            <PostureRow label="Webhook backlog" value="2 retrying" />
          </section>
        </div>
        <section class="panel">
          <PanelHeader
            eyebrow="Recent accounts"
            title="Latest identity activity"
            action="View users"
            onAction={() => props.onNavigate("users")}
          />
          <UserTable
            users={previewUsers.slice(0, 4)}
            compact
            onSelect={setSelectedUser}
          />
        </section>
      </div>
      <Show when={selectedUser()}>
        <UserDrawer
          user={selectedUser()!}
          onClose={() => setSelectedUser()}
          onOpenDirectory={() => {
            setSelectedUser();
            props.onNavigate("users");
          }}
        />
      </Show>
    </>
  );
}

function MetricCard(
  props: {
    label: string;
    value: string;
    change: string;
    tone: "good" | "warn";
  },
) {
  return (
    <article class="metric-card">
      <p>{props.label}</p>
      <strong>{props.value}</strong>
      <span
        classList={{
          positive: props.tone === "good",
          warning: props.tone === "warn",
        }}
      >
        {props.change}
      </span>
      <small>vs previous period</small>
    </article>
  );
}

function PanelHeader(
  props: {
    eyebrow: string;
    title: string;
    action?: string;
    onAction?: () => void;
  },
) {
  return (
    <header class="panel-header">
      <div>
        <p class="eyebrow">{props.eyebrow}</p>
        <h3>{props.title}</h3>
      </div>
      <Show when={props.action}>
        <button type="button" class="text-button" onClick={props.onAction}>
          {props.action}
          <TbOutlineChevronRight size={15} />
        </button>
      </Show>
    </header>
  );
}

function PostureRow(props: { label: string; value: string; good?: boolean }) {
  return (
    <div class="posture-row">
      <span classList={{ "state-icon": true, good: props.good }}>
        {props.good ? <TbOutlineCheck size={15} /> : <TbOutlineRefresh size={15} />}
      </span>
      <strong>{props.label}</strong>
      <small>{props.value}</small>
    </div>
  );
}

function UsersPage(props: { preview: boolean }) {
  const [term, setTerm] = createSignal("");
  const [statusFilter, setStatusFilter] = createSignal("all");
  const [sortBy, setSortBy] = createSignal("activity");
  const [users, setUsers] = createSignal<UserView[]>(
    props.preview ? previewUsers : [],
  );
  const [searching, setSearching] = createSignal(false);
  const [error, setError] = createSignal("");
  const [selected, setSelected] = createSignal<UserView>();
  const filtered = createMemo(() => {
    const query = term().trim().toLowerCase();
    const matches = users().filter((user) => {
      const matchesQuery = !props.preview || !query ||
        `${user.name} ${user.primaryIdentifier} ${user.id}`.toLowerCase()
          .includes(query);
      const matchesStatus = statusFilter() === "all" ||
        (statusFilter() === "active" && user.status === "Active") ||
        (statusFilter() === "verification" && user.status === "Needs verification");
      return matchesQuery && matchesStatus;
    });
    return sortBy() === "name" ? [...matches].sort((a, b) => a.name.localeCompare(b.name)) : matches;
  });
  const directoryTotals = createMemo(() => ({
    identifiers: filtered().reduce((total, user) => total + user.identifiers, 0),
    passkeys: filtered().reduce((total, user) => total + user.passkeys, 0),
  }));

  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (props.preview) return;
    setError("");
    setSearching(true);
    try {
      setUsers(await searchUsers(term()));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "User search failed.");
    } finally {
      setSearching(false);
    }
  }

  return (
    <>
      <div class="content-stack">
        <section class="page-heading">
          <div>
            <p class="eyebrow">Identity directory</p>
            <h2>Find an account</h2>
            <p>
              Search exact identifiers, UUIDs, passkeys and profile fields without exposing credential
              material.
            </p>
          </div>
        </section>
        <form class="search-panel" onSubmit={submit}>
          <TbOutlineSearch size={20} />
          <input
            value={term()}
            onInput={(event) => setTerm(event.currentTarget.value)}
            placeholder="Email, phone, display name or user UUID"
            aria-label="Search users"
          />
          <button class="button primary" type="submit" disabled={searching()}>
            {searching() ? "Searching…" : "Search"}
          </button>
        </form>
        <Show when={error()}>
          <p class="form-error">
            <TbOutlineAlertTriangle size={16} />
            {error()}
          </p>
        </Show>
        <section class="panel table-panel">
          <header class="directory-toolbar">
            <div class="directory-summary">
              <strong>
                {filtered().length} {filtered().length === 1 ? "account" : "accounts"}
              </strong>
              <span>
                {directoryTotals().identifiers}{" "}
                {directoryTotals().identifiers === 1 ? "identifier" : "identifiers"} ·{" "}
                {directoryTotals().passkeys} {directoryTotals().passkeys === 1 ? "passkey" : "passkeys"}
              </span>
            </div>
            <div class="directory-controls">
              <label>
                <span>Status</span>
                <select
                  aria-label="Filter users by status"
                  value={statusFilter()}
                  onChange={(event) => setStatusFilter(event.currentTarget.value)}
                >
                  <option value="all">All statuses</option>
                  <option value="active">Active</option>
                  <option value="verification">Needs verification</option>
                </select>
              </label>
              <label>
                <span>Order</span>
                <select
                  aria-label="Sort users"
                  value={sortBy()}
                  onChange={(event) => setSortBy(event.currentTarget.value)}
                >
                  <option value="activity">Last active</option>
                  <option value="name">Name</option>
                </select>
              </label>
              <span class="directory-updated">Indexed just now</span>
            </div>
          </header>
          <Show
            when={filtered().length}
            fallback={
              <EmptyState
                icon={TbOutlineUsers}
                title="No matching accounts"
                detail={props.preview
                  ? "Try a different search term."
                  : "Search by an exact identifier or display name."}
              />
            }
          >
            <UserTable users={filtered()} onSelect={setSelected} />
          </Show>
        </section>
      </div>
      <Show when={selected()}>
        <UserDrawer user={selected()!} onClose={() => setSelected()} />
      </Show>
    </>
  );
}

function UserTable(
  props: {
    users: UserView[];
    compact?: boolean;
    onSelect?: (user: UserView) => void;
  },
) {
  return (
    <div class="data-table user-table">
      <div class="table-head">
        <span>User</span>
        <span>Status</span>
        <span>Passkeys</span>
        <span>Last active</span>
        <span />
      </div>
      <For each={props.users}>
        {(user, index) => (
          <button
            type="button"
            class="table-row"
            aria-label={`Open ${user.name} account`}
            style={{ "animation-delay": `${index() * 28}ms` }}
            onClick={() => props.onSelect?.(user)}
          >
            <span class="user-cell">
              <i>{initials(user.name)}</i>
              <span>
                <strong>{user.name}</strong>
                <small>{user.primaryIdentifier}</small>
              </span>
            </span>
            <span>
              <StatusBadge status={user.status} />
            </span>
            <span class="mono-value">{user.passkeys}</span>
            <span>{user.lastActive}</span>
            <TbOutlineChevronRight size={17} />
          </button>
        )}
      </For>
    </div>
  );
}

function UserDrawer(props: {
  user: UserView;
  onClose: () => void;
  onOpenDirectory?: () => void;
}) {
  let drawerElement: HTMLElement | undefined;
  let closeButton: HTMLButtonElement | undefined;
  const titleId = `user-drawer-title-${props.user.id}`;

  useDialogSurface(() => drawerElement, () => closeButton, props.onClose);

  return (
    <div
      class="drawer-backdrop"
      onClick={(event) => event.target === event.currentTarget && props.onClose()}
    >
      <aside
        ref={drawerElement}
        class="drawer wide-drawer user-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <header>
          <div>
            <p class="eyebrow">Identity record</p>
            <h3 id={titleId}>{props.user.name}</h3>
          </div>
          <button
            ref={closeButton}
            type="button"
            class="icon-button"
            onClick={props.onClose}
            aria-label="Close user inspector"
          >
            <TbOutlineX size={20} />
          </button>
        </header>
        <div class="profile-hero user-profile-hero">
          <span>{initials(props.user.name)}</span>
          <div>
            <strong>{props.user.name}</strong>
            <small>{props.user.primaryIdentifier}</small>
          </div>
          <StatusBadge status={props.user.status} />
        </div>
        <div class="user-signal-strip">
          <article>
            <span>Last active</span>
            <strong>{props.user.lastActive}</strong>
          </article>
          <article>
            <span>Identifiers</span>
            <strong>{props.user.identifiers}</strong>
          </article>
          <article>
            <span>Passkeys</span>
            <strong>{props.user.passkeys}</strong>
          </article>
        </div>
        <Definition label="User UUID" value={props.user.id} mono copy />
        <Definition label="Created" value={formatDate(props.user.createdAt)} />
        <div class="drawer-section">
          <p class="eyebrow">Credential boundary</p>
          <div class="policy-note">
            <TbOutlineShieldCheck size={19} />
            <span>
              Public keys, counters and assertions remain private. This inspector exposes account metadata
              only.
            </span>
          </div>
        </div>
        <div class="drawer-actions user-drawer-actions">
          <button type="button" class="button secondary" onClick={props.onClose}>Done</button>
          <Show when={props.onOpenDirectory}>
            <button type="button" class="button primary" onClick={props.onOpenDirectory}>
              Open user directory <TbOutlineArrowUpRight size={16} />
            </button>
          </Show>
        </div>
      </aside>
    </div>
  );
}

function OrganizationPage(props: {
  organization?: OrganizationView;
  operator: OperatorView;
  preview: boolean;
  onPreviewUpdate: (value: OrganizationView) => void;
  onLiveUpdate: (name: string) => Promise<void>;
}) {
  const [name, setName] = createSignal(props.organization?.name ?? "");
  const [saved, setSaved] = createSignal(false);
  const [pending, setPending] = createSignal(false);
  async function save(event: SubmitEvent) {
    event.preventDefault();
    setPending(true);
    setSaved(false);
    if (props.preview && props.organization) {
      props.onPreviewUpdate({ ...props.organization, name: name().trim() });
    } else await props.onLiveUpdate(name().trim());
    setPending(false);
    setSaved(true);
    globalThis.setTimeout(() => setSaved(false), 2500);
  }
  return (
    <div class="content-stack narrow-stack">
      <section class="page-heading">
        <div>
          <p class="eyebrow">Instance ownership</p>
          <h2>Organization settings</h2>
          <p>
            The single administrative organization for this RustyAuth deployment.
          </p>
        </div>
      </section>
      <section class="panel form-panel">
        <PanelHeader eyebrow="Organization" title="General details" />
        <form onSubmit={save}>
          <label>
            Display name<input
              value={name()}
              onInput={(event) => setName(event.currentTarget.value)}
              maxlength={120}
            />
          </label>
          <label>
            Instance slug<input
              value={props.organization?.slug ?? ""}
              disabled
            />
          </label>
          <label>
            Organization ID<div class="copy-field">
              <code>{props.organization?.id ?? "Loading…"}</code>
              <TbOutlineCopy size={16} />
            </div>
          </label>
          <div class="form-actions">
            <Show when={saved()}>
              <span class="saved-state">
                <TbOutlineCheck size={16} /> Saved
              </span>
            </Show>
            <button type="submit" class="button primary" disabled={pending()}>
              {pending() ? "Saving…" : "Save changes"}
            </button>
          </div>
        </form>
      </section>
      <section class="panel">
        <PanelHeader eyebrow="Operators" title="Administrative access" />
        <div class="operator-row">
          <span>{initials(props.operator.displayName)}</span>
          <div>
            <strong>{props.operator.displayName}</strong>
            <small>{props.operator.email}</small>
          </div>
          <StatusBadge status={props.operator.role} />
          <button type="button" class="icon-button">
            <TbOutlineDots size={19} />
          </button>
        </div>
        <div class="section-note">
          <TbOutlineShieldCheck size={18} />
          <p>
            Operator access always requires a passkey-authenticated RustyAuth session. Agent handoffs and
            service credentials are rejected.
          </p>
        </div>
      </section>
    </div>
  );
}

function ServiceAccountsPage(props: {
  accounts: ServiceAccountView[];
  preview: boolean;
  onPreviewAccounts: (value: ServiceAccountView[]) => void;
  onRefresh: () => Promise<unknown>;
}) {
  const [createOpen, setCreateOpen] = createSignal(false);
  const [selected, setSelected] = createSignal<ServiceAccountView>();
  const [secret, setSecret] = createSignal("");
  const [secretName, setSecretName] = createSignal("");
  const [revoking, setRevoking] = createSignal("");
  const activeCount = createMemo(() =>
    props.accounts.filter((account) => account.status === "Active").length
  );

  async function createAccount(
    input: {
      name: string;
      description: string;
      scopes: string[];
      credentialName: string;
    },
  ) {
    if (props.preview) {
      const id = crypto.randomUUID();
      const raw = `rsa_preview_${crypto.randomUUID().replaceAll("-", "")}`;
      const created: ServiceAccountView = {
        id,
        name: input.name,
        description: input.description,
        status: "Active",
        scopes: input.scopes,
        credentials: [{
          id: crypto.randomUUID(),
          name: input.credentialName,
          hint: raw.slice(-6),
          createdAt: new Date().toISOString(),
          lastUsedAt: "Never",
          revokedAt: "",
        }],
        createdAt: new Date().toISOString(),
        lastUsedAt: "Never",
      };
      props.onPreviewAccounts([created, ...props.accounts]);
      setSecret(raw);
      setSecretName(input.credentialName);
    } else {
      const account = await createServiceAccount(input);
      const credential = await createServiceCredential({
        serviceAccountId: account.id,
        name: input.credentialName,
      });
      setSecret(credential.secret);
      setSecretName(input.credentialName);
      await props.onRefresh();
    }
    setCreateOpen(false);
  }

  async function revoke(account: ServiceAccountView, credentialId: string) {
    if (props.preview) {
      props.onPreviewAccounts(
        props.accounts.map((item) =>
          item.id === account.id
            ? {
              ...item,
              credentials: item.credentials.map((credential) =>
                credential.id === credentialId
                  ? { ...credential, revokedAt: new Date().toISOString() }
                  : credential
              ),
            }
            : item
        ),
      );
    } else {
      await revokeServiceCredential({
        serviceAccountId: account.id,
        credentialId,
        reason: "Operator requested revocation",
      });
      await props.onRefresh();
    }
    setRevoking("");
  }

  return (
    <div class="content-stack">
      <section class="page-heading">
        <div>
          <p class="eyebrow">Machine identity</p>
          <h2>Service accounts</h2>
          <p>
            Issue narrowly scoped, independently rotatable credentials for gRPC and Connect clients.
          </p>
        </div>
        <button type="button" class="button primary" onClick={() => setCreateOpen(true)}>
          <TbOutlinePlus size={17} />New service account
        </button>
      </section>
      <section class="metric-grid service-summary">
        <MetricCard
          label="Active accounts"
          value={String(activeCount())}
          change={`${props.accounts.length - activeCount()} disabled`}
          tone="good"
        />
        <MetricCard
          label="Live credentials"
          value={String(
            props.accounts.flatMap((account) => account.credentials).filter((
              credential,
            ) => !credential.revokedAt).length,
          )}
          change="Rotatable"
          tone="good"
        />
        <MetricCard
          label="RPC calls · 24h"
          value="18,402"
          change="+12.4%"
          tone="good"
        />
      </section>
      <section class="panel table-panel">
        <PanelHeader
          eyebrow="Principals"
          title={`${props.accounts.length} service accounts`}
        />
        <div class="data-table service-table">
          <div class="table-head">
            <span>Service account</span>
            <span>Status</span>
            <span>Scopes</span>
            <span>Last used</span>
            <span />
          </div>
          <For each={props.accounts}>
            {(account) => (
              <button
                type="button"
                class="table-row"
                onClick={() => setSelected(account)}
              >
                <span class="service-cell">
                  <i>
                    <TbOutlineKey size={18} />
                  </i>
                  <span>
                    <strong>{account.name}</strong>
                    <small>{account.description}</small>
                  </span>
                </span>
                <span>
                  <StatusBadge status={account.status} />
                </span>
                <span class="scope-count">{account.scopes.length} scopes</span>
                <span>{account.lastUsedAt || "Never"}</span>
                <TbOutlineChevronRight size={17} />
              </button>
            )}
          </For>
        </div>
      </section>
      <Show when={createOpen()}>
        <CreateServiceAccountModal
          onClose={() => setCreateOpen(false)}
          onCreate={createAccount}
        />
      </Show>
      <Show when={secret()}>
        <SecretModal
          name={secretName()}
          secret={secret()}
          onClose={() => setSecret("")}
        />
      </Show>
      <Show when={selected()}>
        <ServiceAccountDrawer
          account={selected()!}
          revoking={revoking()}
          onRevokePrompt={setRevoking}
          onRevoke={revoke}
          onClose={() => {
            setSelected();
            setRevoking("");
          }}
        />
      </Show>
    </div>
  );
}

function CreateServiceAccountModal(
  props: {
    onClose: () => void;
    onCreate: (
      input: {
        name: string;
        description: string;
        scopes: string[];
        credentialName: string;
      },
    ) => Promise<void>;
  },
) {
  const [name, setName] = createSignal("");
  const [description, setDescription] = createSignal("");
  const [credentialName, setCredentialName] = createSignal(
    "Primary credential",
  );
  const [scopes, setScopes] = createSignal(["identity.read", "events.read"]);
  const [pending, setPending] = createSignal(false);
  const toggle = (scope: string) =>
    setScopes((current) =>
      current.includes(scope) ? current.filter((value) => value !== scope) : [...current, scope]
    );
  async function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!name().trim() || !scopes().length) return;
    setPending(true);
    await props.onCreate({
      name: name().trim(),
      description: description().trim(),
      scopes: scopes(),
      credentialName: credentialName().trim(),
    });
    setPending(false);
  }
  return (
    <div class="modal-backdrop">
      <section class="modal large-modal">
        <header>
          <div>
            <p class="eyebrow">New machine principal</p>
            <h3>Create service account</h3>
          </div>
          <button type="button" class="icon-button" onClick={props.onClose}>
            <TbOutlineX size={20} />
          </button>
        </header>
        <form onSubmit={submit}>
          <div class="form-grid">
            <label>
              Name<input
                value={name()}
                onInput={(event) => setName(event.currentTarget.value)}
                placeholder="production-api"
                required
                maxlength={100}
              />
            </label>
            <label>
              First credential<input
                value={credentialName()}
                onInput={(event) => setCredentialName(event.currentTarget.value)}
                required
                maxlength={100}
              />
            </label>
          </div>
          <label>
            Description<textarea
              value={description()}
              onInput={(event) => setDescription(event.currentTarget.value)}
              placeholder="Where this principal is used and who owns it."
              maxlength={500}
            />
          </label>
          <fieldset>
            <legend>Granted scopes</legend>
            <div class="scope-options">
              <For each={serviceScopes}>
                {(scope) => (
                  <label classList={{ selected: scopes().includes(scope) }}>
                    <input
                      type="checkbox"
                      checked={scopes().includes(scope)}
                      onChange={() => toggle(scope)}
                    />
                    <span>
                      <TbOutlineCheck size={14} />
                    </span>
                    <code>{scope}</code>
                  </label>
                )}
              </For>
            </div>
          </fieldset>
          <div class="modal-note">
            <TbOutlineKey size={18} />
            <span>
              The credential secret is displayed once after creation. RustyAuth stores only a SHA-256 index.
            </span>
          </div>
          <footer>
            <button
              class="button secondary"
              type="button"
              onClick={props.onClose}
            >
              Cancel
            </button>
            <button
              type="submit"
              class="button primary"
              disabled={pending() || !scopes().length}
            >
              {pending() ? "Creating…" : "Create account"}
            </button>
          </footer>
        </form>
      </section>
    </div>
  );
}

function SecretModal(
  props: { name: string; secret: string; onClose: () => void },
) {
  const [copied, setCopied] = createSignal(false);
  async function copy() {
    await navigator.clipboard.writeText(props.secret);
    setCopied(true);
  }
  return (
    <div class="modal-backdrop top-modal">
      <section class="modal secret-modal">
        <header>
          <div>
            <p class="eyebrow">One-time secret</p>
            <h3>Credential issued</h3>
          </div>
        </header>
        <div class="success-mark">
          <TbOutlineCheck size={24} />
        </div>
        <p>
          <strong>{props.name}</strong>{" "}
          is ready. Copy this value now; it cannot be recovered after this dialog closes.
        </p>
        <div class="secret-value">
          <code>{props.secret}</code>
          <button type="button" class="icon-button" onClick={copy} aria-label="Copy secret">
            {copied() ? <TbOutlineCheck size={19} /> : <TbOutlineClipboard size={19} />}
          </button>
        </div>
        <footer>
          <button type="button" class="button primary wide" onClick={props.onClose}>
            I have stored this credential
          </button>
        </footer>
      </section>
    </div>
  );
}

function ServiceAccountDrawer(
  props: {
    account: ServiceAccountView;
    revoking: string;
    onRevokePrompt: (id: string) => void;
    onRevoke: (account: ServiceAccountView, id: string) => Promise<void>;
    onClose: () => void;
  },
) {
  let drawerElement: HTMLElement | undefined;
  let closeButton: HTMLButtonElement | undefined;
  const titleId = `service-account-title-${props.account.id}`;
  const descriptionId = `service-account-description-${props.account.id}`;
  useDialogSurface(() => drawerElement, () => closeButton, props.onClose);

  return (
    <div
      class="drawer-backdrop"
      onClick={(event) => event.target === event.currentTarget && props.onClose()}
    >
      <aside
        ref={drawerElement}
        class="drawer wide-drawer service-account-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={descriptionId}
      >
        <header>
          <div>
            <p class="eyebrow">Service account</p>
            <h3 id={titleId}>{props.account.name}</h3>
          </div>
          <button
            ref={closeButton}
            type="button"
            class="icon-button"
            onClick={props.onClose}
            aria-label="Close service account details"
          >
            <TbOutlineX size={20} />
          </button>
        </header>
        <div class="profile-hero service-hero">
          <span>
            <TbOutlineKey size={25} />
          </span>
          <div>
            <StatusBadge status={props.account.status} />
            <small id={descriptionId}>{props.account.description}</small>
          </div>
        </div>
        <div class="drawer-section">
          <p class="eyebrow">Granted scopes</p>
          <div class="scope-list">
            <For each={props.account.scopes}>
              {(scope) => <code>{scope}</code>}
            </For>
          </div>
        </div>
        <div class="drawer-section">
          <p class="eyebrow">Credentials</p>
          <For
            each={props.account.credentials}
            fallback={<p class="muted">No credentials have been issued.</p>}
          >
            {(credential) => (
              <div class="credential-row">
                <div>
                  <strong>{credential.name}</strong>
                  <small>
                    Ends in <code>{credential.hint}</code> · {credential.lastUsedAt || "Never used"}
                  </small>
                </div>
                <Show
                  when={!credential.revokedAt}
                  fallback={<StatusBadge status="Revoked" />}
                >
                  <Show
                    when={props.revoking !== credential.id}
                    fallback={
                      <span class="inline-confirm">
                        Revoke now?<button
                          type="button"
                          onClick={() => props.onRevoke(props.account, credential.id)}
                        >
                          Confirm
                        </button>
                        <button type="button" onClick={() => props.onRevokePrompt("")}>
                          Cancel
                        </button>
                      </span>
                    }
                  >
                    <button
                      type="button"
                      class="danger-text"
                      onClick={() => props.onRevokePrompt(credential.id)}
                    >
                      Revoke
                    </button>
                  </Show>
                </Show>
              </div>
            )}
          </For>
        </div>
        <Definition
          label="Service account ID"
          value={props.account.id}
          mono
          copy
        />
        <Definition
          label="Created"
          value={formatDate(props.account.createdAt)}
        />
      </aside>
    </div>
  );
}

function WebhooksPage() {
  const [webhooks, setWebhooks] = createSignal(
    previewWebhooks.map((webhook) => ({ ...webhook, events: [...webhook.events] })),
  );
  const [selected, setSelected] = createSignal<WebhookView>();
  const [creating, setCreating] = createSignal(false);

  function closeEditor() {
    setSelected();
    setCreating(false);
  }

  function saveEndpoint(endpoint: WebhookView) {
    setWebhooks((current) => {
      const existing = current.findIndex((webhook) => webhook.id === endpoint.id);
      if (existing < 0) return [endpoint, ...current];
      return current.map((webhook) => webhook.id === endpoint.id ? endpoint : webhook);
    });
    closeEditor();
  }

  return (
    <div class="content-stack">
      <section class="page-heading">
        <div>
          <p class="eyebrow">Event delivery</p>
          <h2>Webhooks</h2>
          <p>
            Signed, observable delivery with bounded retries and replayable failures.
          </p>
        </div>
        <button
          type="button"
          class="button primary"
          onClick={() => {
            setSelected();
            setCreating(true);
          }}
        >
          <TbOutlinePlus size={17} />New endpoint
        </button>
      </section>
      <div class="roadmap-callout">
        <TbOutlineWebhook size={21} />
        <div>
          <strong>Contract-backed preview</strong>
          <span>
            Webhook storage and the durable delivery outbox are the next Rust implementation boundary.
          </span>
        </div>
      </div>
      <section class="panel table-panel">
        <PanelHeader
          eyebrow="Destinations"
          title={`${webhooks().length} configured endpoints`}
        />
        <div class="data-table webhook-table">
          <div class="table-head">
            <span>Endpoint</span>
            <span>Status</span>
            <span>Events</span>
            <span>Success rate</span>
            <span>Last delivery</span>
            <span>Manage</span>
          </div>
          <For each={webhooks()}>
            {(webhook) => (
              <button
                type="button"
                class="table-row webhook-row"
                aria-label={`Edit ${webhook.name} endpoint`}
                onClick={() => {
                  setCreating(false);
                  setSelected(webhook);
                }}
              >
                <span class="service-cell">
                  <i>
                    <TbOutlineWebhook size={18} />
                  </i>
                  <span>
                    <strong>{webhook.name}</strong>
                    <small>{webhook.url}</small>
                  </span>
                </span>
                <span>
                  <StatusBadge status={webhook.status} />
                </span>
                <span>{webhook.events.length}</span>
                <strong>{webhook.successRate}</strong>
                <span>{webhook.lastDelivery}</span>
                <span class="row-action">
                  Edit<TbOutlineChevronRight size={16} />
                </span>
              </button>
            )}
          </For>
        </div>
      </section>
      <Show when={selected() || creating()}>
        <WebhookEditorDrawer
          webhook={selected()}
          onClose={closeEditor}
          onSave={saveEndpoint}
        />
      </Show>
    </div>
  );
}

function WebhookEditorDrawer(props: {
  webhook?: WebhookView;
  onClose: () => void;
  onSave: (webhook: WebhookView) => void;
}) {
  const isNew = !props.webhook;
  const [name, setName] = createSignal(props.webhook?.name ?? "");
  const [url, setUrl] = createSignal(props.webhook?.url ?? "");
  const [events, setEvents] = createSignal(
    props.webhook?.events ? [...props.webhook.events] : webhookEvents.slice(0, 4),
  );
  const [enabled, setEnabled] = createSignal(props.webhook?.status !== "Paused");
  const [urlError, setUrlError] = createSignal("");
  let drawerElement: HTMLElement | undefined;
  let nameInput: HTMLInputElement | undefined;
  const titleId = `webhook-editor-title-${props.webhook?.id ?? "new"}`;

  useDialogSurface(() => drawerElement, () => nameInput, props.onClose);

  function toggleEvent(eventName: string) {
    setEvents((current) =>
      current.includes(eventName) ? current.filter((value) => value !== eventName) : [...current, eventName]
    );
  }

  function validUrl(value: string) {
    try {
      return new URL(value).protocol === "https:";
    } catch {
      return false;
    }
  }

  function submit(event: SubmitEvent) {
    event.preventDefault();
    if (!validUrl(url())) {
      setUrlError("Use a complete HTTPS endpoint URL.");
      return;
    }
    if (!name().trim() || !events().length) return;

    props.onSave({
      id: props.webhook?.id ?? `wh_${crypto.randomUUID()}`,
      name: name().trim(),
      url: url().trim(),
      status: enabled() ? props.webhook?.status === "Retrying" ? "Retrying" : "Healthy" : "Paused",
      events: events(),
      successRate: props.webhook?.successRate ?? "—",
      lastDelivery: props.webhook?.lastDelivery ?? "Never",
    });
  }

  return (
    <div
      class="drawer-backdrop"
      onClick={(event) => event.target === event.currentTarget && props.onClose()}
    >
      <aside
        ref={drawerElement}
        class="drawer webhook-editor-drawer"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
      >
        <header>
          <div>
            <p class="eyebrow">{isNew ? "New destination" : "Webhook destination"}</p>
            <h3 id={titleId}>{isNew ? "Create endpoint" : `Edit ${props.webhook!.name}`}</h3>
          </div>
          <button
            type="button"
            class="icon-button"
            onClick={props.onClose}
            aria-label="Close webhook editor"
          >
            <TbOutlineX size={20} />
          </button>
        </header>
        <form class="webhook-editor-form" onSubmit={submit}>
          <div class="webhook-editor-scroll">
            <section class="drawer-section webhook-editor-section">
              <p class="eyebrow">Destination</p>
              <div class="webhook-field-stack">
                <label>
                  Display name
                  <input
                    ref={nameInput}
                    value={name()}
                    onInput={(event) => setName(event.currentTarget.value)}
                    placeholder="Application lifecycle"
                    required
                    maxlength={100}
                  />
                </label>
                <label>
                  HTTPS endpoint
                  <input
                    type="url"
                    value={url()}
                    onInput={(event) => {
                      setUrl(event.currentTarget.value);
                      setUrlError("");
                    }}
                    placeholder="https://api.example.com/hooks/rustyauth"
                    required
                    aria-invalid={Boolean(urlError())}
                    aria-describedby={urlError() ? "webhook-url-error" : undefined}
                  />
                  <Show when={urlError()}>
                    <span id="webhook-url-error" class="field-error">{urlError()}</span>
                  </Show>
                </label>
              </div>
            </section>
            <section class="drawer-section webhook-editor-section">
              <fieldset>
                <legend>
                  <span class="eyebrow">Subscribed events</span>
                  <strong>{events().length} selected</strong>
                </legend>
                <div class="event-options">
                  <For each={webhookEvents}>
                    {(eventName) => (
                      <label classList={{ selected: events().includes(eventName) }}>
                        <input
                          type="checkbox"
                          checked={events().includes(eventName)}
                          onChange={() => toggleEvent(eventName)}
                        />
                        <span>
                          <TbOutlineCheck size={13} />
                        </span>
                        <code>{eventName}</code>
                      </label>
                    )}
                  </For>
                </div>
              </fieldset>
            </section>
            <section class="drawer-section webhook-editor-section">
              <p class="eyebrow">Delivery</p>
              <label class="delivery-state-control">
                State
                <select
                  value={enabled() ? "active" : "paused"}
                  onChange={(event) => setEnabled(event.currentTarget.value === "active")}
                >
                  <option value="active">Active — accept deliveries</option>
                  <option value="paused">Paused — retain queued events</option>
                </select>
              </label>
              <p class="field-hint">
                Signing secrets rotate separately so destination edits never expose credential material.
              </p>
            </section>
          </div>
          <footer class="webhook-editor-actions">
            <button type="button" class="button secondary" onClick={props.onClose}>
              Cancel
            </button>
            <button
              type="submit"
              class="button primary"
              disabled={!name().trim() || !events().length}
            >
              <TbOutlineCheck size={16} />
              {isNew ? "Create endpoint" : "Save changes"}
            </button>
          </footer>
        </form>
      </aside>
    </div>
  );
}

function MetricsPage() {
  return (
    <div class="content-stack">
      <section class="page-heading">
        <div>
          <p class="eyebrow">Auth telemetry</p>
          <h2>Authentication metrics</h2>
          <p>
            Bounded-cardinality aggregates with no user, identifier, credential or webhook URL dimensions.
          </p>
        </div>
        <div class="segmented">
          <button type="button" class="active">24 hours</button>
          <button type="button">7 days</button>
          <button type="button">28 days</button>
        </div>
      </section>
      <section class="metric-grid metrics-full">
        <For each={previewMetrics}>
          {(metric) => (
            <article class="metric-card">
              <p>{metric.label}</p>
              <strong>{metric.value}</strong>
              <span
                classList={{
                  positive: metric.direction === "up",
                  warning: metric.direction === "down",
                }}
              >
                {metric.change}
              </span>
              <small>{metric.note}</small>
            </article>
          )}
        </For>
      </section>
      <div class="overview-grid metrics-grid">
        <section class="panel volume-panel">
          <PanelHeader
            eyebrow="Authentication attempts"
            title="Volume and outcome"
          />
          <div
            class="bar-chart tall"
            aria-label="Authentication attempts by hour"
          >
            <For each={authVolume}>
              {(value, index) => (
                <span
                  style={{ height: `${Math.round(value / 1.6)}%` }}
                  title={`${index()}:00 · ${value}`}
                />
              )}
            </For>
          </div>
          <div class="chart-legend">
            <span>
              <i class="copper" />Successful
            </span>
            <span>
              <i class="graphite" />Failed
            </span>
            <strong>98.72% success</strong>
          </div>
        </section>
        <section class="panel">
          <PanelHeader eyebrow="Passkey funnel" title="Ceremony completion" />
          <FunnelRow label="Options started" value="12,940" percent={100} />
          <FunnelRow label="Authenticator opened" value="12,611" percent={97} />
          <FunnelRow label="Assertions returned" value="12,402" percent={96} />
          <FunnelRow label="Verified" value="12,238" percent={95} />
        </section>
      </div>
      <section class="panel failure-panel">
        <PanelHeader eyebrow="Failure analysis" title="Top rejection classes" />
        <div class="failure-grid">
          <FunnelRow label="Challenge expired" value="84" percent={44} />
          <FunnelRow label="Origin mismatch" value="41" percent={21} />
          <FunnelRow label="Counter regression" value="9" percent={5} />
          <FunnelRow label="User verification absent" value="59" percent={31} />
        </div>
      </section>
    </div>
  );
}

function FunnelRow(props: { label: string; value: string; percent: number }) {
  return (
    <div class="funnel-row">
      <div>
        <strong>{props.label}</strong>
        <span>{props.value}</span>
      </div>
      <meter min="0" max="100" value={props.percent}>{props.percent}%</meter>
      <small>{props.percent}%</small>
    </div>
  );
}

function EmptyState(
  props: { icon: IconComponent; title: string; detail: string },
) {
  return (
    <div class="empty-state">
      <props.icon size={28} />
      <strong>{props.title}</strong>
      <p>{props.detail}</p>
    </div>
  );
}

function StatusBadge(props: { status: string }) {
  const tone = () =>
    ["Active", "Healthy", "Owner", "Administrator"].includes(props.status)
      ? "good"
      : ["Retrying", "Needs verification"].includes(props.status)
      ? "warn"
      : "neutral";
  return (
    <span class={`status-badge ${tone()}`}>
      <i />
      {props.status}
    </span>
  );
}

function Definition(
  props: { label: string; value: string; mono?: boolean; copy?: boolean },
) {
  const [copied, setCopied] = createSignal(false);
  async function copy() {
    await navigator.clipboard.writeText(props.value);
    setCopied(true);
    globalThis.setTimeout(() => setCopied(false), 1500);
  }
  return (
    <div class="definition">
      <span>{props.label}</span>
      <strong classList={{ mono: props.mono }}>{props.value}</strong>
      <Show when={props.copy}>
        <button type="button" class="icon-button" onClick={copy}>
          {copied() ? <TbOutlineCheck size={16} /> : <TbOutlineCopy size={16} />}
        </button>
      </Show>
    </div>
  );
}

function initials(value: string) {
  return value.split(/\s+/).map((part) => part[0]).join("").slice(0, 2)
    .toUpperCase();
}
function formatDate(value: string) {
  return value
    ? new Intl.DateTimeFormat("en-GB", {
      day: "numeric",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    }).format(new Date(value))
    : "—";
}
