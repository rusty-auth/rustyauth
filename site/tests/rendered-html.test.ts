import { assertEquals, assertMatch, assertNotMatch } from "@std/assert";

const outputFor = (path: string) => path === "/" ? "dist/index.html" : `dist${path}/index.html`;

async function* renderedHtml(directory = "dist"): AsyncGenerator<string> {
  for await (const entry of Deno.readDir(directory)) {
    const path = `${directory}/${entry.name}`;
    if (entry.isDirectory) yield* renderedHtml(path);
    else if (entry.isFile && entry.name.endsWith(".html")) yield path;
  }
}

Deno.test("renders the RustyAuth landing page", async () => {
  const html = await Deno.readTextFile(outputFor("/"));
  assertMatch(html, /Self-Hosted Passkey Authentication in Rust/);
  assertMatch(html, /Self-hosted passkey authentication/);
  assertEquals(html.match(/<h1\b/g)?.length, 1);
  assertMatch(html, /Built in Rust/);
  assertMatch(html, /SableDB key-value store/);
  assertMatch(html, /Fast, lean, self-hosted/);
  assertMatch(html, /SoftwareSourceCode/);
  assertMatch(html, /\/passkey-authentication/);
  assertMatch(html, /\/self-hosted-authentication/);
  assertMatch(html, /\/authentication-in-rust/);
  assertMatch(html, /\/authentication-events/);
  assertMatch(html, /\/fleet/);
  assertMatch(html, /Many realms/);
  assertMatch(html, /Attacks move faster/);
  assertNotMatch(html, /Attack moves faster/);
  assertMatch(html, /data-hero-carousel/);
  assertMatch(html, /Pause rotating headlines/);
  assertMatch(html, /Start with SaaS/);
  assertMatch(html, /Gambling and gaming/);
  assertMatch(html, /Banking and payments/);
  assertMatch(html, /Healthcare products/);
  assertMatch(html, /Defence and secure systems/);
  assertMatch(html, /Security infrastructure/);
  assertMatch(html, /solution-link-grid/);
  assertNotMatch(html, /Deploy on Railway/);
  assertNotMatch(html, /railway\.com\/new\/template\/rustyauth/);
  assertMatch(html, /scheduled backups and clean-room restore/i);
  assertMatch(html, /Native applications remain post-1.0 previews/);
  assertNotMatch(html, /Signed native packages/);
  assertMatch(html, /illustrative—not customer case studies/);
  assertMatch(html, /capability-grid/);
  assertNotMatch(html, /agent-thesis-compact|capability-editorial|pathway-list/);
  assertNotMatch(html, /codex-preview|Your site is taking shape/);
  const header = html.match(/<header class="site-header">[\s\S]*?<\/header>/)?.[0] ?? "";
  assertNotMatch(header, />GitHub<\/a>/);
  assertMatch(header, /github-proof/);
});

Deno.test("renders the Fleet flagship page honestly", async () => {
  const html = await Deno.readTextFile(outputFor("/fleet"));
  assertMatch(html, /Multi-Cloud Authentication Management/);
  assertMatch(html, /Fleet-native/);
  assertMatch(html, /One identity realm anywhere/);
  assertMatch(html, /data-hero-carousel/);
  assertMatch(html, /Pause rotating headlines/);
  assertMatch(html, /Central coordination/);
  assertMatch(html, /Multi-cloud topology/);
  assertMatch(html, /Fleet Analytics/);
  assertMatch(html, /Illustrative Fleet view/);
  assertMatch(html, /Analytics V1 contract shipped/);
  assertMatch(html, /1\.0\.0 GA scope/);
  assertMatch(html, /organization-policy canaries continue as assurance/);
  assertMatch(html, /railway\.com\/new\/template\/rustyauth/);
  assertMatch(html, /standalone evaluation realm, not the complete/);
  assertMatch(html, /Fleet never receives a realm SableDB URL/);
  assertEquals(html.match(/<h1\b/g)?.length, 1);
});

Deno.test("renders the RustyAuth differentiation and trade-off page", async () => {
  const html = await Deno.readTextFile(outputFor("/why-rustyauth"));
  assertMatch(html, /Fleet-Native Identity Infrastructure/);
  assertMatch(html, /Fleet-native identity infrastructure/);
  assertMatch(html, /One identity realm anywhere/);
  assertMatch(html, /Scale by cells first/);
  assertMatch(html, /Rauthy/);
  assertMatch(html, /Kanidm/);
  assertMatch(html, /Keycloak/);
  assertMatch(html, /authentik/);
  assertMatch(html, /ZITADEL/);
  assertMatch(html, /Deliberate trade-offs/);
  assertMatch(html, /Choose RustyAuth when/);
  assertMatch(html, /Choose an established provider when/);
  assertMatch(html, /supported server\/container\/web release/);
  assertEquals(html.match(/<h1\b/g)?.length, 1);
});

Deno.test("renders search-focused developer guides", async () => {
  const guides = [
    ["/passkey-authentication", /Passkey authentication for developers/, /How passkey authentication works/],
    ["/self-hosted-authentication", /Self-hosted authentication/, /Why teams self-host authentication/],
    ["/authentication-in-rust", /Authentication in Rust/, /Why Rust for authentication infrastructure/],
    ["/authentication-events", /Connect authentication events/, /Stream signups over gRPC/],
  ] as const;

  for (const [path, heading, evidence] of guides) {
    const html = await Deno.readTextFile(outputFor(path));
    assertMatch(html, heading);
    assertMatch(html, evidence);
    assertMatch(html, /BreadcrumbList/);
    assertMatch(html, /Updated 9 August 2026/);
    assertEquals(html.match(/<h1\b/g)?.length, 1);
  }

  const index = await Deno.readTextFile(outputFor("/guides"));
  assertMatch(index, /RustyAuth developer guides/);
  assertMatch(index, /\/authentication-events/);
  assertEquals(index.match(/<h1\b/g)?.length, 1);
});

Deno.test("publishes crawler controls and a real 404 document", async () => {
  const robots = await Deno.readTextFile("dist/robots.txt");
  assertMatch(robots, /User-agent: \*/);
  assertMatch(robots, /Sitemap: https:\/\/rustyauth\.dev\/sitemap\.xml/);

  const sitemap = await Deno.readTextFile("dist/sitemap.xml");
  assertMatch(sitemap, /<urlset xmlns="http:\/\/www\.sitemaps\.org\/schemas\/sitemap\/0\.9">/);
  assertMatch(sitemap, /https:\/\/rustyauth\.dev\/passkey-authentication\//);
  assertMatch(sitemap, /https:\/\/rustyauth\.dev\/self-hosted-authentication\//);
  assertMatch(sitemap, /https:\/\/rustyauth\.dev\/authentication-in-rust\//);
  assertMatch(sitemap, /https:\/\/rustyauth\.dev\/authentication-events\//);
  assertMatch(sitemap, /https:\/\/rustyauth\.dev\/guides\//);
  assertMatch(sitemap, /https:\/\/rustyauth\.dev\/fleet\//);
  assertMatch(sitemap, /https:\/\/rustyauth\.dev\/benchmarks\//);
  assertMatch(sitemap, /https:\/\/rustyauth\.dev\/why-rustyauth\//);
  assertMatch(sitemap, /https:\/\/rustyauth\.dev\/docs\/integration\//);

  const notFound = await Deno.readTextFile("dist/404.html");
  assertMatch(notFound, /Page not found/);
  assertMatch(notFound, /name="robots" content="noindex, follow"/);
});

Deno.test("renders the reviewed single-realm capacity baseline", async () => {
  const html = await Deno.readTextFile(outputFor("/benchmarks"));
  assertMatch(html, /Benchmarks,/);
  assertMatch(html, /Active baseline/);
  assertMatch(html, /Separate benchmark project/);
  assertMatch(html, /Starter single-realm Railway baseline/);
  assertMatch(html, /5,600/);
  assertMatch(html, /76\.4562/);
  assertMatch(html, /Medium-tier 28-day organization query/);
  assertMatch(html, /239\.5325/);
  assertMatch(html, /8,064,000/);
  assertMatch(html, /lower bound rather than an absolute breakpoint/i);
  assertMatch(html, /Each qualified realm adds another capacity unit/);
  assertMatch(html, /Does this prove Facebook scale/);
  assertMatch(html, /No—not yet/);
  assertMatch(html, /Latency remains flat as traffic rises/);
  assertMatch(html, /high-traffic product journey/i);
  assertMatch(html, /2,400 RPS traffic spike/);
  assertMatch(html, /Not demonstrated/);
  assertEquals(html.match(/<h1\b/g)?.length, 1);

  const catalogue = JSON.parse(await Deno.readTextFile("dist/benchmarks/catalog.json"));
  assertEquals(catalogue.schemaVersion, 2);
  assertEquals(catalogue.programs[0].state, "active");
  assertEquals(
    catalogue.reports[0].results.find((result: { key: string }) =>
      result.key === "sustainable_authenticated_rps"
    ).value,
    800,
  );
});

Deno.test("renders every industry solution route", async () => {
  const routes = [
    "/solutions",
    "/solutions/saas",
    "/solutions/gambling-gaming",
    "/solutions/banking-payments",
    "/solutions/financial-services",
    "/solutions/healthcare-products",
    "/solutions/defence-secure-systems",
  ];
  for (const path of routes) {
    const html = await Deno.readTextFile(outputFor(path));
    assertMatch(html, /Reference scenario|reference scenario/);
    assertNotMatch(html, /HIPAA compliant|FCA approved|defence accredited/);
  }

  const hub = await Deno.readTextFile(outputFor("/solutions"));
  assertMatch(hub, /\/solutions\/industry\/saas\.svg/);
  assertMatch(hub, /\/solutions\/industry\/defence-secure-systems\.svg/);

  const saas = await Deno.readTextFile(outputFor("/solutions/saas"));
  assertMatch(saas, /4-step authentication path/);
  assertMatch(saas, /solution-boundary-stage/);
  assertMatch(saas, /solution-boundary-legend/);

  const defence = await Deno.readTextFile(outputFor("/solutions/defence-secure-systems"));
  assertMatch(defence, /disconnected enclave/);
  assertMatch(defence, /Offline signed release bundles/);

  const banking = await Deno.readTextFile(outputFor("/solutions/banking-payments"));
  assertMatch(banking, /does not replace/);
  assertMatch(banking, /Transaction signing or payment approval/);
});

Deno.test("renders every documentation route", async () => {
  const routes = [
    "/docs",
    "/docs/getting-started",
    "/docs/integration",
    "/docs/architecture",
    "/docs/identity-data",
    "/docs/fleet",
    "/docs/fleet-analytics",
    "/docs/api",
    "/docs/fleet-analytics-v1",
    "/docs/configuration",
    "/docs/deployment",
    "/docs/kubernetes",
    "/docs/security",
    "/docs/recovery",
    "/docs/project-status",
  ];
  for (const path of routes) {
    const html = await Deno.readTextFile(outputFor(path));
    assertEquals(html.includes("Documentation"), true, path);
  }

  const gettingStarted = await Deno.readTextFile(outputFor("/docs/getting-started"));
  assertMatch(gettingStarted, /scripts\/local-stack standalone up/);
  assertNotMatch(gettingStarted, /vtr-local-enrolment-only/);

  const architecture = await Deno.readTextFile(outputFor("/docs/architecture"));
  assertMatch(architecture, /One realm, three services/);
  assertMatch(architecture, /Fleet is a separate management plane/);

  const kubernetes = await Deno.readTextFile(outputFor("/docs/kubernetes"));
  assertMatch(kubernetes, /rustyauth-integrated/);
  assertMatch(kubernetes, /rustyauth-fleet/);
  assertMatch(kubernetes, /rustyauth-realm/);
  assertMatch(kubernetes, /AUTH_MASTER_KEY_HEX/);
  assertMatch(kubernetes, /Civo Kubernetes uses K3s/);

  const fleet = await Deno.readTextFile(outputFor("/docs/fleet"));
  assertMatch(fleet, /No database connection strings/);
  assertMatch(fleet, /Dioxus Fleet dashboard/);

  const fleetAnalytics = await Deno.readTextFile(outputFor("/docs/fleet-analytics"));
  assertMatch(fleetAnalytics, /Fleet Analytics V1 is supported in 1\.0\.0/);
  assertMatch(fleetAnalytics, /Fleet does not continuously introspect arbitrary customer buckets/);
  assertMatch(fleetAnalytics, /GreptimeDB is an internal adapter/);

  const fleetAnalyticsV1 = await Deno.readTextFile(outputFor("/docs/fleet-analytics-v1"));
  assertMatch(fleetAnalyticsV1, /Unknown versions rejected/);
  assertMatch(fleetAnalyticsV1, /Active account observations are not unique people/);
  assertMatch(fleetAnalyticsV1, /Signed Parquet archive/);

  const docsHome = await Deno.readTextFile(outputFor("/docs"));
  assertMatch(docsHome, /Search documentation/);
  assertMatch(docsHome, /Choose your path/);
  assertMatch(docsHome, /Native applications are post-1.0 previews/);

  const projectStatus = await Deno.readTextFile(outputFor("/docs/project-status"));
  assertMatch(projectStatus, /Native clients<\/td><td>Preview/);
  assertMatch(projectStatus, /does not block the server, container and web GA/);

  const configuration = await Deno.readTextFile(outputFor("/docs/configuration"));
  assertMatch(configuration, /One contract for every environment/);
  assertMatch(configuration, /Configuration source precedence/);
  assertMatch(configuration, /RUSTYAUTH_CONFIG_YAML/);
  assertMatch(configuration, /Managed by YAML/);
  assertMatch(configuration, /Durable delivery is supported in 1\.0\.0/);

  const api = await Deno.readTextFile(outputFor("/docs/api"));
  assertMatch(api, /Webhook contract and IaC ownership/);
  assertMatch(api, /managementSource/);
  assertMatch(api, /webhooks\.manage/);
  assertMatch(api, /Durable delivery is supported in 1\.0\.0/);

  const recovery = await Deno.readTextFile(outputFor("/docs/recovery"));
  assertMatch(recovery, /complete Realm or Fleet workspace/);
  assertMatch(recovery, /RAUTHBK3/);
  assertMatch(recovery, /Postcard \+ Zstandard/);
  assertMatch(recovery, /COMPLIANCE/);
  assertMatch(recovery, /Do not repair a partial target in place/);
  assertMatch(recovery, /monthly external drill/);
});

Deno.test("documents the complete identity persistence boundary", async () => {
  const html = await Deno.readTextFile(outputFor("/docs/identity-data"));
  assertMatch(html, /The durable anchor is a UUID/);
  assertMatch(html, /Email and phone identifiers/);
  assertMatch(html, /Sessions and step-up state/);
  assertMatch(html, /Deliberately not persisted/);
  assertMatch(html, /IdentityService/);
});

Deno.test("every rendered internal link resolves", async () => {
  const missing: string[] = [];
  for await (const source of renderedHtml()) {
    const html = await Deno.readTextFile(source);
    for (const match of html.matchAll(/href="(\/[^"#?]*)/g)) {
      const href = match[1];
      const destination = href === "/"
        ? "dist/index.html"
        : /\.[a-z0-9]+$/i.test(href)
        ? `dist${href}`
        : `dist${href}/index.html`;
      try {
        await Deno.stat(destination);
      } catch (error) {
        if (!(error instanceof Deno.errors.NotFound)) throw error;
        missing.push(`${source} -> ${href}`);
      }
    }
  }
  assertEquals(missing, []);
});
