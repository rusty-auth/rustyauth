import { assertEquals, assertMatch, assertNotMatch } from "@std/assert";

const outputFor = (path: string) => path === "/" ? "dist/index.html" : `dist${path}/index.html`;

Deno.test("renders the RustyAuth landing page", async () => {
  const html = await Deno.readTextFile(outputFor("/"));
  assertMatch(html, /Authentication for the/);
  assertMatch(html, /agentic threat era/);
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
  assertMatch(html, /illustrative—not customer case studies/);
  assertMatch(html, /capability-grid/);
  assertNotMatch(html, /agent-thesis-compact|capability-editorial|pathway-list/);
  assertNotMatch(html, /codex-preview|Your site is taking shape/);
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
  assertMatch(hub, /\/solutions\/industry\/saas\.jpg/);
  assertMatch(hub, /\/solutions\/industry\/defence-secure-systems\.jpg/);

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
    "/docs/architecture",
    "/docs/identity-data",
    "/docs/api",
    "/docs/configuration",
    "/docs/recovery",
    "/docs/deployment",
  ];
  for (const path of routes) {
    const html = await Deno.readTextFile(outputFor(path));
    assertEquals(html.includes("Documentation"), true, path);
  }

  const gettingStarted = await Deno.readTextFile(outputFor("/docs/getting-started"));
  assertMatch(gettingStarted, /Deploy on Railway/);
  assertMatch(gettingStarted, /railway\.com\/new\/template\/rustyauth/);
});

Deno.test("documents the complete identity persistence boundary", async () => {
  const html = await Deno.readTextFile(outputFor("/docs/identity-data"));
  assertMatch(html, /The durable anchor is a UUID/);
  assertMatch(html, /Email and phone identifiers/);
  assertMatch(html, /Sessions and step-up state/);
  assertMatch(html, /Deliberately not persisted/);
  assertMatch(html, /IdentityService/);
});
