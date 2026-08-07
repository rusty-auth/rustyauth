import { assertEquals, assertMatch, assertNotMatch } from "@std/assert";

const outputFor = (path: string) => path === "/" ? "dist/index.html" : `dist${path}/index.html`;

Deno.test("renders the RustyAuth landing page", async () => {
  const html = await Deno.readTextFile(outputFor("/"));
  assertMatch(html, /Passkeys without/);
  assertMatch(html, /Built in Rust/);
  assertMatch(html, /Built on SableDB/);
  assertMatch(html, /GitHub/);
  assertMatch(html, /Deploy on Railway/);
  assertMatch(html, /railway\.com\/new\/template\/rustyauth/);
  assertMatch(html, /Why Rust/);
  assertMatch(html, /Protobuf \+ gRPC event stream/);
  assertMatch(html, /Connect, gRPC-Web and native gRPC/);
  assertMatch(html, /Private identity gRPC control plane/);
  assertNotMatch(html, /codex-preview|Your site is taking shape/);
});

Deno.test("documents the event streaming wire", async () => {
  const html = await Deno.readTextFile(outputFor("/docs/api"));
  assertMatch(html, /rustyauth\.events\.v1\.AuthEventService\/Subscribe/);
  assertMatch(html, /AUTH_EVENT_RPC_TOKEN/);
  assertMatch(html, /at least once/i);
});

Deno.test("documents the private identity wire", async () => {
  const html = await Deno.readTextFile(outputFor("/docs/api"));
  assertMatch(html, /rustyauth\.identity\.v1\.IdentityService/);
  assertMatch(html, /AUTH_IDENTITY_RPC_TOKEN/);
  assertMatch(html, /never contain WebAuthn credential/);
});

Deno.test("renders every documentation route", async () => {
  const routes = [
    "/docs",
    "/docs/getting-started",
    "/docs/architecture",
    "/docs/api",
    "/docs/configuration",
    "/docs/deployment",
  ];
  for (const path of routes) {
    const html = await Deno.readTextFile(outputFor(path));
    assertEquals(html.includes("Documentation"), true, path);
  }
});
