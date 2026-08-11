const clientPath = "console/src/fleet_client.rs";
const gatewayPath = "console/Caddyfile";
const appPath = "console/src/app.rs";
const authRouterPath = "src/auth.rs";

const [client, gateway, app, authRouter] = await Promise.all([
  Deno.readTextFile(clientPath),
  Deno.readTextFile(gatewayPath),
  Deno.readTextFile(appPath),
  Deno.readTextFile(authRouterPath),
]);

const clientHttpPaths = new Set(
  [...client.matchAll(/"((?:\/v1|\/\.well-known)[A-Za-z0-9_./-]*)"/g)].map((match) => match[1]),
);
// The dashboard is the only public service in the integrated topology. Test
// the complete production REST contract, not only the subset the current WASM
// client happens to call, so SDK/token routes cannot silently fall through to
// index.html. The local agent handoff is deliberately local-development-only.
const excludedProductionPaths = new Set(["/v1/local-agent-handoff"]);
const authHttpPaths = new Set(
  [...authRouter.matchAll(/\.route\(\s*"((?:\/v1|\/\.well-known)[A-Za-z0-9_./-]*)"/gs)]
    .map((match) => match[1])
    .filter((path) => !excludedProductionPaths.has(path)),
);
const httpPaths = new Set([...clientHttpPaths, ...authHttpPaths]);
const gatewayTokens = new Set(gateway.split(/\s+/));
const missingHttpPaths = [...httpPaths].filter((path) => !gatewayTokens.has(path));

const rpcServices = new Set(
  [...client.matchAll(/const [A-Z_]+_PREFIX: &str = "\/(rustyauth\.[^"]+)\/";/g)].map(
    (match) => match[1],
  ),
);
const normalizedGateway = gateway.replaceAll(/\\\./g, ".");
const rpcAlternatives = normalizedGateway.match(/\^\/rustyauth\.\(([^)]+)\)/)?.[1].split("|") ?? [];
const gatewayRpcServices = new Set(rpcAlternatives.map((service) => `rustyauth.${service}`));
const missingRpcServices = [...rpcServices].filter((service) => !gatewayRpcServices.has(service));

if (missingHttpPaths.length > 0 || missingRpcServices.length > 0) {
  if (missingHttpPaths.length > 0) {
    console.error(`Dashboard gateway is missing HTTP routes: ${missingHttpPaths.sort().join(", ")}`);
  }
  if (missingRpcServices.length > 0) {
    console.error(`Dashboard gateway is missing RPC services: ${missingRpcServices.sort().join(", ")}`);
  }
  Deno.exit(1);
}

if (!normalizedGateway.includes("/[A-Za-z0-9]+$")) {
  console.error("Dashboard RPC gateway must remain method-bounded and end-anchored");
  Deno.exit(1);
}

if (gateway.includes("style-src 'self' 'unsafe-inline'")) {
  console.error("Dashboard CSP must not permit inline styles");
  Deno.exit(1);
}

if (!gateway.includes("style-src 'self'")) {
  console.error("Dashboard CSP must explicitly confine styles to the dashboard origin");
  Deno.exit(1);
}

if (app.includes("dangerous_inner_html") || /\bstyle\s*\{/.test(app)) {
  console.error("Dashboard styles must be static assets; inline style injection is forbidden");
  Deno.exit(1);
}

if (!app.includes('document::Stylesheet { href: asset!("/assets/styles.css") }')) {
  console.error("Dashboard must load its stylesheet through the Dioxus static-asset pipeline");
  Deno.exit(1);
}

console.log(
  `Dashboard gateway covers ${httpPaths.size} HTTP routes and ${rpcServices.size} RPC services used by the client.`,
);
