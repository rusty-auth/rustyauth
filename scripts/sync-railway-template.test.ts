import { assertEquals, assertRejects, assertThrows } from "@std/assert";
import { prepareTemplateConfig, RailwayTemplateConfig } from "./sync-railway-template.ts";

const source = JSON.parse(await Deno.readTextFile("railway.template.json")) as RailwayTemplateConfig;

Deno.test("canonical Railway template is the private three-service topology", () => {
  const config = prepareTemplateConfig(source);
  const services = Object.values(config.services ?? {});
  assertEquals(services.map((service) => service.name).sort(), [
    "RustyAuth",
    "SableDB",
    "rustyauth-dashboard",
  ]);
  assertEquals(
    services.filter((service) => Object.keys(service.networking?.serviceDomains ?? {}).length > 0).map((
      service,
    ) => service.name),
    ["rustyauth-dashboard"],
  );
  assertEquals(Object.values(config.buckets ?? {}).map((bucket) => bucket.name), ["rustyauth-backups"]);
});

Deno.test("release workflow can replace every pinned image digest", () => {
  const digest = `sha256:${"a".repeat(64)}`;
  const config = prepareTemplateConfig(source, {
    api: `ghcr.io/rusty-auth/rustyauth@${digest}`,
    dashboard: `ghcr.io/rusty-auth/dashboard@${digest}`,
    sabledb: `ghcr.io/rusty-auth/sabledb@${digest}`,
  });
  assertEquals(
    Object.values(config.services ?? {}).map((service) => service.source?.image).sort(),
    [
      `ghcr.io/rusty-auth/dashboard@${digest}`,
      `ghcr.io/rusty-auth/rustyauth@${digest}`,
      `ghcr.io/rusty-auth/sabledb@${digest}`,
    ],
  );
});

Deno.test("template validation rejects mutable images and an exposed API", () => {
  const mutable = structuredClone(source);
  const api = Object.values(mutable.services ?? {}).find((service) => service.name === "RustyAuth");
  if (api?.source != null) api.source.image = "ghcr.io/rusty-auth/rustyauth:latest";
  assertThrows(() => prepareTemplateConfig(mutable), Error, "immutable GHCR digest");

  const exposed = structuredClone(source);
  const exposedApi = Object.values(exposed.services ?? {}).find((service) => service.name === "RustyAuth");
  if (exposedApi != null) exposedApi.networking = { serviceDomains: { "<hasDomain>:8080": { port: 8080 } } };
  assertThrows(() => prepareTemplateConfig(exposed), Error, "only rustyauth-dashboard");
});

Deno.test("sync requires a Railway API token before making a request", async () => {
  const command = new Deno.Command(Deno.execPath(), {
    args: ["run", "--allow-env", "--allow-read=railway.template.json", "scripts/sync-railway-template.ts"],
    env: { RAILWAY_API_TOKEN: "" },
    stdout: "piped",
    stderr: "piped",
  });
  const result = await command.output();
  assertEquals(result.success, false);
  await assertRejects(
    () =>
      result.success ? Promise.resolve() : Promise.reject(new Error(new TextDecoder().decode(result.stderr))),
    Error,
    "RAILWAY_API_TOKEN is required",
  );
});
