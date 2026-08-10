import { assertEquals } from "@std/assert";
import { CI_AREAS, classifyCiChanges } from "./ci-changes.ts";

Deno.test("workflow classifier changes force a full qualification", () => {
  const selected = classifyCiChanges([".github/workflows/ci.yml"]);
  for (const area of CI_AREAS) assertEquals(selected[area], true, area);
});

Deno.test("Railway workflow changes stay within workflow and policy lanes", () => {
  assertEquals(classifyCiChanges([".github/workflows/railway-production.yml"]), {
    workflow: true,
    protocol: false,
    client: false,
    site: false,
    policy: true,
    infrastructure: false,
    rust: false,
    console: false,
    supply_chain: false,
    recovery: false,
    api_image: false,
    dashboard_image: false,
    sabledb_image: false,
  });
});

Deno.test("Rust service changes select runtime, integration and API image lanes", () => {
  const selected = classifyCiChanges(["src/backup/snapshot.rs"]);
  assertEquals(selected.rust, true);
  assertEquals(selected.recovery, true);
  assertEquals(selected.api_image, true);
  assertEquals(selected.console, false);
  assertEquals(selected.dashboard_image, false);
  assertEquals(selected.sabledb_image, false);
  assertEquals(selected.site, false);
});

Deno.test("site-only changes do not compile Rust or containers", () => {
  const selected = classifyCiChanges(["site/src/pages/index.astro"]);
  assertEquals(selected.site, true);
  assertEquals(selected.rust, false);
  assertEquals(selected.recovery, false);
  assertEquals(selected.api_image, false);
  assertEquals(selected.dashboard_image, false);
  assertEquals(selected.sabledb_image, false);
});

Deno.test("console changes qualify the dashboard without the API", () => {
  const selected = classifyCiChanges(["console/src/app.rs"]);
  assertEquals(selected.console, true);
  assertEquals(selected.dashboard_image, true);
  assertEquals(selected.api_image, false);
  assertEquals(selected.sabledb_image, false);
  assertEquals(selected.rust, false);
});

Deno.test("benchmark catalogue changes rebuild only its two published surfaces", () => {
  const selected = classifyCiChanges(["benchmarks/catalog.json"]);
  assertEquals(selected.site, true);
  assertEquals(selected.console, true);
  assertEquals(selected.dashboard_image, true);
  assertEquals(selected.rust, false);
  assertEquals(selected.recovery, false);
  assertEquals(selected.api_image, false);
  assertEquals(selected.sabledb_image, false);
  assertEquals(selected.infrastructure, false);
});

Deno.test("benchmark runner changes do not rebuild production images or product surfaces", () => {
  const selected = classifyCiChanges([
    "Dockerfile.benchmark",
    "src/bin/rustyauth-benchmark.rs",
    "benchmarks/k6/single-realm.js",
    "benchmarks/k6/webauthn.js",
    "benchmarks/k6/webauthn.test.ts",
    "benchmarks/run-passkey-companion.sh",
    "benchmarks/k6/utf8.js",
    "benchmarks/k6/utf8.test.ts",
    "benchmarks/run-starter-baseline.sh",
    "railway.benchmark.json",
  ]);
  assertEquals(selected.policy, true);
  assertEquals(selected.supply_chain, true);
  assertEquals(selected.site, false);
  assertEquals(selected.console, false);
  assertEquals(selected.rust, true);
  assertEquals(selected.recovery, false);
  assertEquals(selected.api_image, false);
  assertEquals(selected.dashboard_image, false);
  assertEquals(selected.sabledb_image, false);
});

Deno.test("dependency and protocol changes fan out to every consumer", () => {
  const selected = classifyCiChanges(["Cargo.lock", "proto/rustyauth/fleet/v1/fleet.proto"]);
  assertEquals(selected.protocol, true);
  assertEquals(selected.rust, true);
  assertEquals(selected.console, true);
  assertEquals(selected.supply_chain, true);
  assertEquals(selected.recovery, true);
  assertEquals(selected.api_image, true);
  assertEquals(selected.dashboard_image, false);
  assertEquals(selected.sabledb_image, false);
});

Deno.test("unknown paths fail safe by selecting every lane", () => {
  const selected = classifyCiChanges(["helm/rustyauth/Chart.yaml"]);
  for (const area of CI_AREAS) assertEquals(selected[area], true, area);
});

Deno.test("Helm chart changes select deployment policy without rebuilding images", () => {
  const selected = classifyCiChanges(["charts/rustyauth-realm/values.yaml"]);
  assertEquals(selected.policy, true);
  assertEquals(selected.api_image, false);
  assertEquals(selected.dashboard_image, false);
  assertEquals(selected.sabledb_image, false);
  assertEquals(selected.rust, false);
});

Deno.test("SableDB image changes select one dedicated container lane", () => {
  const selected = classifyCiChanges(["sabledb/Dockerfile"]);
  assertEquals(selected.sabledb_image, true);
  assertEquals(selected.api_image, false);
  assertEquals(selected.dashboard_image, false);
  assertEquals(selected.rust, false);
  assertEquals(selected.console, false);
  assertEquals(selected.site, false);
});

Deno.test("vendored SableDB revisions select image, supply-chain and recovery only", () => {
  const selected = classifyCiChanges(["vendor/sabledb"]);
  assertEquals(selected.sabledb_image, true);
  assertEquals(selected.supply_chain, true);
  assertEquals(selected.recovery, true);
  assertEquals(selected.api_image, false);
  assertEquals(selected.dashboard_image, false);
  assertEquals(selected.rust, false);
  assertEquals(selected.console, false);
  assertEquals(selected.site, false);
  assertEquals(selected.policy, false);
});

Deno.test("submodule configuration qualifies the pinned SableDB supply chain", () => {
  const selected = classifyCiChanges([".gitmodules"]);
  assertEquals(selected.sabledb_image, true);
  assertEquals(selected.supply_chain, true);
  assertEquals(selected.recovery, true);
  assertEquals(selected.api_image, false);
  assertEquals(selected.dashboard_image, false);
});

Deno.test("shared healthcheck code rebuilds each consuming runtime image", () => {
  const selected = classifyCiChanges(["container-healthcheck/sabledb-entrypoint/main.go"]);
  assertEquals(selected.sabledb_image, true);
  assertEquals(selected.api_image, true);
  assertEquals(selected.dashboard_image, true);
  assertEquals(selected.rust, false);
  assertEquals(selected.console, false);
});
