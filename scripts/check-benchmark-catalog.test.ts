import { assertEquals, assertMatch } from "@std/assert";
import { validateBenchmarkCatalog } from "./check-benchmark-catalog.ts";

const catalogue = () => ({
  schemaVersion: 2,
  updatedAt: "2026-08-10T10:00:00Z",
  publicationPolicy: { summary: "Synthetic only", isolation: "Separate project", promotion: "Reviewed" },
  programs: [{
    id: "single-realm-capacity",
    title: "Capacity",
    state: "awaiting-baseline",
    summary: "Capacity programme",
    schedule: [],
    resourceTiers: [],
    userProfiles: [],
    gates: [],
    decisionGuide: {
      headline: "Measured",
      measured: "Measured evidence",
      inferred: "Declared inference",
      notDemonstrated: "Explicit boundary",
      scaleStrategy: "Cells",
    },
    enterpriseProfile: {
      name: "Enterprise",
      mix: [{ operation: "Read", percent: 100 }],
    },
  }],
  reports: [],
});

Deno.test("accepts an awaiting benchmark programme without invented results", () => {
  assertEquals(validateBenchmarkCatalog(catalogue()), []);
});

Deno.test("rejects duplicate programme identifiers", () => {
  const value = catalogue();
  value.programs.push({ ...value.programs[0] });
  assertMatch(validateBenchmarkCatalog(value).join("\n"), /id must be unique/);
});

Deno.test("rejects a passed realm capacity claim without complete measured evidence", () => {
  const value = catalogue() as Record<string, unknown>;
  value.reports = [{
    id: "realm-result",
    programId: "single-realm-capacity",
    title: "Realm result",
    status: "passed",
    qualification: "Railway",
    observedAt: "2026-08-10T10:00:00Z",
    release: "1.0.0",
    commit: "abc",
    environment: "Railway",
    methodologyVersion: "1",
    summary: "Incomplete on purpose",
    dataset: [],
    results: [{
      key: "signin_p95_ms",
      label: "Sign-in p95",
      value: 100,
      unit: "ms",
      threshold: "< 250 ms",
      outcome: "pass",
    }],
    evidence: [{ label: "Run", url: "https://example.com/run" }],
  }];
  const errors = validateBenchmarkCatalog(value).join("\n");
  assertMatch(errors, /missing required capacity result registered_accounts/);
  assertMatch(errors, /imageDigests is required/);
});

Deno.test("enterprise reports require the operating rate, boundary and latency waterfall", () => {
  const value = catalogue() as Record<string, unknown>;
  value.reports = [{
    id: "enterprise-result",
    programId: "single-realm-capacity",
    title: "Enterprise result",
    status: "passed",
    qualification: "Railway",
    observedAt: "2026-08-11T01:00:00Z",
    release: "1.0.0",
    commit: "abc",
    environment: "Railway",
    methodologyVersion: "single-realm-enterprise-v2",
    summary: "Incomplete on purpose",
    dataset: [],
    results: [],
    evidence: [{ label: "Run", url: "https://example.com/run" }],
  }];
  const errors = validateBenchmarkCatalog(value).join("\n");
  assertMatch(errors, /missing required enterprise result supported_operating_rps/);
  assertMatch(errors, /missing required enterprise result first_failing_rps/);
  assertMatch(errors, /missing required enterprise result sable_p95_ms/);
  assertMatch(errors, /missing required enterprise result soak_duration_seconds/);
  assertMatch(errors, /missing required enterprise result railway_soak_monthly_resource_usd/);
  assertMatch(errors, /realmScaling is required/);
});

Deno.test("enterprise reports reject overstated operating and realm-cell claims", () => {
  const value = catalogue() as Record<string, unknown>;
  const requiredResults = [
    "registered_accounts",
    "valid_sessions",
    "supported_typical_active_users",
    "signin_rps",
    "signin_p95_ms",
    "mixed_authenticated_p95_ms",
    "external_path_p95_ms",
    "application_p95_ms",
    "sable_p95_ms",
  ].map((key) => ({
    key,
    label: key,
    value: key === "signin_p95_ms" ? 0 : 1,
    unit: "count",
    threshold: "measured",
    outcome: "pass",
  }));
  value.reports = [{
    id: "enterprise-result",
    programId: "single-realm-capacity",
    title: "Enterprise result",
    status: "passed",
    qualification: "Railway",
    observedAt: "2026-08-11T01:00:00Z",
    release: "1.0.0",
    commit: "abc",
    environment: "Railway",
    methodologyVersion: "single-realm-enterprise-v2",
    summary: "Invalid on purpose",
    dataset: [],
    results: [
      ...requiredResults,
      {
        key: "sustainable_authenticated_rps",
        label: "qualified",
        value: 500,
        unit: "RPS",
        threshold: "measured",
        outcome: "pass",
      },
      {
        key: "supported_operating_rps",
        label: "operating",
        value: 600,
        unit: "RPS",
        threshold: "bounded",
        outcome: "pass",
      },
      {
        key: "first_failing_rps",
        label: "failure",
        value: 500,
        unit: "RPS",
        threshold: "observed",
        outcome: "observe",
      },
      {
        key: "soak_authenticated_rps",
        label: "soak rate",
        value: 500,
        unit: "RPS",
        threshold: "operating rate",
        outcome: "pass",
      },
      {
        key: "soak_duration_seconds",
        label: "soak duration",
        value: 3599,
        unit: "seconds",
        threshold: "one hour",
        outcome: "pass",
      },
      {
        key: "soak_mixed_p95_ms",
        label: "soak p95",
        value: 0,
        unit: "ms",
        threshold: "measured",
        outcome: "pass",
      },
      {
        key: "soak_failed_requests",
        label: "soak failures",
        value: 0,
        unit: "requests",
        threshold: "below 0.1%",
        outcome: "pass",
      },
      {
        key: "railway_soak_monthly_resource_usd",
        label: "resource cost",
        value: 0,
        unit: "USD/month",
        threshold: "observed",
        outcome: "observe",
      },
      {
        key: "railway_soak_monthly_egress_usd",
        label: "egress cost",
        value: 0,
        unit: "USD/month",
        threshold: "observed",
        outcome: "observe",
      },
    ],
    realmScaling: {
      measuredRealmCells: 2,
      model: "unbounded",
      formula: "",
      limitations: [],
    },
    capacityModels: [{
      profile: "Typical application",
      requestsPerMinute: 6,
      activeUsers: 1,
      basis: "measured",
    }],
    charts: [{
      id: "latency",
      title: "Latency",
      description: "Measured latency",
      xUnit: "RPS",
      yUnit: "ms",
      series: [{ name: "p95", points: [{ x: 1, y: 1 }, { x: 2, y: 2 }] }],
    }],
    confidence: { measured: "one realm", inferred: "more realms", notProven: "shared limits" },
    imageDigests: {
      api: `sha256:${"a".repeat(64)}`,
      dashboard: `sha256:${"b".repeat(64)}`,
      sableDb: `sha256:${"c".repeat(64)}`,
    },
    evidence: [{ label: "Run", url: "https://example.com/run" }],
  }];
  const errors = validateBenchmarkCatalog(value).join("\n");
  assertMatch(errors, /supported_operating_rps must not exceed qualified throughput/);
  assertMatch(errors, /supported_operating_rps must retain 30 percent throughput headroom/);
  assertMatch(errors, /first_failing_rps must be above qualified throughput/);
  assertMatch(errors, /signin_p95_ms must contain an observed positive duration/);
  assertMatch(errors, /soak_authenticated_rps must qualify the published operating rate/);
  assertMatch(errors, /soak_duration_seconds must cover at least one hour/);
  assertMatch(errors, /soak_mixed_p95_ms must contain an observed positive duration/);
  assertMatch(errors, /railway_soak_monthly_resource_usd must contain an observed run-rate/);
  assertMatch(errors, /railway_soak_monthly_egress_usd must contain an observed run-rate/);
  assertMatch(errors, /measuredRealmCells must be 1/);
  assertMatch(errors, /model must be linear-independent-cells/);
  assertMatch(errors, /formula is required/);
  assertMatch(errors, /limitations must contain explicit assumptions/);
  assertMatch(errors, /activeUsers must use the published operating rate/);
  assertMatch(errors, /supported_typical_active_users must match the typical capacity model/);
});
