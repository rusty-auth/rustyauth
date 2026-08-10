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
