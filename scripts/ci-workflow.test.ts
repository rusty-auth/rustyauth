import { assert, assertEquals, assertStringIncludes } from "jsr:@std/assert@1.0.19";

const read = (path: string): string => Deno.readTextFileSync(new URL(`../${path}`, import.meta.url));

const ci = read(".github/workflows/ci.yml");
const assurance = read(".github/workflows/assurance.yml");
const fuzz = read(".github/workflows/fuzz.yml");
const native = read(".github/workflows/native-packaging.yml");

Deno.test("blocking CI is change-aware and exposes one stable result", () => {
  assertStringIncludes(ci, "name: Changed areas");
  assertStringIncludes(ci, "name: CI result");
  assertStringIncludes(ci, "cancel-in-progress: true");
  assertStringIncludes(ci, "needs.changes.outputs.rust == 'true'");
  assertStringIncludes(ci, "needs.changes.outputs.console == 'true'");
  assertStringIncludes(ci, "scope=rustyauth-image");
  assertStringIncludes(ci, "scope=dashboard-image");
});

Deno.test("deep security and qualification are outside the merge gate", () => {
  for (
    const command of [
      "govulncheck",
      "cargo audit",
      "trivy",
      "CodeQL",
      "medium_tier_organization_query_meets_the_two_second_p95_target",
    ]
  ) {
    assertEquals(ci.includes(command), false, command);
    assert(assurance.includes(command), command);
  }
  assertStringIncludes(assurance, "schedule:");
  assertStringIncludes(assurance, "branches: [main]");
});

Deno.test("fuzzing and native preview qualification run after merge or on schedules", () => {
  for (const workflow of [fuzz, native]) {
    assertEquals(workflow.includes("pull_request:"), false);
    assertStringIncludes(workflow, "push:");
    assertStringIncludes(workflow, "branches: [main]");
    assertStringIncludes(workflow, "schedule:");
  }
});
