import { requiredGates, validateReleaseEvidence } from "./check-release-readiness.ts";

function assertEquals(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
  }
}

function assertIncludes(values: string[], expected: string): void {
  if (!values.includes(expected)) throw new Error(`expected errors to contain ${JSON.stringify(expected)}`);
}

function workflowJob(workflow: string, job: string): string {
  const match = workflow.match(new RegExp(`\\n  ${job}:\\n([\\s\\S]*?)(?=\\n  [a-z][a-z0-9-]*:\\n|$)`));
  if (!match) throw new Error(`release workflow job ${job} is missing`);
  return match[0];
}

function completeEvidence(): Record<string, unknown> {
  return {
    version: "1.0.0",
    scope: "server-container-web-ga",
    decision: "go",
    reviewedBy: ["independent-reviewer", "release-owner"],
    completedAt: "2026-08-10T06:00:00Z",
    gates: Object.fromEntries(requiredGates.map((gate) => [
      gate,
      { passed: true, evidence: `evidence/${gate}.md` },
    ])),
  };
}

Deno.test("release evidence accepts only a complete go decision", () => {
  assertEquals(validateReleaseEvidence("1.0.0", completeEvidence()), []);
});

Deno.test("release evidence fails closed on reviewers, decision, evidence and missing gates", () => {
  const evidence = completeEvidence();
  evidence.scope = "native-ga";
  evidence.decision = "no-go";
  evidence.reviewedBy = ["one-reviewer"];
  const gates = evidence.gates as Record<string, Record<string, unknown>>;
  gates.application_security_review.evidence = "";
  delete gates.analytics_production_qualification;
  delete gates.browser_authenticator_matrix;
  gates.ios_device_distribution = { passed: false, evidence: "deprecated/native-gate.md" };

  const errors = validateReleaseEvidence("1.0.0", evidence);
  assertIncludes(errors, 'scope must be "server-container-web-ga"');
  assertIncludes(errors, 'decision must be "go"');
  assertIncludes(errors, "reviewedBy must name at least two distinct real reviewers");
  assertIncludes(errors, "application_security_review needs a stable evidence URL or repository path");
  assertIncludes(errors, "analytics_production_qualification is missing");
  assertIncludes(errors, "browser_authenticator_matrix is missing");
  assertIncludes(errors, "ios_device_distribution is not a recognized release gate");
});

Deno.test("every publisher waits for the registry preflight", async () => {
  const workflow = await Deno.readTextFile(".github/workflows/release.yml");
  const preflight = workflowJob(workflow, "publication-preflight");
  for (
    const required of [
      "https://jsr.io/@rustyauth/${package}/meta.json",
      "buf registry whoami",
      "buf registry module info buf.build/rusty-auth/rustyauth",
    ]
  ) {
    if (!preflight.includes(required)) throw new Error(`publication preflight is missing ${required}`);
  }

  for (const job of ["container", "dashboard-container", "sabledb-container", "jsr", "bsr"]) {
    const publisher = workflowJob(workflow, job);
    if (!publisher.includes("needs: [qualification, fuzz, publication-preflight]")) {
      throw new Error(`${job} can publish without passing the registry preflight`);
    }
  }
});
