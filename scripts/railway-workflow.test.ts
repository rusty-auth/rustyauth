const workflow = await Deno.readTextFile(".github/workflows/railway-production.yml");
const rollout = await Deno.readTextFile("scripts/railway-rollout.ts");

function assertIncludes(source: string, required: string): void {
  if (!source.includes(required)) throw new Error(`missing ${JSON.stringify(required)}`);
}

function assertOrdered(source: string, values: string[]): void {
  let position = -1;
  for (const value of values) {
    const next = source.indexOf(value, position + 1);
    if (next === -1) throw new Error(`missing ordered value ${JSON.stringify(value)}`);
    position = next;
  }
}

Deno.test("Railway automatic deployments follow successful current-main CI only", () => {
  for (
    const required of [
      "workflow_run:",
      "workflows: [CI]",
      "branches: [main]",
      "github.event.workflow_run.conclusion == 'success'",
      "git merge-base --is-ancestor",
      "Skipping stale successful CI result",
      "group: railway-production",
      "cancel-in-progress: false",
      "RAILWAY_API_TOKEN: ${{ secrets.RAILWAY_API_TOKEN }}",
    ]
  ) assertIncludes(workflow, required);
});

Deno.test("Railway candidates are immutable, signed and digest-verified", () => {
  for (
    const required of [
      "ghcr.io/rusty-auth/rustyauth:main-${{ needs.prepare.outputs.sha }}",
      "ghcr.io/rusty-auth/dashboard:main-${{ needs.prepare.outputs.sha }}",
      "ghcr.io/rusty-auth/sabledb:main-${{ needs.prepare.outputs.sha }}",
      "provenance: mode=max",
      "sbom: true",
      "cosign sign --yes",
      "matchingDeployment(deployments, options.image, digest, baselineIds)",
      'candidate.status === "SUCCESS"',
    ]
  ) assertIncludes(workflow + rollout, required);
  if (/tags:.*:latest/.test(workflow)) {
    throw new Error("production deployment must not use a mutable latest tag");
  }
});

Deno.test("Railway rollout is serialized across every stateful boundary", () => {
  assertOrdered(workflow, [
    "name: Deploy realm API",
    "--profile realm",
    "name: Deploy dashboard",
    "--profile dashboard",
    "name: Deploy private SableDB",
    "--profile sabledb",
  ]);
  for (const required of ["/healthz", "/readyz", "retention-days: 90"]) {
    assertIncludes(workflow, required);
  }
});
