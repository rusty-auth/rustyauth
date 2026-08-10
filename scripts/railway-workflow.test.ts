const workflow = await Deno.readTextFile(".github/workflows/railway-production.yml");
const releaseWorkflow = await Deno.readTextFile(".github/workflows/release.yml");
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
      "cancel-in-progress: true",
      "RAILWAY_TOKEN: ${{ secrets.RAILWAY_TOKEN }}",
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
      "matchingDeployment(deployments, sourceImage, digest, baselineIds)",
      "pinnedImageReference(options.image, digest)",
      'candidate.status === "SUCCESS"',
      "configuredImage !== sourceImage",
      '"redeploy"',
      '"--from-source"',
      "await runJson(runner, redeployArgs(options));",
      "Verify candidates are anonymously pullable",
      "docker buildx imagetools inspect",
    ]
  ) assertIncludes(workflow + rollout, required);
  if (/tags:.*:latest/.test(workflow)) {
    throw new Error("production deployment must not use a mutable latest tag");
  }
});

Deno.test("the public Railway template follows the verified production image set", () => {
  for (
    const required of [
      "name: Publish the verified Railway template graph",
      "needs: [prepare, publish-api, publish-dashboard, publish-sabledb, deploy]",
      "needs.deploy.result == 'success'",
      "RAILWAY_API_TOKEN: ${{ secrets.RAILWAY_TEMPLATE_TOKEN }}",
      "scripts/sync-railway-template.ts",
      "ghcr.io/rusty-auth/rustyauth@${API_DIGEST}",
      "ghcr.io/rusty-auth/dashboard@${DASHBOARD_DIGEST}",
      "ghcr.io/rusty-auth/sabledb@${SABLEDB_DIGEST}",
    ]
  ) assertIncludes(workflow, required);
  assertOrdered(workflow, [
    "name: Roll out verified candidate",
    "name: Publish the verified Railway template graph",
  ]);
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
  assertIncludes(workflow, '"AUTH_TRUSTED_PROXY_HOPS=1"');
  assertIncludes(workflow, '"AUTH_BACKUP_STORAGE_PROFILE=portable"');
  assertIncludes(workflow, '"AUTH_BACKUP_SSE=provider"');
  assertIncludes(workflow, '"RUST_LOG=rustyauth=info,tower_http=info"');
  assertIncludes(rollout, '"/usr/local/bin/rustyauth backup create"');
  assertIncludes(rollout, '"down"');
  assertIncludes(workflow, "name: Require a fresh verified recovery point");
  assertIncludes(workflow, "encrypted backup created and verified");
  assertIncludes(workflow, '"formatVersion\\": 3"');
  assertIncludes(workflow, "rustyauth-backups/v3/");
  assertOrdered(workflow, [
    "name: Deploy realm API",
    "name: Require a fresh verified recovery point",
    "name: Deploy dashboard",
  ]);
});

Deno.test("a partial Railway rollout restores services and browser origin in reverse order", () => {
  assertIncludes(workflow, "name: Restore the previous Railway deployment set");
  assertIncludes(workflow, "if: failure() || cancelled()");
  assertOrdered(workflow, [
    'rollback_service "${RUNNER_TEMP}/railway-receipts/sabledb.json"',
    'rollback_service "${RUNNER_TEMP}/railway-receipts/dashboard.json"',
    '"AUTH_ISSUER=${previous_issuer}"',
    'rollback_service "${RUNNER_TEMP}/railway-receipts/api.json"',
  ]);
  assertIncludes(workflow, "railway down");
  assertIncludes(rollout, "healthVerifiedAt: null");
});

Deno.test("same-revision release retries cancel without crossing tag boundaries", () => {
  assertIncludes(releaseWorkflow, "group: release-${{ github.ref }}");
  assertIncludes(releaseWorkflow, "cancel-in-progress: true");
});
