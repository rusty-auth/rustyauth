export const requiredGates = [
  "application_security_review",
  "deployment_security_review",
  "sabledb_assumption_review",
  "analytics_threat_privacy_review",
  "analytics_production_qualification",
  "organization_analytics_canary",
  "published_image_install_upgrade",
  "browser_authenticator_matrix",
  "witnessed_recovery_drill",
  "release_owner_approval",
] as const;

export function validateReleaseEvidence(version: string, evidence: Record<string, unknown>): string[] {
  const errors: string[] = [];
  if (evidence.version !== version) errors.push(`version must be ${version}`);
  if (evidence.scope !== "server-container-web-ga") {
    errors.push('scope must be "server-container-web-ga"');
  }
  if (evidence.decision !== "go") errors.push('decision must be "go"');
  if (
    typeof evidence.completedAt !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(evidence.completedAt) ||
    Number.isNaN(Date.parse(evidence.completedAt))
  ) {
    errors.push("completedAt must be an ISO-8601 UTC timestamp");
  }

  const reviewers = evidence.reviewedBy;
  if (
    !Array.isArray(reviewers) || reviewers.length < 2 ||
    reviewers.some((value) =>
      typeof value !== "string" || value.trim().length < 2 || value.includes("replace-with")
    ) || new Set(reviewers).size !== reviewers.length
  ) {
    errors.push("reviewedBy must name at least two distinct real reviewers");
  }

  const gates = evidence.gates;
  if (!gates || typeof gates !== "object" || Array.isArray(gates)) {
    errors.push("gates must be an object");
    return errors;
  }

  const gateRecords = gates as Record<string, unknown>;
  const requiredGateNames = new Set<string>(requiredGates);
  for (const gateName of Object.keys(gateRecords)) {
    if (!requiredGateNames.has(gateName)) errors.push(`${gateName} is not a recognized release gate`);
  }

  for (const gateName of requiredGates) {
    const gate = gateRecords[gateName];
    if (!gate || typeof gate !== "object" || Array.isArray(gate)) {
      errors.push(`${gateName} is missing`);
      continue;
    }
    const record = gate as Record<string, unknown>;
    if (record.passed !== true) errors.push(`${gateName} has not passed`);
    if (typeof record.evidence !== "string" || record.evidence.trim().length < 8) {
      errors.push(`${gateName} needs a stable evidence URL or repository path`);
    }
  }

  return errors;
}

if (import.meta.main) {
  const version = Deno.args[0];
  if (!version || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(version)) {
    console.error("Release readiness failed: pass a semantic version without the v prefix");
    Deno.exit(1);
  }

  const evidencePath = `release-evidence/v${version}.json`;
  let raw: string;
  try {
    raw = await Deno.readTextFile(evidencePath);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      console.error(
        `Release readiness failed: ${evidencePath} is missing; copy release-evidence/TEMPLATE.json and record every gate`,
      );
      Deno.exit(1);
    }
    throw error;
  }

  let evidence: Record<string, unknown>;
  try {
    evidence = JSON.parse(raw) as Record<string, unknown>;
  } catch {
    console.error(`Release readiness failed: ${evidencePath} is not valid JSON`);
    Deno.exit(1);
  }

  const errors = validateReleaseEvidence(version, evidence);
  if (errors.length > 0) {
    for (const error of errors) console.error(`Release readiness failed: ${evidencePath} ${error}`);
    Deno.exit(1);
  }

  console.log(`Release evidence for v${version} is complete across ${requiredGates.length} required gates.`);
}
