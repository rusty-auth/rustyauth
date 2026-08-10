export type ValidationError = string;

const object = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const nonEmpty = (value: unknown): value is string => typeof value === "string" && value.trim().length > 0;

const finiteNonNegative = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= 0;

const isoTimestamp = (value: unknown): value is string =>
  nonEmpty(value) && !Number.isNaN(Date.parse(value)) && value.includes("T");

const requiredCapacityResults = [
  "registered_accounts",
  "valid_sessions",
  "sustainable_authenticated_rps",
  "supported_typical_active_users",
  "signin_rps",
  "signin_p95_ms",
] as const;

export function validateBenchmarkCatalog(value: unknown): ValidationError[] {
  const errors: string[] = [];
  if (!object(value)) return ["catalogue must be an object"];
  if (value.schemaVersion !== 2) errors.push("schemaVersion must be 2");
  if (!isoTimestamp(value.updatedAt)) errors.push("updatedAt must be an ISO timestamp");

  if (!object(value.publicationPolicy)) {
    errors.push("publicationPolicy must be an object");
  } else {
    for (const field of ["summary", "isolation", "promotion"]) {
      if (!nonEmpty(value.publicationPolicy[field])) errors.push(`publicationPolicy.${field} is required`);
    }
  }

  const programs = Array.isArray(value.programs) ? value.programs : [];
  if (programs.length === 0) errors.push("programs must not be empty");
  const programIds = new Set<string>();
  for (const [index, candidate] of programs.entries()) {
    const path = `programs[${index}]`;
    if (!object(candidate)) {
      errors.push(`${path} must be an object`);
      continue;
    }
    if (!nonEmpty(candidate.id)) errors.push(`${path}.id is required`);
    else if (programIds.has(candidate.id)) errors.push(`${path}.id must be unique`);
    else programIds.add(candidate.id);
    if (!nonEmpty(candidate.title)) errors.push(`${path}.title is required`);
    if (!nonEmpty(candidate.summary)) errors.push(`${path}.summary is required`);
    if (!["awaiting-baseline", "active", "retired"].includes(String(candidate.state))) {
      errors.push(`${path}.state is invalid`);
    }
    for (const field of ["schedule", "resourceTiers", "userProfiles", "gates"]) {
      if (!Array.isArray(candidate[field])) errors.push(`${path}.${field} must be an array`);
    }
    if (candidate.id === "single-realm-capacity") {
      if (!object(candidate.decisionGuide)) {
        errors.push(`${path}.decisionGuide must be an object`);
      } else {
        for (const field of ["headline", "measured", "inferred", "notDemonstrated", "scaleStrategy"]) {
          if (!nonEmpty(candidate.decisionGuide[field])) {
            errors.push(`${path}.decisionGuide.${field} is required`);
          }
        }
      }
      if (!object(candidate.enterpriseProfile)) {
        errors.push(`${path}.enterpriseProfile must be an object`);
      } else {
        if (!nonEmpty(candidate.enterpriseProfile.name)) {
          errors.push(`${path}.enterpriseProfile.name is required`);
        }
        if (!Array.isArray(candidate.enterpriseProfile.mix) || candidate.enterpriseProfile.mix.length === 0) {
          errors.push(`${path}.enterpriseProfile.mix must not be empty`);
        } else {
          const total = candidate.enterpriseProfile.mix.reduce(
            (sum, item) => sum + (object(item) && finiteNonNegative(item.percent) ? item.percent : 0),
            0,
          );
          if (total !== 100) errors.push(`${path}.enterpriseProfile.mix must total 100 percent`);
        }
      }
    }
  }

  const reports = Array.isArray(value.reports) ? value.reports : [];
  const reportIds = new Set<string>();
  for (const [index, candidate] of reports.entries()) {
    const path = `reports[${index}]`;
    if (!object(candidate)) {
      errors.push(`${path} must be an object`);
      continue;
    }
    if (!nonEmpty(candidate.id)) errors.push(`${path}.id is required`);
    else if (reportIds.has(candidate.id)) errors.push(`${path}.id must be unique`);
    else reportIds.add(candidate.id);
    if (!nonEmpty(candidate.programId) || !programIds.has(candidate.programId)) {
      errors.push(`${path}.programId must reference a declared program`);
    }
    for (
      const field of [
        "title",
        "qualification",
        "release",
        "commit",
        "environment",
        "methodologyVersion",
        "summary",
      ]
    ) {
      if (!nonEmpty(candidate[field])) errors.push(`${path}.${field} is required`);
    }
    if (!isoTimestamp(candidate.observedAt)) errors.push(`${path}.observedAt must be an ISO timestamp`);
    if (!["passed", "failed", "informational"].includes(String(candidate.status))) {
      errors.push(`${path}.status is invalid`);
    }

    const results = Array.isArray(candidate.results) ? candidate.results : [];
    if (results.length === 0) errors.push(`${path}.results must not be empty`);
    const resultKeys = new Set<string>();
    for (const [resultIndex, result] of results.entries()) {
      const resultPath = `${path}.results[${resultIndex}]`;
      if (!object(result)) {
        errors.push(`${resultPath} must be an object`);
        continue;
      }
      if (!nonEmpty(result.key)) errors.push(`${resultPath}.key is required`);
      else resultKeys.add(result.key);
      if (!nonEmpty(result.label)) errors.push(`${resultPath}.label is required`);
      if (!finiteNonNegative(result.value)) errors.push(`${resultPath}.value must be non-negative`);
      if (!nonEmpty(result.unit)) errors.push(`${resultPath}.unit is required`);
      if (!nonEmpty(result.threshold)) errors.push(`${resultPath}.threshold is required`);
      if (!["pass", "fail", "observe"].includes(String(result.outcome))) {
        errors.push(`${resultPath}.outcome is invalid`);
      }
    }

    const evidence = Array.isArray(candidate.evidence) ? candidate.evidence : [];
    if (evidence.length === 0) errors.push(`${path}.evidence must not be empty`);
    for (const [evidenceIndex, item] of evidence.entries()) {
      const evidencePath = `${path}.evidence[${evidenceIndex}]`;
      if (!object(item) || !nonEmpty(item.label) || !nonEmpty(item.url)) {
        errors.push(`${evidencePath} requires label and url`);
        continue;
      }
      try {
        if (new URL(item.url).protocol !== "https:") errors.push(`${evidencePath}.url must use HTTPS`);
      } catch {
        errors.push(`${evidencePath}.url must be an absolute URL`);
      }
    }

    if (candidate.programId === "single-realm-capacity" && candidate.status === "passed") {
      for (const key of requiredCapacityResults) {
        if (!resultKeys.has(key)) errors.push(`${path} is missing required capacity result ${key}`);
      }
      if (!object(candidate.imageDigests)) {
        errors.push(`${path}.imageDigests is required for a passed capacity report`);
      } else {
        for (const image of ["api", "dashboard", "sableDb"]) {
          const digest = candidate.imageDigests[image];
          if (!nonEmpty(digest) || !/^sha256:[0-9a-f]{64}$/.test(digest)) {
            errors.push(`${path}.imageDigests.${image} must be an immutable sha256 digest`);
          }
        }
      }
      const capacityModels = Array.isArray(candidate.capacityModels) ? candidate.capacityModels : [];
      if (capacityModels.length === 0) errors.push(`${path}.capacityModels must not be empty`);
      const charts = Array.isArray(candidate.charts) ? candidate.charts : [];
      if (charts.length === 0) errors.push(`${path}.charts must not be empty`);
      for (const [chartIndex, chart] of charts.entries()) {
        const chartPath = `${path}.charts[${chartIndex}]`;
        if (!object(chart)) {
          errors.push(`${chartPath} must be an object`);
          continue;
        }
        for (const field of ["id", "title", "description", "xUnit", "yUnit"]) {
          if (!nonEmpty(chart[field])) errors.push(`${chartPath}.${field} is required`);
        }
        const series = Array.isArray(chart.series) ? chart.series : [];
        if (series.length === 0) errors.push(`${chartPath}.series must not be empty`);
        for (const [seriesIndex, line] of series.entries()) {
          const seriesPath = `${chartPath}.series[${seriesIndex}]`;
          if (
            !object(line) || !nonEmpty(line.name) || !Array.isArray(line.points) || line.points.length < 2
          ) {
            errors.push(`${seriesPath} requires a name and at least two points`);
            continue;
          }
          for (const point of line.points) {
            if (!object(point) || !finiteNonNegative(point.x) || !finiteNonNegative(point.y)) {
              errors.push(`${seriesPath} points require non-negative x and y values`);
            }
          }
        }
      }
      if (!object(candidate.confidence)) errors.push(`${path}.confidence must be an object`);
    }
  }

  return errors;
}

if (import.meta.main) {
  const path = Deno.args[0] ?? "benchmarks/catalog.json";
  let parsed: unknown;
  try {
    parsed = JSON.parse(await Deno.readTextFile(path));
  } catch (error) {
    console.error(`${path}: ${error instanceof Error ? error.message : String(error)}`);
    Deno.exit(1);
  }
  const errors = validateBenchmarkCatalog(parsed);
  if (errors.length > 0) {
    for (const error of errors) console.error(`${path}: ${error}`);
    Deno.exit(1);
  }
  console.log(`validated benchmark catalogue: ${path}`);
}
