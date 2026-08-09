interface RailwayCommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export type RailwayRunner = (args: string[]) => Promise<RailwayCommandResult>;

export interface RailwayDeployment {
  id: string;
  status: string;
  createdAt?: string;
  meta?: {
    image?: string;
    imageDigest?: string;
    serviceManifest?: {
      deploy?: Record<string, unknown>;
    };
  };
}

export type RailwayServiceProfile = "realm" | "dashboard" | "sabledb";

export interface RailwayRolloutOptions {
  project: string;
  environment: string;
  service: string;
  profile: RailwayServiceProfile;
  image: string;
  digest: string;
  healthUrls: string[];
  receipt?: string;
  timeoutMs: number;
  pollMs: number;
}

export interface RailwayRolloutReceipt {
  project: string;
  environment: string;
  service: string;
  profile: RailwayServiceProfile;
  previousDeploymentId: string | null;
  previousImage: string | null;
  previousDigest: string | null;
  deploymentId: string | null;
  image: string;
  sourceImage: string;
  digest: string;
  status: "PENDING" | "SUCCESS";
  changed: boolean;
  healthUrls: string[];
  deploymentSucceededAt: string | null;
  healthVerifiedAt: string | null;
}

const UPDATE_SERVICE_MUTATION = `
mutation UpdateService(
  $serviceId: String!
  $environmentId: String!
  $input: ServiceInstanceUpdateInput!
) {
  serviceInstanceUpdate(
    serviceId: $serviceId
    environmentId: $environmentId
    input: $input
  )
}
`.trim();

const pendingStatuses = new Set([
  "BUILDING",
  "CREATING",
  "DEPLOYING",
  "INITIALIZING",
  "QUEUED",
  "WAITING",
]);

function fail(message: string): never {
  throw new Error(message);
}

function required(value: string | undefined, name: string): string {
  if (!value?.trim()) fail(`${name} is required`);
  return value.trim();
}

function positiveInteger(value: string | undefined, name: string, fallback: number): number {
  if (value === undefined) return fallback;
  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed <= 0) fail(`${name} must be a positive integer`);
  return parsed;
}

export function normalizeDigest(value: string): string {
  const digest = value.trim().toLowerCase();
  if (!/^sha256:[0-9a-f]{64}$/.test(digest)) {
    fail(`digest must be a sha256 digest, received ${JSON.stringify(value)}`);
  }
  return digest;
}

export function pinnedImageReference(image: string, digest: string): string {
  const normalizedDigest = normalizeDigest(digest);
  const withoutDigest = image.trim().split("@", 1)[0];
  const lastSlash = withoutDigest.lastIndexOf("/");
  const lastColon = withoutDigest.lastIndexOf(":");
  const repository = lastColon > lastSlash ? withoutDigest.slice(0, lastColon) : withoutDigest;
  if (!repository || !repository.includes("/") || /\s/.test(repository)) {
    fail(`image must include a registry repository, received ${JSON.stringify(image)}`);
  }
  return `${repository}@${normalizedDigest}`;
}

export function imageReferenceDigest(image: string | undefined): string | null {
  const match = image?.trim().match(/@(sha256:[0-9a-f]{64})$/i);
  return match ? normalizeDigest(match[1]) : null;
}

export function serviceUpdateInput(
  profile: RailwayServiceProfile,
  image: string,
): Record<string, unknown> {
  const source = { image };
  switch (profile) {
    case "realm":
      return {
        source,
        healthcheckPath: "/readyz",
        healthcheckTimeout: 180,
        numReplicas: 1,
        overlapSeconds: 0,
        drainingSeconds: 25,
        preDeployCommand: ["/usr/local/bin/rustyauth backup create"],
        restartPolicyType: "ON_FAILURE",
        restartPolicyMaxRetries: 10,
      };
    case "dashboard":
      return {
        source,
        healthcheckPath: "/readyz",
        healthcheckTimeout: 180,
        numReplicas: 1,
        overlapSeconds: 10,
        drainingSeconds: 10,
        restartPolicyType: "ON_FAILURE",
        restartPolicyMaxRetries: 10,
      };
    case "sabledb":
      return {
        source,
        numReplicas: 1,
        overlapSeconds: 0,
        restartPolicyType: "ALWAYS",
      };
  }
}

export function parseDeployments(raw: string): RailwayDeployment[] {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    fail("Railway deployment list did not return valid JSON");
  }
  if (!Array.isArray(parsed)) fail("Railway deployment list was not an array");
  return parsed.map((deployment, index) => {
    if (!deployment || typeof deployment !== "object") {
      fail(`Railway deployment ${index} was not an object`);
    }
    const record = deployment as Record<string, unknown>;
    if (typeof record.id !== "string" || typeof record.status !== "string") {
      fail(`Railway deployment ${index} is missing id or status`);
    }
    return deployment as RailwayDeployment;
  });
}

export function configuredServiceImage(
  raw: string,
  environment: string,
  service: string,
): string | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    fail("Railway status did not return valid JSON");
  }
  if (!parsed || typeof parsed !== "object") fail("Railway status was not an object");
  const environments = (parsed as {
    environments?: { edges?: Array<{ node?: Record<string, unknown> }> };
  }).environments?.edges;
  if (!Array.isArray(environments)) fail("Railway status is missing environments");

  for (const edge of environments) {
    const environmentNode = edge.node;
    if (!environmentNode) continue;
    if (environmentNode.id !== environment && environmentNode.name !== environment) continue;
    const instances = (environmentNode.serviceInstances as {
      edges?: Array<{ node?: Record<string, unknown> }>;
    } | undefined)?.edges;
    if (!Array.isArray(instances)) fail("Railway status is missing service instances");
    const instance = instances
      .map((candidate) => candidate.node)
      .find((candidate) => candidate?.serviceId === service || candidate?.serviceName === service);
    if (!instance) fail(`Railway status is missing service ${service}`);
    const image = (instance.source as { image?: unknown } | undefined)?.image;
    if (image === null || image === undefined) return null;
    if (typeof image !== "string") fail(`Railway service ${service} has an invalid source image`);
    return image;
  }
  fail(`Railway status is missing environment ${environment}`);
}

export function matchingDeployment(
  deployments: RailwayDeployment[],
  image: string,
  digest: string,
  excludedIds: ReadonlySet<string> = new Set(),
): RailwayDeployment | undefined {
  return deployments.find((deployment) =>
    !excludedIds.has(deployment.id) &&
    deployment.meta?.image === image &&
    (deployment.meta?.imageDigest?.toLowerCase() === digest ||
      imageReferenceDigest(deployment.meta?.image) === digest)
  );
}

export function deploymentMatchesProfile(
  deployment: RailwayDeployment,
  profile: RailwayServiceProfile,
): boolean {
  const actual = deployment.meta?.serviceManifest?.deploy;
  if (!actual) return false;
  const expected = serviceUpdateInput(profile, deployment.meta?.image ?? "");
  for (const [key, value] of Object.entries(expected)) {
    if (key === "source") continue;
    if (JSON.stringify(actual[key]) !== JSON.stringify(value)) return false;
  }
  return true;
}

function commandError(args: string[], result: RailwayCommandResult): Error {
  const detail = result.stderr.trim() || result.stdout.trim() || `exit ${result.code}`;
  return new Error(`railway ${args[0]} failed: ${detail}`);
}

async function runJson(
  runner: RailwayRunner,
  args: string[],
): Promise<string> {
  const result = await runner(args);
  if (result.code !== 0) throw commandError(args, result);
  return result.stdout;
}

function deploymentListArgs(options: RailwayRolloutOptions): string[] {
  return [
    "deployment",
    "list",
    "--project",
    options.project,
    "--environment",
    options.environment,
    "--service",
    options.service,
    "--limit",
    "20",
    "--json",
  ];
}

function projectStatusArgs(options: RailwayRolloutOptions): string[] {
  return [
    "status",
    "--project",
    options.project,
    "--environment",
    options.environment,
    "--json",
  ];
}

function redeployArgs(options: RailwayRolloutOptions): string[] {
  return [
    "redeploy",
    "--project",
    options.project,
    "--environment",
    options.environment,
    "--service",
    options.service,
    "--from-source",
    "--yes",
    "--json",
  ];
}

function downArgs(options: RailwayRolloutOptions): string[] {
  return [
    "down",
    "--project",
    options.project,
    "--environment",
    options.environment,
    "--service",
    options.service,
    "--yes",
  ];
}

function updateArgs(options: RailwayRolloutOptions, sourceImage: string): string[] {
  const variables = {
    serviceId: options.service,
    environmentId: options.environment,
    input: serviceUpdateInput(options.profile, sourceImage),
  };
  return [
    "api",
    UPDATE_SERVICE_MUTATION,
    "--variables",
    JSON.stringify(variables),
    "--compact",
  ];
}

async function verifyHealth(urls: string[]): Promise<void> {
  for (const url of urls) {
    let lastFailure = "no response";
    for (let attempt = 1; attempt <= 12; attempt++) {
      try {
        const response = await fetch(url, {
          redirect: "error",
          signal: AbortSignal.timeout(15_000),
        });
        const body = await response.text();
        if (!response.ok) {
          lastFailure = `HTTP ${response.status}`;
        } else {
          const status = (JSON.parse(body) as Record<string, unknown>).status;
          if (status === "ok" || status === "ready") {
            lastFailure = "";
            break;
          }
          lastFailure = `unexpected status ${JSON.stringify(status)}`;
        }
      } catch (error) {
        lastFailure = error instanceof Error ? error.message : String(error);
      }
      if (attempt < 12) await new Promise((resolve) => setTimeout(resolve, 5_000));
    }
    if (lastFailure) fail(`health verification failed for ${url}: ${lastFailure}`);
  }
}

export async function rolloutRailwayImage(
  options: RailwayRolloutOptions,
  runner: RailwayRunner,
  sleep: (milliseconds: number) => Promise<void> = (milliseconds) =>
    new Promise((resolve) => setTimeout(resolve, milliseconds)),
  now: () => Date = () => new Date(),
  healthCheck: (urls: string[]) => Promise<void> = verifyHealth,
): Promise<RailwayRolloutReceipt> {
  const digest = normalizeDigest(options.digest);
  const sourceImage = pinnedImageReference(options.image, digest);
  const baseline = parseDeployments(await runJson(runner, deploymentListArgs(options)));
  // Failed attempts may be newer than the deployment that is actually serving.
  // The newest successful deployment is the rollback target; using baseline[0]
  // can select a failed image and make recovery fail a second time.
  const previous = baseline.find((deployment) => deployment.status === "SUCCESS");
  const current = previous && matchingDeployment([previous], sourceImage, digest);

  const receipt: RailwayRolloutReceipt = {
    project: options.project,
    environment: options.environment,
    service: options.service,
    profile: options.profile,
    previousDeploymentId: previous?.id ?? null,
    previousImage: previous?.meta?.image ?? null,
    previousDigest: previous?.meta?.imageDigest ?? imageReferenceDigest(previous?.meta?.image),
    deploymentId: null,
    image: options.image,
    sourceImage,
    digest,
    status: "PENDING",
    changed: false,
    healthUrls: options.healthUrls,
    deploymentSucceededAt: null,
    healthVerifiedAt: null,
  };
  const writeReceipt = async (): Promise<void> => {
    if (options.receipt) {
      await Deno.writeTextFile(options.receipt, `${JSON.stringify(receipt, null, 2)}\n`);
    }
  };

  let deployment: RailwayDeployment | undefined;
  if (current?.status === "SUCCESS" && deploymentMatchesProfile(current, options.profile)) {
    deployment = current;
  } else {
    const configuredImage = configuredServiceImage(
      await runJson(runner, projectStatusArgs(options)),
      options.environment,
      options.service,
    );
    if (configuredImage !== sourceImage) {
      const update = JSON.parse(await runJson(runner, updateArgs(options, sourceImage))) as {
        data?: { serviceInstanceUpdate?: boolean };
        errors?: unknown[];
      };
      if (update.errors?.length || update.data?.serviceInstanceUpdate !== true) {
        fail("Railway rejected the service image/configuration update");
      }
    }
    receipt.changed = true;
    await writeReceipt();

    // Railway keeps the old deployment alive until its replacement is ready,
    // even with overlapSeconds=0. A RustyAuth realm intentionally refuses to
    // start while that old process owns the one-writer lease, so perform an
    // explicit, receipt-backed handoff before starting the replacement.
    if (options.profile === "realm" && previous) {
      await runJson(runner, downArgs(options));
    }
    await runJson(runner, redeployArgs(options));

    const baselineIds = new Set(baseline.map((existing) => existing.id));
    const deadline = now().getTime() + options.timeoutMs;
    let latestObserved = "no deployment";
    while (now().getTime() < deadline) {
      const deployments = parseDeployments(await runJson(runner, deploymentListArgs(options)));
      const candidate = matchingDeployment(deployments, sourceImage, digest, baselineIds);
      if (!candidate) {
        latestObserved = deployments[0] ? `${deployments[0].id} (${deployments[0].status})` : "no deployment";
        await sleep(options.pollMs);
        continue;
      }

      latestObserved = `${candidate.id} (${candidate.status})`;
      if (candidate.status === "SUCCESS") {
        if (!deploymentMatchesProfile(candidate, options.profile)) {
          fail(`Railway deployment ${candidate.id} succeeded with an unexpected service policy`);
        }
        deployment = candidate;
        break;
      }
      if (!pendingStatuses.has(candidate.status)) {
        fail(`Railway deployment ${candidate.id} ended in ${candidate.status}`);
      }
      await sleep(options.pollMs);
    }
    if (!deployment) {
      fail(`Railway deployment timed out after ${options.timeoutMs}ms; latest was ${latestObserved}`);
    }
  }

  if (!deployment) fail("Railway rollout completed without a deployment");
  receipt.deploymentId = deployment.id;
  receipt.status = "SUCCESS";
  receipt.deploymentSucceededAt = now().toISOString();
  await writeReceipt();
  await healthCheck(options.healthUrls);
  receipt.healthVerifiedAt = now().toISOString();
  await writeReceipt();
  return receipt;
}

function parseOptions(args: string[]): RailwayRolloutOptions {
  const values = new Map<string, string[]>();
  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index];
    const value = args[index + 1];
    if (!flag?.startsWith("--") || value === undefined) fail(`invalid argument near ${flag ?? "end"}`);
    const existing = values.get(flag) ?? [];
    existing.push(value);
    values.set(flag, existing);
  }
  const profile = required(values.get("--profile")?.[0], "--profile") as RailwayServiceProfile;
  if (!(["realm", "dashboard", "sabledb"] as string[]).includes(profile)) {
    fail(`--profile must be realm, dashboard or sabledb`);
  }
  const healthUrls = values.get("--health-url") ?? [];
  for (const url of healthUrls) {
    if (!url.startsWith("https://")) fail(`--health-url must use https: ${url}`);
  }
  return {
    project: required(values.get("--project")?.[0], "--project"),
    environment: required(values.get("--environment")?.[0], "--environment"),
    service: required(values.get("--service")?.[0], "--service"),
    profile,
    image: required(values.get("--image")?.[0], "--image"),
    digest: required(values.get("--digest")?.[0], "--digest"),
    healthUrls,
    receipt: values.get("--receipt")?.[0],
    timeoutMs: positiveInteger(values.get("--timeout-ms")?.[0], "--timeout-ms", 20 * 60 * 1_000),
    pollMs: positiveInteger(values.get("--poll-ms")?.[0], "--poll-ms", 10_000),
  };
}

function commandRunner(binary: string): RailwayRunner {
  return async (args) => {
    const command = new Deno.Command(binary, {
      args,
      stdout: "piped",
      stderr: "piped",
      env: {
        RAILWAY_CALLER: "workflow:rustyauth-main-cd",
        RAILWAY_AGENT_SESSION: Deno.env.get("RAILWAY_AGENT_SESSION") ??
          `github-${Deno.env.get("GITHUB_RUN_ID") ?? "local"}`,
      },
    });
    const output = await command.output();
    return {
      code: output.code,
      stdout: new TextDecoder().decode(output.stdout),
      stderr: new TextDecoder().decode(output.stderr),
    };
  };
}

if (import.meta.main) {
  try {
    if (!Deno.env.get("RAILWAY_TOKEN") && !Deno.env.get("RAILWAY_API_TOKEN")) {
      fail("RAILWAY_TOKEN or RAILWAY_API_TOKEN is required");
    }
    const options = parseOptions(Deno.args);
    const receipt = await rolloutRailwayImage(
      options,
      commandRunner(Deno.env.get("RAILWAY_BIN") ?? "railway"),
    );
    console.log(
      `${receipt.service} is ${receipt.status} on ${receipt.image}@${receipt.digest} ` +
        `(${receipt.changed ? "deployed" : "already current"})`,
    );
  } catch (error) {
    console.error(error instanceof Error ? error.message : error);
    Deno.exit(1);
  }
}
