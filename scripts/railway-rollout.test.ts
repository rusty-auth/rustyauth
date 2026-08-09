import {
  deploymentMatchesProfile,
  matchingDeployment,
  normalizeDigest,
  parseDeployments,
  pinnedImageReference,
  RailwayDeployment,
  RailwayRunner,
  rolloutRailwayImage,
  serviceUpdateInput,
} from "./railway-rollout.ts";

const digest = `sha256:${"a".repeat(64)}`;
const image = "ghcr.io/rusty-auth/rustyauth:main-0123456789abcdef";
const sourceImage = `ghcr.io/rusty-auth/rustyauth@${digest}`;

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function assertEquals(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`expected ${JSON.stringify(expected)}, received ${JSON.stringify(actual)}`);
  }
}

function deployment(id: string, status: string, target = true): RailwayDeployment {
  const policy = serviceUpdateInput("realm", image);
  delete policy.source;
  return {
    id,
    status,
    meta: target ? { image: sourceImage, imageDigest: digest, serviceManifest: { deploy: policy } } : {
      image: "ghcr.io/rusty-auth/rustyauth:older",
      imageDigest: `sha256:${"b".repeat(64)}`,
    },
  };
}

Deno.test("Railway service profiles preserve the one-writer and readiness policies", () => {
  assertEquals(serviceUpdateInput("realm", image), {
    source: { image },
    healthcheckPath: "/readyz",
    healthcheckTimeout: 180,
    numReplicas: 1,
    overlapSeconds: 0,
    drainingSeconds: 25,
    preDeployCommand: ["/usr/local/bin/rustyauth doctor"],
    restartPolicyType: "ON_FAILURE",
    restartPolicyMaxRetries: 10,
  });
  const dashboard = serviceUpdateInput("dashboard", image);
  assertEquals(dashboard.numReplicas, 1);
  assertEquals(dashboard.healthcheckPath, "/readyz");
  assertEquals(dashboard.overlapSeconds, 10);
  const sabledb = serviceUpdateInput("sabledb", image);
  assertEquals(sabledb.restartPolicyType, "ALWAYS");
  assertEquals(sabledb.numReplicas, 1);
});

Deno.test("deployment parsing and matching require the exact image and digest", () => {
  const deployments = parseDeployments(JSON.stringify([
    deployment("other", "SUCCESS", false),
    deployment("candidate", "SUCCESS"),
  ]));
  assertEquals(matchingDeployment(deployments, sourceImage, digest)?.id, "candidate");
  assertEquals(matchingDeployment(deployments, sourceImage, digest, new Set(["candidate"])), undefined);
  assertEquals(matchingDeployment(deployments, sourceImage, `sha256:${"c".repeat(64)}`), undefined);
  assertEquals(normalizeDigest(digest.toUpperCase()), digest);
  assertEquals(pinnedImageReference(image, digest), sourceImage);
  assertEquals(pinnedImageReference(`${image}@${digest}`, digest), sourceImage);
  assert(deploymentMatchesProfile(deployments[1], "realm"), "candidate policy did not match");
});

Deno.test("a historical matching image is not mistaken for the active deployment", async () => {
  const outputs = [
    JSON.stringify([deployment("current", "SUCCESS", false), deployment("historical", "SUCCESS")]),
    JSON.stringify({ data: { serviceInstanceUpdate: true } }),
    JSON.stringify([deployment("new", "SUCCESS"), deployment("current", "SUCCESS", false)]),
  ];
  let mutations = 0;
  const runner: RailwayRunner = (args) => {
    if (args[0] === "api") mutations++;
    return Promise.resolve({ code: 0, stdout: outputs.shift() ?? "[]", stderr: "" });
  };
  const receipt = await rolloutRailwayImage(
    {
      project: "project",
      environment: "production",
      service: "api",
      profile: "realm",
      image,
      digest,
      healthUrls: [],
      timeoutMs: 100,
      pollMs: 1,
    },
    runner,
    () => Promise.resolve(),
    () => new Date(0),
    () => Promise.resolve(),
  );
  assertEquals(receipt.deploymentId, "new");
  assertEquals(receipt.sourceImage, sourceImage);
  assertEquals(mutations, 1);
});

Deno.test("rollout waits for the exact digest to reach terminal success before health checks", async () => {
  const outputs = [
    JSON.stringify([deployment("old", "SUCCESS", false)]),
    JSON.stringify({ data: { serviceInstanceUpdate: true } }),
    JSON.stringify([deployment("queued", "QUEUED"), deployment("old", "SUCCESS", false)]),
    JSON.stringify([deployment("new", "DEPLOYING"), deployment("old", "SUCCESS", false)]),
    JSON.stringify([deployment("new", "SUCCESS"), deployment("old", "SUCCESS", false)]),
  ];
  const commands: string[][] = [];
  const runner: RailwayRunner = (args) => {
    commands.push(args);
    return Promise.resolve({ code: 0, stdout: outputs.shift() ?? "[]", stderr: "" });
  };
  let clock = 0;
  let healthChecks = 0;
  const receipt = await rolloutRailwayImage(
    {
      project: "project",
      environment: "production",
      service: "api",
      profile: "realm",
      image,
      digest,
      healthUrls: ["https://auth.example.test/readyz"],
      timeoutMs: 5_000,
      pollMs: 10,
    },
    runner,
    (milliseconds) => {
      clock += milliseconds;
      return Promise.resolve();
    },
    () => new Date(clock),
    (urls) => {
      healthChecks++;
      assertEquals(urls, ["https://auth.example.test/readyz"]);
      return Promise.resolve();
    },
  );

  assertEquals(receipt.deploymentId, "new");
  assertEquals(receipt.changed, true);
  assertEquals(receipt.previousDeploymentId, "old");
  assertEquals(healthChecks, 1);
  assert(commands.some((args) => args[0] === "api"), "service update mutation was not invoked");
  const mutation = commands.find((args) => args[0] === "api");
  const variablesIndex = mutation?.indexOf("--variables") ?? -1;
  const variables = JSON.parse(variablesIndex >= 0 ? mutation?.[variablesIndex + 1] ?? "{}" : "{}") as {
    input?: { source?: { image?: string } };
  };
  assertEquals(variables.input?.source?.image, sourceImage);
  assert(commands.filter((args) => args[0] === "deployment").length === 4, "rollout did not poll");
});

Deno.test("a deployment receipt exists before a failing health check so rollback can restore it", async () => {
  const receiptPath = await Deno.makeTempFile();
  const outputs = [
    JSON.stringify([deployment("old", "SUCCESS", false)]),
    JSON.stringify({ data: { serviceInstanceUpdate: true } }),
    JSON.stringify([deployment("new", "SUCCESS"), deployment("old", "SUCCESS", false)]),
  ];
  const runner: RailwayRunner = () =>
    Promise.resolve({ code: 0, stdout: outputs.shift() ?? "[]", stderr: "" });
  try {
    let error = "";
    try {
      await rolloutRailwayImage(
        {
          project: "project",
          environment: "production",
          service: "api",
          profile: "realm",
          image,
          digest,
          healthUrls: ["https://auth.example.test/readyz"],
          receipt: receiptPath,
          timeoutMs: 100,
          pollMs: 1,
        },
        runner,
        () => Promise.resolve(),
        () => new Date(0),
        () => Promise.reject(new Error("synthetic health failure")),
      );
    } catch (caught) {
      error = caught instanceof Error ? caught.message : String(caught);
    }
    assert(error.includes("synthetic health failure"), `unexpected error: ${error}`);
    const receipt = JSON.parse(await Deno.readTextFile(receiptPath)) as Record<string, unknown>;
    assertEquals(receipt.deploymentId, "new");
    assertEquals(receipt.healthVerifiedAt, null);
  } finally {
    await Deno.remove(receiptPath);
  }
});

Deno.test("rollout is idempotent when the exact successful digest is already active", async () => {
  let calls = 0;
  const runner: RailwayRunner = () => {
    calls++;
    return Promise.resolve({
      code: 0,
      stdout: JSON.stringify([deployment("current", "SUCCESS")]),
      stderr: "",
    });
  };
  const receipt = await rolloutRailwayImage(
    {
      project: "project",
      environment: "production",
      service: "api",
      profile: "realm",
      image,
      digest,
      healthUrls: [],
      timeoutMs: 100,
      pollMs: 1,
    },
    runner,
    () => Promise.resolve(),
    () => new Date(0),
    () => Promise.resolve(),
  );
  assertEquals(receipt.changed, false);
  assertEquals(calls, 1);
});

Deno.test("rollout fails closed on a terminal failed deployment", async () => {
  const outputs = [
    JSON.stringify([deployment("old", "SUCCESS", false)]),
    JSON.stringify({ data: { serviceInstanceUpdate: true } }),
    JSON.stringify([deployment("failed", "FAILED")]),
  ];
  const runner: RailwayRunner = () =>
    Promise.resolve({ code: 0, stdout: outputs.shift() ?? "[]", stderr: "" });
  let error = "";
  try {
    await rolloutRailwayImage(
      {
        project: "project",
        environment: "production",
        service: "api",
        profile: "realm",
        image,
        digest,
        healthUrls: [],
        timeoutMs: 100,
        pollMs: 1,
      },
      runner,
      () => Promise.resolve(),
      () => new Date(0),
      () => Promise.resolve(),
    );
  } catch (caught) {
    error = caught instanceof Error ? caught.message : String(caught);
  }
  assert(error.includes("ended in FAILED"), `unexpected error: ${error}`);
});
