import http from "k6/http";
import exec from "k6/execution";
import crypto from "k6/crypto";
import { check } from "k6";
import { SharedArray } from "k6/data";
import { Counter, Rate, Trend } from "k6/metrics";
import { parseServerTiming } from "./timing.js";

const fixtures = new SharedArray(
  "enterprise-realm-fixtures",
  () =>
    open(__ENV.FIXTURES_PATH || "/data/fixtures.jsonl")
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((line) => JSON.parse(line)),
);

if (!__ENV.TARGET_URL || !__ENV.RP_ORIGIN || !__ENV.BENCHMARK_TIMING_ROOT_SECRET) {
  throw new Error("TARGET_URL, RP_ORIGIN and BENCHMARK_TIMING_ROOT_SECRET are required");
}
if (fixtures.length === 0) throw new Error("fixture dataset is empty");

// Only this domain-separated derivative crosses the public TLS boundary. It
// cannot be replayed as the realm's bootstrap credential.
const benchmarkTimingToken = crypto.sha256(
  `rustyauth:benchmark-timing:v1\0${__ENV.BENCHMARK_TIMING_ROOT_SECRET}`,
  "hex",
);

const profile = __ENV.PROFILE || "enterprise";
const phases = profile === "smoke" ? [{ name: "smoke", rate: 5, duration: "10s" }] : profile === "soak"
  ? [
    { name: "warmup", rate: 100, duration: "1m" },
    { name: "soak", rate: Number(__ENV.SOAK_RATE || 560), duration: __ENV.SOAK_DURATION || "1h" },
    { name: "recovery", rate: 100, duration: "2m" },
  ]
  : [
    { name: "warmup", rate: 250, duration: "30s" },
    { name: "baseline", rate: 800, duration: "90s" },
    { name: "growth", rate: 1_200, duration: "2m" },
    { name: "high", rate: 1_600, duration: "2m" },
    { name: "saturation", rate: 2_000, duration: "2m" },
    { name: "spike", rate: 2_400, duration: "1m" },
    { name: "recovery", rate: 800, duration: "2m" },
  ];

const operationDuration = {
  account: new Trend("account_duration", true),
  token: new Trend("token_duration", true),
  credentials: new Trend("credentials_duration", true),
  jwks: new Trend("jwks_duration", true),
};
const endToEndDuration = new Trend("enterprise_end_to_end_duration", true);
const serverApplicationDuration = new Trend("server_application_duration", true);
const sabledbDuration = new Trend("sabledb_duration", true);
const nonStoreDuration = new Trend("application_nonstore_duration", true);
const externalPathDuration = new Trend("external_path_duration", true);
const sabledbRoundTrips = new Trend("sabledb_round_trips");
const requestFailures = new Rate("enterprise_request_failures");
const unplanned5xx = new Counter("enterprise_unplanned_5xx");

const phaseMetrics = Object.fromEntries(
  phases.map((phase) => [phase.name, {
    endToEnd: new Trend(`phase_${phase.name}_end_to_end`, true),
    application: new Trend(`phase_${phase.name}_application`, true),
    sabledb: new Trend(`phase_${phase.name}_sabledb`, true),
  }]),
);

let startsAtSeconds = 0;
const scenarios = {};
for (const phase of phases) {
  scenarios[phase.name] = {
    executor: "constant-arrival-rate",
    rate: phase.rate,
    timeUnit: "1s",
    duration: phase.duration,
    startTime: `${startsAtSeconds}s`,
    // Sequential scenarios retain their initialized VU pools for the full run.
    // Allocate for the measured median path and allow bounded dynamic growth;
    // oversized pools can otherwise qualify the generator's memory, not the
    // realm under test.
    preAllocatedVUs: Math.max(25, Math.ceil(phase.rate * 0.15)),
    maxVUs: Math.max(100, Math.ceil(phase.rate * 0.75)),
    gracefulStop: "20s",
    exec: "enterpriseJourney",
    tags: { phase: phase.name, target_rate: String(phase.rate) },
  };
  startsAtSeconds += durationSeconds(phase.duration);
}

export const options = {
  scenarios,
  summaryTrendStats: ["avg", "min", "med", "max", "p(90)", "p(95)", "p(99)", "p(99.9)"],
  thresholds: {
    enterprise_request_failures: ["rate<0.001"],
    enterprise_unplanned_5xx: ["count==0"],
    enterprise_end_to_end_duration: ["p(95)<300", "p(99)<750"],
    server_application_duration: ["p(95)<150", "p(99)<400"],
    sabledb_duration: ["p(95)<100", "p(99)<250"],
    account_duration: ["p(95)<250"],
    token_duration: ["p(95)<350"],
    credentials_duration: ["p(95)<250"],
    jwks_duration: ["p(95)<150"],
    dropped_iterations: ["count==0"],
  },
};

const jsonHeaders = {
  "Content-Type": "application/json",
  Origin: __ENV.RP_ORIGIN,
  "X-RustyAuth-Benchmark-Timing": benchmarkTimingToken,
};

export function enterpriseJourney() {
  const fixture = fixtures[(2_000 + exec.scenario.iterationInTest) % fixtures.length];
  const operation = operationForIteration(exec.scenario.iterationInTest);
  const request = requestFor(operation, fixture);
  const response = request.method === "POST"
    ? http.post(request.url, request.body, request.options)
    : http.get(request.url, request.options);
  const failed = response.status !== 200;
  const duration = response.timings.duration;
  const timing = parseServerTiming(response.headers["Server-Timing"] || response.headers["server-timing"]);
  const phase = phaseMetrics[exec.scenario.name];

  operationDuration[operation].add(duration);
  endToEndDuration.add(duration);
  phase.endToEnd.add(duration);
  requestFailures.add(failed);
  if (response.status >= 500) unplanned5xx.add(1);

  if (timing) {
    serverApplicationDuration.add(timing.app);
    sabledbDuration.add(timing.sabledb);
    nonStoreDuration.add(timing.nonstore);
    externalPathDuration.add(Math.max(0, duration - timing.app));
    sabledbRoundTrips.add(timing.roundTrips);
    phase.application.add(timing.app);
    phase.sabledb.add(timing.sabledb);
  } else {
    requestFailures.add(true);
  }

  check(response, {
    "enterprise operation returned 200": (value) => value.status === 200,
    "internal timing was returned": () => timing !== null,
  });
}

function requestFor(operation, fixture) {
  const sessionHeaders = {
    ...jsonHeaders,
    Cookie: `__Host-Http-rustyauth_session=${fixture.sessionToken}`,
  };
  const options = {
    headers: sessionHeaders,
    tags: { operation },
    responseType: "none",
  };
  switch (operation) {
    case "token":
      return { method: "POST", url: `${__ENV.TARGET_URL}/v1/token`, body: "", options };
    case "credentials":
      return { method: "GET", url: `${__ENV.TARGET_URL}/v1/credentials`, options };
    case "jwks":
      return {
        method: "GET",
        url: `${__ENV.TARGET_URL}/.well-known/jwks.json`,
        options: { ...options, headers: jsonHeaders },
      };
    default:
      return { method: "GET", url: `${__ENV.TARGET_URL}/v1/account`, options };
  }
}

// Exact deterministic mix: 60% session-backed account reads, 20% token minting,
// 15% passkey inventory reads and 5% public key discovery.
function operationForIteration(iteration) {
  const slot = iteration % 20;
  if (slot < 12) return "account";
  if (slot < 16) return "token";
  if (slot < 19) return "credentials";
  return "jwks";
}

function durationSeconds(value) {
  const match = String(value).match(/^([0-9]+)(s|m|h)$/);
  if (!match) throw new Error(`unsupported phase duration ${value}`);
  const multiplier = match[2] === "h" ? 3_600 : match[2] === "m" ? 60 : 1;
  return Number(match[1]) * multiplier;
}
