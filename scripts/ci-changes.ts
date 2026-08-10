export const CI_AREAS = [
  "workflow",
  "protocol",
  "client",
  "site",
  "policy",
  "infrastructure",
  "rust",
  "console",
  "supply_chain",
  "recovery",
  "api_image",
  "dashboard_image",
  "sabledb_image",
] as const;

export type CiArea = (typeof CI_AREAS)[number];
export type CiSelection = Record<CiArea, boolean>;

const matches = (path: string, patterns: RegExp[]): boolean => patterns.some((pattern) => pattern.test(path));

const sharedMetadata = [
  /^LICENSE$/,
  /^NOTICE$/,
  /^THIRD_PARTY_/,
  /^about\.(?:hbs|toml)$/,
];

// This feature-gated binary exists only in Dockerfile.benchmark. It must still
// compile and lint in the Rust lane, but it cannot affect the production API
// image or recovery drills because neither includes it.
const productionRustSource = /^src\/(?!bin\/rustyauth-benchmark\.rs$)/;

const patterns: Record<CiArea, RegExp[]> = {
  workflow: [/^\.github\//, /^scripts\/ci-changes(?:\.test)?\.ts$/],
  protocol: [/^proto\//, /^buf(?:\.gen)?\.yaml$/, /^packages\/protocol\//, /^build\.rs$/],
  client: [
    /^packages\/(?:client|protocol)\//,
    /^deno\.(?:json|lock)$/,
  ],
  site: [
    /^site\//,
    /^benchmarks\/catalog\.json$/,
    /^scripts\/check-benchmark-catalog(?:\.test)?\.ts$/,
    /^docs\//,
    /^assets\//,
    /^examples\//,
    /^(?:README|SECURITY|CONTRIBUTING|CODE_OF_CONDUCT|TRADEMARKS)\.md$/,
    /^packages\/(?:client|protocol)\//,
    /^deno\.(?:json|lock)$/,
  ],
  policy: [
    /^\.github\/workflows\/(?:release|railway-production|native-packaging)\.yml$/,
    /^scripts\/(?:railway-|resolve-image-digest|check-release|check-native|check-dashboard|check-docs|check-helm)/,
    /^scripts\/qualify-(?:runtime-images|sabledb-image)\.sh$/,
    /^charts\//,
    /^benchmarks\/(?!catalog\.json$)/,
    /^Dockerfile\.benchmark$/,
    /^release-evidence\//,
    /^railway(?:\.[^.]+)?\.json$/,
    /^sabledb\/railway\.json$/,
    /^compose(?:\.fleet)?\.yaml$/,
    /^(?:RELEASING|CHANGELOG)\.md$/,
    /^docs\/(?:DEPLOYMENT|KUBERNETES|RAILWAY_TEMPLATE|RELEASE_READINESS|NATIVE_PACKAGING)\.md$/,
    /^deno\.(?:json|lock)$/,
  ],
  infrastructure: [/^infra\/cloudflare\//],
  rust: [
    /^src\//,
    /^tests\//,
    /^Cargo\.(?:toml|lock)$/,
    /^rust-toolchain\.toml$/,
    /^build\.rs$/,
    /^proto\//,
    /^schemas\//,
    /^rustyauth(?:\.fleet)?\.example\.yaml$/,
  ],
  console: [
    /^console\//,
    /^benchmarks\/catalog\.json$/,
    /^Dockerfile\.dashboard$/,
    /^proto\//,
  ],
  supply_chain: [
    /^(?:Cargo|deno)\.(?:toml|json|lock)$/,
    /^console\/Cargo\.(?:toml|lock)$/,
    /^sabledb\/Cargo\.lock$/,
    /^fuzz\/Cargo\.(?:toml|lock)$/,
    /^deny\.toml$/,
    /^Dockerfile(?:\.dashboard|\.benchmark)?$/,
    /^sabledb\/Dockerfile$/,
    /^\.gitmodules$/,
    /^vendor\/sabledb(?:\/|$)/,
    ...sharedMetadata,
  ],
  recovery: [
    productionRustSource,
    /^tests\//,
    /^Cargo\.(?:toml|lock)$/,
    /^rust-toolchain\.toml$/,
    /^build\.rs$/,
    /^proto\//,
    /^compose\.integration\.yaml$/,
    /^sabledb\//,
    /^\.gitmodules$/,
    /^vendor\/sabledb(?:\/|$)/,
  ],
  api_image: [
    /^Dockerfile$/,
    /^container-healthcheck\//,
    productionRustSource,
    /^Cargo\.(?:toml|lock)$/,
    /^rust-toolchain\.toml$/,
    /^build\.rs$/,
    /^proto\//,
    /^rustyauth(?:\.fleet)?\.example\.yaml$/,
    ...sharedMetadata,
  ],
  dashboard_image: [
    /^Dockerfile\.dashboard$/,
    /^container-healthcheck\//,
    /^console\//,
    /^benchmarks\/catalog\.json$/,
    ...sharedMetadata,
  ],
  sabledb_image: [
    /^sabledb\/(?:Cargo\.lock|Dockerfile|server\.ini)$/,
    /^\.gitmodules$/,
    /^vendor\/sabledb(?:\/|$)/,
    /^container-healthcheck\//,
    ...sharedMetadata,
  ],
};

const fullQualificationPaths = [
  /^\.github\/workflows\/ci\.yml$/,
  /^scripts\/ci-changes(?:\.test)?\.ts$/,
];

export function classifyCiChanges(paths: string[]): CiSelection {
  const normalized = paths.map((path) => path.trim()).filter(Boolean);
  // A newly introduced top-level area must not silently bypass CI just because
  // this classifier has not learned it yet. Unknown paths conservatively run all
  // lanes until an explicit mapping is added.
  const unknown = normalized.some(
    (path) => !CI_AREAS.some((area) => matches(path, patterns[area])),
  );
  const all = unknown || normalized.some((path) => matches(path, fullQualificationPaths));
  return Object.fromEntries(
    CI_AREAS.map((area) => [
      area,
      all || normalized.some((path) => matches(path, patterns[area])),
    ]),
  ) as CiSelection;
}

async function changedPaths(base: string, head: string): Promise<string[]> {
  const validBase = base && !/^0+$/.test(base);
  // Deletions matter: removing a source, manifest or workflow file must qualify
  // the same consumers as changing it.
  const args = validBase ? ["diff", "--name-only", "--diff-filter=ACMRD", base, head] : ["ls-files"];
  const result = await new Deno.Command("git", { args, stdout: "piped", stderr: "inherit" }).output();
  if (!result.success) throw new Error(`git ${args.join(" ")} failed`);
  return new TextDecoder().decode(result.stdout).split("\n");
}

if (import.meta.main) {
  const base = Deno.env.get("BASE_SHA") ?? "";
  const head = Deno.env.get("HEAD_SHA") ?? "HEAD";
  const selected = classifyCiChanges(await changedPaths(base, head));
  for (const area of CI_AREAS) console.log(`${area}=${selected[area]}`);
}
