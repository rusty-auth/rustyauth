const DEFAULT_TEMPLATE_ID = "ea7d8dec-ce0a-4231-9559-fe8845a8809b";
const DEFAULT_WORKSPACE_ID = "33da4e8e-d3bf-464a-ace0-bc5426be65c9";
const DEFAULT_CONFIG_PATH = "railway.template.json";
const DEFAULT_API_URL = "https://backboard.railway.com/graphql/internal";

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };

interface TemplateService {
  name?: string;
  source?: { image?: string };
  networking?: { serviceDomains?: Record<string, unknown> };
  variables?: Record<string, { defaultValue?: string }>;
  volumeMounts?: Record<string, { mountPath?: string }>;
}

export interface RailwayTemplateConfig {
  services?: Record<string, TemplateService>;
  buckets?: Record<string, { name?: string }>;
}

interface ImageOverrides {
  api?: string;
  dashboard?: string;
  sabledb?: string;
}

interface Options {
  apiUrl: string;
  check: boolean;
  configPath: string;
  images: ImageOverrides;
  templateId: string;
  workspaceId: string;
}

function requireValue(args: string[], index: number, option: string): string {
  const value = args[index + 1];
  if (value == null || value.startsWith("--")) throw new Error(`${option} requires a value`);
  return value;
}

function parseOptions(args: string[]): Options {
  const options: Options = {
    apiUrl: Deno.env.get("RAILWAY_TEMPLATE_API_URL") ?? DEFAULT_API_URL,
    check: false,
    configPath: DEFAULT_CONFIG_PATH,
    images: {},
    templateId: Deno.env.get("RAILWAY_TEMPLATE_ID") ?? DEFAULT_TEMPLATE_ID,
    workspaceId: Deno.env.get("RAILWAY_TEMPLATE_WORKSPACE_ID") ?? DEFAULT_WORKSPACE_ID,
  };
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (arg === "--check") options.check = true;
    else if (arg === "--config") options.configPath = requireValue(args, index++, arg);
    else if (arg === "--template-id") options.templateId = requireValue(args, index++, arg);
    else if (arg === "--workspace-id") options.workspaceId = requireValue(args, index++, arg);
    else if (arg === "--api-url") options.apiUrl = requireValue(args, index++, arg);
    else if (arg === "--api-image") options.images.api = requireValue(args, index++, arg);
    else if (arg === "--dashboard-image") options.images.dashboard = requireValue(args, index++, arg);
    else if (arg === "--sabledb-image") options.images.sabledb = requireValue(args, index++, arg);
    else throw new Error(`unknown option ${arg}`);
  }
  return options;
}

function entries(config: RailwayTemplateConfig): Array<[string, TemplateService]> {
  return Object.entries(config.services ?? {});
}

function serviceByName(config: RailwayTemplateConfig, name: string): [string, TemplateService] {
  const match = entries(config).find(([, service]) => service.name === name);
  if (match == null) throw new Error(`Railway template is missing ${name}`);
  return match;
}

function assertPinnedImage(image: string | undefined, repository: string): void {
  const expected = new RegExp(`^ghcr\\.io/rusty-auth/${repository}@sha256:[0-9a-f]{64}$`);
  if (image == null || !expected.test(image)) {
    throw new Error(`${repository} must use a public immutable GHCR digest, received ${image ?? "none"}`);
  }
}

export function prepareTemplateConfig(
  source: RailwayTemplateConfig,
  overrides: ImageOverrides = {},
): RailwayTemplateConfig {
  const config = structuredClone(source);
  const api = serviceByName(config, "RustyAuth")[1];
  const dashboard = serviceByName(config, "rustyauth-dashboard")[1];
  const sabledb = serviceByName(config, "SableDB")[1];
  if (entries(config).length !== 3) {
    throw new Error("the standalone Railway template must contain three services");
  }

  api.source ??= {};
  dashboard.source ??= {};
  sabledb.source ??= {};
  if (overrides.api != null) api.source.image = overrides.api;
  if (overrides.dashboard != null) dashboard.source.image = overrides.dashboard;
  if (overrides.sabledb != null) sabledb.source.image = overrides.sabledb;
  assertPinnedImage(api.source.image, "rustyauth");
  assertPinnedImage(dashboard.source.image, "dashboard");
  assertPinnedImage(sabledb.source.image, "sabledb");

  const publicServices = entries(config).filter(([, service]) =>
    Object.keys(service.networking?.serviceDomains ?? {}).length > 0
  );
  if (publicServices.length !== 1 || publicServices[0][1].name !== "rustyauth-dashboard") {
    throw new Error("only rustyauth-dashboard may have a public Railway domain");
  }
  if (
    dashboard.variables?.RUSTYAUTH_API_UPSTREAM?.defaultValue !==
      "http://${{RustyAuth.RAILWAY_PRIVATE_DOMAIN}}:8080"
  ) {
    throw new Error("dashboard must use the RustyAuth private Railway endpoint");
  }
  if (api.variables?.AUTH_TRUSTED_PROXY_HOPS?.defaultValue !== "1") {
    throw new Error("production API must trust exactly the dashboard gateway proxy hop");
  }
  if (!Object.values(sabledb.volumeMounts ?? {}).some((mount) => mount.mountPath === "/var/lib/sabledb")) {
    throw new Error("SableDB must mount persistent storage at /var/lib/sabledb");
  }
  const buckets = Object.values(config.buckets ?? {});
  if (buckets.length !== 1 || buckets[0].name !== "rustyauth-backups") {
    throw new Error("the standalone Railway template must contain the rustyauth-backups bucket");
  }
  return config;
}

function canvasConfig(config: RailwayTemplateConfig): Json {
  const dashboardId = serviceByName(config, "rustyauth-dashboard")[0];
  const apiId = serviceByName(config, "RustyAuth")[0];
  const sabledbId = serviceByName(config, "SableDB")[0];
  const bucketId = Object.keys(config.buckets ?? {})[0];
  const ids = [dashboardId, apiId, sabledbId, bucketId];
  return {
    groups: {},
    groupRefs: Object.fromEntries(ids.map((id) => [id, null])),
    positions: {
      [dashboardId]: { x: 0, y: 0 },
      [apiId]: { x: 7, y: 0 },
      [sabledbId]: { x: 14, y: 0 },
      [bucketId]: { x: 7, y: 7 },
    },
  };
}

function canonical(value: Json): string {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value != null && typeof value === "object") {
    return `{${
      Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, item]) =>
        `${JSON.stringify(key)}:${canonical(item)}`
      ).join(",")
    }}`;
  }
  return JSON.stringify(value);
}

async function graphQL<T>(apiUrl: string, token: string, query: string, variables: Json): Promise<T> {
  const response = await fetch(apiUrl, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ query, variables }),
  });
  const body = await response.json() as { data?: T; errors?: Array<{ message?: string }> };
  if (!response.ok || body.errors?.length || body.data == null) {
    const detail = body.errors?.map((error) => error.message).filter(Boolean).join("; ") ||
      `HTTP ${response.status}`;
    throw new Error(`Railway template API failed: ${detail}`);
  }
  return body.data;
}

async function main(): Promise<void> {
  const options = parseOptions(Deno.args);
  const source = JSON.parse(await Deno.readTextFile(options.configPath)) as RailwayTemplateConfig;
  const config = prepareTemplateConfig(source, options.images);
  const summary = entries(config).map(([, service]) => ({
    name: service.name,
    image: service.source?.image,
  }));
  if (options.check) {
    console.log(
      JSON.stringify({ buckets: Object.values(config.buckets ?? {}).length, services: summary }, null, 2),
    );
    return;
  }

  const token = Deno.env.get("RAILWAY_API_TOKEN");
  if (token == null || token.length < 20) {
    throw new Error("RAILWAY_API_TOKEN is required to update the template");
  }
  const mutation = `
    mutation templateUpsertConfig($id: String!, $input: TemplateUpsertConfigInput!) {
      templateUpsertConfig(id: $id, input: $input) { id code }
    }
  `;
  const updated = await graphQL<{ templateUpsertConfig: { id: string; code: string } }>(
    options.apiUrl,
    token,
    mutation,
    {
      id: options.templateId,
      input: {
        name: "RustyAuth",
        workspaceId: options.workspaceId,
        serializedConfig: config as Json,
        canvasConfig: canvasConfig(config),
      },
    },
  );
  const query = `
    query templateReadback($id: String!) {
      template(id: $id) { id code serializedConfig }
    }
  `;
  const readback = await graphQL<{ template: { id: string; code: string; serializedConfig: Json } }>(
    options.apiUrl,
    token,
    query,
    { id: options.templateId },
  );
  if (canonical(readback.template.serializedConfig) !== canonical(config as Json)) {
    throw new Error("Railway template read-back did not match the requested service graph");
  }
  console.log(JSON.stringify(
    {
      code: updated.templateUpsertConfig.code,
      id: updated.templateUpsertConfig.id,
      services: summary,
      verified: true,
    },
    null,
    2,
  ));
}

if (import.meta.main) await main();
