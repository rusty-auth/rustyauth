# RustyAuth.dev

The public website and documentation for [RustyAuth](https://github.com/rusty-auth/rustyauth).

The site is an Astro static build with SolidJS islands. The interactive trust-boundary hero uses
Three.js; all documentation remains server-rendered HTML with no client runtime.

## Development

From the repository root:

```sh
deno install
deno task site:dev
```

Validation:

```sh
deno task site:check
deno task site:test
```

The build output is `site/dist/` and is suitable for Cloudflare's static asset hosting.

## Deployment

Cloudflare Pages, apex DNS and the `rustyauth.dev` domain binding are managed by the production
Pulumi stack under `infra/cloudflare`. The tested static build is published as a direct upload:

```sh
deno task infra:preview
deno task infra:up
deno task site:publish
```

Cloudflare credentials must be injected at runtime. They are never stored in this repository or in
plain Pulumi configuration.
