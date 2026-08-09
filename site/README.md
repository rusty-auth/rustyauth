# RustyAuth.dev

The public website and documentation for [RustyAuth](https://github.com/rusty-auth/rustyauth).

The site is an Astro static build. The interactive trust-boundary hero uses Three.js; documentation is
rendered as static HTML with a small framework-free script for navigation, search, the on-page table of
contents and copy buttons. The product dashboard is the separate Dioxus application under `console/`.

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
deno task docs:check
```

The build output is `site/dist/` and is suitable for Cloudflare's static asset hosting.

## Documentation content

Public documentation routes live under `site/src/pages/docs`; grouped navigation and search metadata live in
`site/src/data/docs.ts`. The site provides guided learning paths. Normative, exhaustive contracts remain under
the root [`docs/`](../docs/README.md), `proto/`, `schemas/` and `docs/openapi.yaml` so they are reviewed
beside the implementation.

When adding a route:

1. add its title, description and search terms to `site/src/data/docs.ts`;
2. add the page under `site/src/pages/docs` using `DocsLayout.astro`;
3. link the appropriate normative repository reference; and
4. add the route and an identifying content assertion to `site/tests/rendered-html.test.ts`.

Keep quick-start commands, topology, capability status and security limitations aligned with the root
documentation. The Astro recovery chapter must remain aligned with the normative
[`docs/BACKUPS.md`](../docs/BACKUPS.md) contract. Do not present a roadmap item as an implemented product
claim.

## Deployment

Cloudflare Pages, apex DNS and the `rustyauth.dev` domain binding are managed by the production Pulumi stack
under `infra/cloudflare`. The tested static build is published as a direct upload:

```sh
deno task infra:preview
deno task infra:up
deno task site:publish
```

Cloudflare credentials must be injected at runtime. They are never stored in this repository or in plain
Pulumi configuration.
