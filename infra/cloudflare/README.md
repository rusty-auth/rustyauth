# Cloudflare infrastructure

This Pulumi project owns the Cloudflare Pages project, apex DNS record and custom-domain binding for
`rustyauth.dev`. It deliberately does not manage `rustyauth.com`, which is reserved for a future
commercial service.

The production stack lives in the `livermoreledger` Pulumi organisation. Cloudflare credentials are
injected at runtime through `CLOUDFLARE_API_TOKEN`, `CLOUDFLARE_DNS_API_TOKEN` and
`CLOUDFLARE_ACCOUNT_ID`; they are never stored
in Pulumi configuration or this repository. Livermore maintainers source them from the self-hosted
Infisical environment.

```sh
deno task site:build
pulumi -C infra/cloudflare preview \
  --stack livermoreledger/rustyauth-cloudflare/production
pulumi -C infra/cloudflare up --yes \
  --stack livermoreledger/rustyauth-cloudflare/production
deno task site:publish
```

The Pages project uses direct upload so the tested Astro output in `site/dist` is exactly what is
published. Pulumi owns the long-lived infrastructure; Wrangler creates immutable Pages deployments.
