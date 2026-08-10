# Deploy and Host RustyAuth on Railway

## About Hosting RustyAuth

RustyAuth `1.0.0` is a passkey-first authentication service with a separately deployable Dioxus WebAssembly
dashboard, a private Rust API, persistent SableDB state, and encrypted S3-compatible recovery points. This
template deploys the complete supported Railway topology as one unit.

## What the template creates

- `rustyauth-dashboard`: the only public HTTPS service. It serves the web dashboard and forwards only the
  supported same-origin authentication and ConnectRPC paths to the private API.
- `RustyAuth`: the private authorization and mutation boundary. It issues short-lived ES256 tokens and owns
  users, passkeys, browser sessions, operator roles, signing keys, rate limits, and audit events.
- `SableDB`: a private stateful service whose hardened initializer prepares Railway's new root-owned volume
  at `/var/lib/sabledb`, drops to UID/GID 10002, and starts the database.
- `rustyauth-backups`: a private Railway bucket for application-encrypted, read-back-verified recovery points.

All three containers are pinned to immutable public GHCR digests qualified together from the same `main`
revision. The API and SableDB receive no public domain or TCP proxy.

## Required input

Enter `AUTH_OPERATOR_EMAILS` for the verified email address that may bootstrap the first dashboard owner.
Railway derives the issuer, WebAuthn origin, and relying-party ID from the generated dashboard domain. It also
generates independent master, backup, bootstrap, event-RPC, and identity-RPC secrets for every deployment.

After the deployment reaches `SUCCESS`, open the `rustyauth-dashboard` domain. Use `?preview=1` to inspect the
dashboard without changing state, or sign in with the allowlisted verified email and create the first owner
passkey.

## Why Deploy RustyAuth on Railway

Railway provisions the public dashboard gateway, private service network, persistent SableDB volume, generated
secrets, encrypted backup bucket, health checks, and HTTPS domain together. The result preserves RustyAuth's
security boundaries without asking an operator to assemble the services manually.

## Common Use Cases

- Add passkey registration, authentication, browser sessions, and short-lived tokens to a self-hosted product.
- Run an auditable identity boundary without adopting a hosted identity provider.
- Operate isolated project realms now and connect them to the separate RustyAuth Fleet control plane later.
- Evaluate the supported web dashboard through preview mode before creating an operator or user.

## Dependencies for RustyAuth Hosting

### Deployment Dependencies

- Three anonymously pullable Linux container images from `ghcr.io/rusty-auth`.
- Railway private networking between the dashboard, API, and SableDB.
- One persistent Railway volume for SableDB.
- One S3-compatible Railway bucket for encrypted recovery points.
- A generated Railway HTTPS domain on the dashboard service.

## Security and operations

- Browser traffic is same-origin through the dashboard gateway; the dashboard has no database or key material.
- RustyAuth reaches SableDB only through Railway private networking.
- Production proxy trust is explicit: the API trusts exactly the dashboard gateway hop.
- Scheduled backups use independent application encryption and verify each uploaded recovery point by reading
  it back. Railway object storage uses the documented `portable` profile because it does not provide S3 Object
  Lock semantics.
- `/healthz` is process liveness and `/readyz` verifies the complete service dependency chain.

For configuration, recovery, upgrades, and threat-model details, see the
[RustyAuth repository](https://github.com/rusty-auth/rustyauth) and the
[Railway deployment guide](https://github.com/rusty-auth/rustyauth/blob/main/docs/RAILWAY_TEMPLATE.md).

Desktop, iOS, and Android clients remain preview-only. The server, supplied container topology, and web
dashboard are the `1.0.0` GA surface.
