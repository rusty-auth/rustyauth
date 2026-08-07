# RustyAuth brand guide

## Positioning

RustyAuth is passkey-first authentication for teams that want to own their identity boundary.

Primary strapline:

> Built in Rust. Built on SableDB. Built for passkeys.

Long description:

> RustyAuth is passkey-first authentication built in Rust on SableDB: a small, self-hosted identity
> service for WebAuthn ceremonies, durable browser sessions and short-lived ES256 access tokens.

Do not call RustyAuth production-ready until the README's production gates are complete.

## Naming

- Product: **RustyAuth** — one word, capital R and A.
- Repository slug: `rustyauth` when the standalone split occurs.
- Current internal crate and binary: `passkey-auth-service`.
- Never write `Rusty Auth`, `RustyAUTH`, `Rust Auth` or `Rusty-Auth` in product copy.

Internal protocol identifiers such as `passkey_auth_session` and
the versioned `application/vnd.rustyauth.backup.v2` content type change only through an explicit
compatibility plan. Branding is not a reason to break stored data or clients.

## Voice

RustyAuth copy is:

- direct rather than theatrical;
- technically exact rather than reassuring by assertion;
- independent rather than adversarial toward hosted providers;
- honest about incomplete security work; and
- useful to operators, not only persuasive to buyers.

Prefer “RustyAuth rejects an expired ceremony” over “military-grade protection.” Avoid “unhackable,”
“zero trust” without a defined model, “passwordless” when discussing recovery, and any unsupported
compliance claim.

## Visual identity

The emblem is an architectural `R` divided by a diagonal trust boundary. Copper represents the
public authentication surface, graphite represents private durable state, and the cream aperture
represents a passkey crossing that boundary.

| Token | Hex | Use |
| --- | --- | --- |
| Rust copper | `#CC5A19` | Primary emblem, `Auth`, calls to action |
| Graphite | `#2F2F2F` | `Rusty`, body text, dark surfaces |
| Warm cream | `#FFF8E8` | Aperture and light highlights |
| White | `#FFFFFF` | Primary background |

## Assets

| Asset | Intended use |
| --- | --- |
| [`assets/rustyauth-lockup.png`](../assets/rustyauth-lockup.png) | Primary README and product header |
| [`assets/rustyauth-mark.svg`](../assets/rustyauth-mark.svg) | Scalable standalone icon |
| [`assets/rustyauth-mark.png`](../assets/rustyauth-mark.png) | Raster standalone fallback |

Maintain clear space around the mark equal to at least one quarter of its height. Do not rotate,
stretch, recolour individual pieces, add effects, place text over the aperture or combine it with the
Rust, Cargo, Ferris or SableDB artwork.

## Dependency attribution

Approved short form:

> Built on SableDB.

Approved full form:

> RustyAuth is an independent open-source project built on SableDB. SableDB and its contributors do
> not sponsor, endorse or maintain RustyAuth.

Do not use “SableDB Auth,” “official SableDB authentication,” “SableDB-powered security” or the
SableDB logo without separate written permission.

## Independence statement

Use this statement in public legal or brand documentation:

> RustyAuth is an independent project. It is not sponsored, endorsed or maintained by the Rust
> Foundation, the Rust Project, SableDB or their contributors.

See [TRADEMARKS.md](../TRADEMARKS.md) before creating merchandise, registering a mark or offering a
commercial service under the RustyAuth name.
