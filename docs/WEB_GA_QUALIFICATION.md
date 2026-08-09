# Web GA browser and authenticator qualification

RustyAuth `1.0.0` supports the Dioxus web dashboard served through the hardened same-origin gateway. Desktop,
iOS and Android applications are previews and are not release artifacts. Mobile browsers remain part of the
web contract and require no native RustyAuth package, Xcode build or Android NDK.

## Supported matrix

Record the exact OS, browser and authenticator versions used. “Current” means the vendor-supported stable
release on the day the release owner records evidence; mobile coverage includes the current and immediately
previous supported major OS where devices remain vendor-supported.

| Client | Browser | Required authenticator coverage |
| --- | --- | --- |
| Current and previous macOS | Safari | Touch ID/platform passkey and an iCloud-synced passkey |
| Current macOS | Current stable Chrome | Platform passkey and a FIDO2 roaming security key |
| Current Windows 11 | Current stable Edge | Windows Hello and a FIDO2 roaming security key |
| Current Windows 11 | Current stable Chrome | Windows Hello or the same roaming security key |
| Current macOS or Windows 11 | Current stable Firefox | A FIDO2 roaming security key |
| Current and previous iOS/iPadOS | Safari | Platform passkey and a synced passkey |
| Current and previous vendor-supported Android | Chrome | Android Credential Manager platform/synced passkey |
| Desktop Chrome or Edge plus a supported phone | Browser hybrid flow | Cross-device QR/Bluetooth passkey sign-in |

Other browsers, embedded webviews, browser extensions that rewrite credential calls, private-browsing storage
semantics and vendor-abandoned operating systems are unsupported until separately qualified. A Chromium result
does not substitute for Safari/WebKit or Firefox/Gecko, and a virtual authenticator does not substitute for the
real-device rows above.

## Required journey on every row

Use a synthetic account and the exact release-candidate dashboard/API image digests:

1. Load the dashboard through its production TLS origin and confirm no console error, mixed content, CSP
   violation, unexpected redirect or cross-origin request.
2. Register a first passkey through a one-time production invitation and confirm the invitation cannot be
   reused.
3. Sign out, sign in with the passkey and mint a short-lived audience-bound access token.
4. Complete a fresh passkey step-up, add and rename a second passkey, then revoke it.
5. Generate recovery codes, sign out, consume one code to enrol a replacement passkey, and prove all earlier
   sessions plus the remaining recovery codes are invalid.
6. Revoke all sessions and prove the current cookie no longer authenticates.
7. Attempt one wrong-origin/RP ceremony or replayed challenge and prove it fails without changing account
   state.

On at least Safari/macOS and Edge/Windows, also complete the Owner sign-in, organization/project/environment
journey, pair a synthetic realm, perform a stepped-up reasoned mutation and disconnect it. Fleet unavailability
during the test must not interrupt a separate realm sign-in.

## Evidence requirements

The `browser_authenticator_matrix` release record must link to retained evidence containing:

- release commit and immutable API/dashboard image digests;
- OS build, browser version, device model and authenticator type for every row;
- UTC start/end time, tester and independent witness;
- pass/fail result for every numbered journey step and the Fleet representative rows;
- redacted request IDs or traces proving server-side completion and the expected negative denials;
- browser console/CSP results and any accepted deviations with an owner; and
- confirmation that screenshots, traces and support bundles contain no cookies, bearer tokens, invitation or
  recovery codes, WebAuthn credential material or native preview credentials.

One unresolved failure, an untested supported row, a virtual-only result or evidence captured from a different
artifact digest is a release NO-GO.
