# Dioxus dashboard and operator-auth clone design QA

## Comparison target

- Source visual truth: the packaged SolidJS preview at `http://127.0.0.1:8081/?preview=1`.
- Auth source visual truth: the packaged SolidJS classic sign-in at `http://127.0.0.1:8081/` and Aperture
  variant at `http://127.0.0.1:8081/?login=aperture`.
- Implementation: the Dioxus sign-in at `http://127.0.0.1:5196/`, Aperture variant at
  `http://127.0.0.1:5196/?login=aperture`, and populated preview at `http://127.0.0.1:5196/?preview=1`.
- States: unauthenticated operator sign-in, passkey boundary error, populated preview data and local development
  instance.
- Desktop CSS viewport: `1390 × 1202` at density `1` after viewport calibration.
- Mobile CSS viewport: `390 × 844` at density `1` after viewport calibration.
- Auth desktop comparison viewport: `1707 × 960` CSS pixels. Browser `devicePixelRatio` was `1.5`; the browser
  produced equal source and implementation screenshots at `1707 × 960` pixels, so no resampling was applied.
- Auth responsive comparison viewport: `520 × 1125` CSS pixels. Browser `devicePixelRatio` was `0.75`; equal
  source and implementation screenshots were `693 × 1500` pixels and were compared at that shared density.

## Evidence

All evidence is stored in the ignored local `.codex-dioxus/` QA directory.

### Source captures

- `reference-overview.png`
- `reference-users.png`
- `reference-organization.png`
- `reference-service-accounts.png`
- `reference-webhooks.png`
- `reference-metrics-qa.png`
- `reference-mobile-overview-qa.png`
- `reference-mobile-navigation-qa.png`
- `reference-operator-menu-qa.png`
- `reference-signin-classic-final.png`
- `reference-signin-aperture-final.png`
- `reference-signin-classic-mobile.png`

### Implementation captures

- `implementation-overview-viewport.png`
- `implementation-users.png`
- `implementation-organization.png`
- `implementation-service-accounts.png`
- `implementation-webhooks.png`
- `implementation-metrics.png`
- `implementation-mobile-overview.png`
- `implementation-mobile-navigation-full.png`
- `implementation-operator-menu.png`
- `implementation-signin-classic-final.png`
- `implementation-signin-aperture-final.png`
- `implementation-signin-classic-mobile.png`

### Full-view comparison inputs

- `compare-overview.png`
- `compare-users.png`
- `compare-organization.png`
- `compare-service-accounts.png`
- `compare-webhooks.png`
- `compare-metrics.png`
- `compare-mobile-overview.png`
- `compare-mobile-navigation.png`
- `compare-operator-menu.png`
- `comparison-signin-classic.png`
- `comparison-signin-aperture.png`
- `comparison-signin-classic-mobile.png`

The desktop in-app viewport capture excludes 38 pixels of browser panel chrome. Source and implementation were
therefore normalized to the same `1390 × 1164` top crop before side-by-side comparison. The mobile overview
compares equal `390 × 1815` full-page captures. The mobile navigation comparison crops both equal-density
captures to the intended `390 × 844` viewport. No density mismatch or browser chrome was judged as product
drift.

The auth comparisons preserve the same route, animation-settled state, CSS viewport and screenshot density for
source and implementation. The desktop source and implementation frames are each `1707 × 960`; the responsive
classic frames are each `693 × 1500` for the shared `520 × 1125` CSS viewport. Browser chrome is absent from all
auth captures.

### Focused comparison inputs

- `compare-focus-chrome.png`: logo, top bar, sidebar, preview banner, headings and metric typography.
- `compare-focus-identity-table.png`: table rhythm, avatars, status chips, copy and row affordances.
- `compare-focus-metrics.png`: metric cards, chart geometry, funnel meters, color and data labels.
- `compare-mobile-navigation.png`: responsive drawer, scrim, icons, footer and touch layout.
- `comparison-signin-classic-focus.png`: classic lockup, headline, email field, passkey CTA, evaluation CTA and
  trust-boundary cards.
- `comparison-signin-aperture-focus.png`: textured backdrop, dark console proportions, trust rail, headline,
  form hierarchy and both call-to-action states.

Focused inputs were required because typography, icons, status chips and table density are too small to judge
reliably from the complete desktop views alone.

## Findings

No actionable P0, P1 or P2 visual differences remain.

- Fonts and typography: same Inter/system and mono stacks, weights, sizes, line heights, tracking, wrapping and
  hierarchy because the clone consumes the established dashboard stylesheet. The auth pass additionally checks
  the classic two-line headline and Aperture two-line headline at the matched desktop viewport; renderer-specific
  text-width compensation keeps their visible pixel bounds within three pixels of the source.
- Spacing and layout rhythm: desktop grid, `242px` navigation rail, top-bar height, page gutters, cards, forms,
  tables, radii and mobile stacking match the source comparisons. Both auth card layouts, rail proportions,
  form rhythm and responsive stacking match their combined comparison inputs.
- Colors and visual tokens: graphite, paper, copper, green and amber tokens, opacity, dividers, active states and
  chart fills match. The Aperture backdrop and soft-light console treatment use the exact source texture.
- Image quality and asset fidelity: the real RustyAuth PNG lockup is embedded from the source brand asset; no
  placeholder, CSS drawing, handcrafted SVG or emoji replaces a target asset. Both source lockups, the standalone
  mark and `operator-paper-v1.webp` are embedded as first-party source assets. Tabler icons use the same icon family
  as the source.
- Copy and content: all six screens reproduce the source labels, fixture values, statuses, table rows, form copy
  and policy notes. Both auth variants reproduce the source labels and policy copy. The submitted-form error is
  intentionally client-specific: it explains that the standalone Dioxus console must be connected before a real
  passkey ceremony can run instead of claiming successful authentication.
- Responsiveness: the `390px` overview, navigation drawer, scrim, charts, cards and horizontally bounded table
  behavior match the source state without overlap or unusable controls. The auth form also matches the source at
  the tested `520px` responsive width, with no horizontal overflow or clipped action.
- Accessibility and behavior: semantic buttons, labels, dialogs, status text, alt text and reduced-motion CSS
  remain present. Keyboard/focus behavior is supplied by native HTML controls in the web renderer.

Residual P3 note: operating-system text and SVG antialiasing may differ between webview implementations on
Windows, Linux, iOS and Android. This does not change layout or hierarchy and should be rechecked when those
packages are produced.

## Interaction evidence

The browser-rendered implementation was exercised for:

- navigation across all six screens;
- user search reducing four rows to the matching account;
- user detail drawer open and close;
- organization name edit, saved confirmation and reset;
- service-account create modal validation and account detail drawer;
- webhook create validation and existing-endpoint edit state;
- metrics range selection and active state;
- operator menu and profile drawer open and close;
- mobile navigation open and close behavior;
- classic sign-in form submission and explicit unpaired-client error state;
- classic and Aperture `Open populated preview` entry;
- `Connect live` returning from the preview to classic sign-in;
- sidebar operator control returning to classic sign-in;
- avatar-menu `Exit preview` returning to classic sign-in; and
- profile-drawer `Exit preview` returning to classic sign-in.

The browser console was checked after the final build and contained no errors.

## Comparison history

### Preflight correction

- Earlier finding: **P1 — missing brand asset**. The first Dioxus preview rendered a broken image because the
  existing `/brand/rustyauth-lockup.png` URL was not part of the standalone Dioxus bundle.
- Fix: embed the real `site/public/brand/rustyauth-lockup.png` bytes in the cross-platform application and render
  that source asset as a PNG data URL.
- Post-fix evidence: `compare-focus-chrome.png` shows the source and implementation lockups at matching size,
  crop and sharpness.

### Formal side-by-side pass

- Compared every desktop screen and both mobile states in combined inputs.
- No new P0, P1 or P2 findings were identified, so no further visual-fix iteration was required.

### Operator-auth iteration

- Earlier finding: **P0 — missing route and core journey**. The Dioxus clone opened only the populated preview;
  `Connect live`, the sidebar operator control and both `Exit preview` actions had no sign-in destination.
- Fix: add the classic and Aperture operator sign-in screens, preserve the original query states, add an honest
  standalone-client passkey error state, and wire every preview entry/exit control through the same app state.
- Post-fix interaction evidence: all four preview exits return to the classic sign-in, both sign-in variants open
  the populated preview, and the URL is synchronized to `/`, `/?login=aperture` or `/?preview=1` on web.
- Earlier finding: **P2 — auth headline wrapping drift**. At the matched desktop viewport the host renderer wrapped
  the classic headline across three lines and the Aperture headline across three lines, while both source designs
  use two lines. This also shifted the form vertically.
- Fix: compensate for the standalone renderer's glyph-width difference only on the two auth headlines, retaining
  the established font size, weight, line height and source CSS while restoring the source line breaks.
- Post-fix visual evidence: `comparison-signin-classic-focus.png` and `comparison-signin-aperture-focus.png` show
  matching two-line headlines, vertical rhythm and call-to-action placement. Pixel-threshold checks put the final
  classic headline bounds within three pixels of the source.
- Final auth pass: no actionable P0, P1 or P2 differences remain in the combined desktop and responsive inputs.

### Aperture trust-rail motion iteration

- Source visual truth: the user-annotated SolidJS Aperture sign-in at
  `http://127.0.0.1:8081/?login=aperture`.
- Implementation: the Dioxus Aperture sign-in at `http://127.0.0.1:5196/?login=aperture`.
- Matched viewport and captures: 1707 × 960 CSS px, 1707 × 960 screenshot pixels, browser DPR 1.5;
  both screenshots were normalized by the in-app browser to CSS-pixel output.
- Settled source: `.codex-dioxus/source-aperture-trust-motion-final.png`.
- Settled implementation: `.codex-dioxus/implementation-aperture-trust-motion-final.png`.
- Full-view comparison: `.codex-dioxus/comparison-aperture-trust-motion-final.png`.
- Focused trust-rail comparison: `.codex-dioxus/comparison-aperture-trust-motion-final-focus.png`.
- Staged entrance evidence around 900ms:
  `.codex-dioxus/comparison-aperture-trust-motion-900ms.png` and
  `.codex-dioxus/comparison-aperture-trust-motion-900ms-focus.png`.

The earlier rail used one generic 500ms child fade, so the three-part trust relationship arrived as a flat
group. The revised rail reveals from the left over 760ms, introduces its label at 360ms, lands Operator,
RustyAuth and SableDB at 440ms, 760ms and 1080ms, and draws each connector between the corresponding node
entrances. The active RustyAuth shield gets a restrained 3.8s copper ring after the entry sequence.

The browser-read motion contracts for the source and Dioxus implementation are byte-for-byte equivalent:
animation names, delays, durations, easing functions and iteration counts all match. The intermediate
screenshots show the intended partially drawn state; exact pixel comparison is reserved for the settled frame
because background-tab animation scheduling can shift a live capture by a fraction of a frame.

Required fidelity surfaces remain passed: typography, layout rhythm, palette, official brand imagery, Tabler
icons and copy are unchanged in the settled comparison. The global reduced-motion rule now also removes
animation and transition delays, preventing hidden delayed states before the 0.01ms final frame is applied.

No actionable P0, P1 or P2 findings remain after the motion iteration. `dashboard:check`, `dashboard:build`,
web clippy, desktop and mobile feature checks, the Dioxus web release build and `git diff --check` passed.

### Aperture embossed-paper iteration

- User direction: add a soft moving shimmer and a transparent, embossed RustyAuth R to the open paper field
  surrounding the Aperture console.
- Pre-change source capture: `.codex-dioxus/source-aperture-emboss-before.png`.
- Final SolidJS source: `.codex-dioxus/source-aperture-emboss-final.png`.
- Final Dioxus implementation: `.codex-dioxus/implementation-aperture-emboss-final.png`.
- Matched viewport and captures: 1707 × 960 CSS px, 1707 × 960 screenshot pixels, browser DPR 1.5;
  the in-app browser normalized both outputs to CSS-pixel dimensions.
- Full-view comparison: `.codex-dioxus/comparison-aperture-emboss-final.png`.
- Focused paper-and-mark comparison: `.codex-dioxus/comparison-aperture-emboss-final-focus.png`.

The mark is derived directly from the official 512 × 512 RustyAuth raster, with its white field removed into
alpha while preserving the original R, diagonal cut and keyhole geometry. The source asset is not redrawn.
Two copies create the material response: a multiply-blended warm recessed edge and a screen-blended ivory
raised edge. Their interiors are balanced to stay close to the underlying paper color, so the effect reads as
blind emboss instead of a translucent sticker.

The paper's existing security texture remains the only full-bleed image. Its screen-blended layer now travels
over 12 seconds; the embossed mark drifts over 18 seconds and its highlight changes over 8.5 seconds. Browser
inspection confirmed the complete source and Dioxus motion contracts are identical. Reduced-motion still
collapses every animation to a single 0.01ms final frame with no delayed hidden state.

Required fidelity surfaces pass: typography, console geometry, spacing, palette, controls and copy are
unchanged; the added mark uses the official brand silhouette and remains behind the interaction surface. The
first implementation pass was treated as P2 because it read too much like a flat translucent watermark. The
final pass rebalanced the opposing blends and strengthened the edge offset; the combined full and focused
evidence shows no remaining actionable P0, P1 or P2 issue.

## Open questions

- None for the clone milestone. Native package-specific antialiasing remains a later platform QA task.

## Implementation checklist

- [x] Real source assets, tokens and icon family used.
- [x] Six desktop screens compared at the same state and viewport.
- [x] Mobile overview and navigation compared at the same state and viewport.
- [x] Classic and Aperture sign-in variants compared at the same desktop state and viewport.
- [x] Aperture trust-rail entrance and settled state verified in SolidJS and Dioxus.
- [x] Source and Dioxus motion contracts verified as identical, with reduced-motion delay removal.
- [x] Official R silhouette converted to alpha and verified as a restrained paper emboss in both renderers.
- [x] Paper shimmer, emboss drift and highlight motion contracts verified as identical.
- [x] Classic sign-in compared at the same responsive state, viewport and screenshot density.
- [x] Preview entry and every Connect live / Exit preview path exercised.
- [x] Core navigation, search, forms, drawers, modals and filters exercised.
- [x] Console errors checked.
- [x] Web release build, web WASM clippy, desktop application bundle and mobile feature check passed.

final result: passed
