# Archived SolidJS service-account detail interaction audit

## Audit scope

- Surface: RustyAuth control plane, populated local preview.
- Flow: open **Service accounts**, select **audit-exporter**, inspect and dismiss its detail panel.
- User goal: understand a machine principal and its credentials without losing list context.
- Evidence:
  - Step 1: `/Users/seanknowles/Desktop/Projects/rustyauth/.codex-service-account-audit-01-list.png`
  - Step 2 before correction:
    `/Users/seanknowles/Desktop/Projects/rustyauth/.codex-service-account-audit-02-strange-drawer.png`
  - Step 2 after correction:
    `/Users/seanknowles/Desktop/Projects/rustyauth/.codex-service-account-implementation-open.png`

## Steps

1. **Service-account list — healthy.** The table communicates principal name, description, status, scope count
   and recency clearly. Rows have a consistent, discoverable disclosure affordance.
2. **Open account detail — corrected.** The initial panel was fixed to the animated content stack at
   `x290/y154`, so its backdrop covered only the table region and the panel appeared to float inside the page.
   The corrected inspector is fixed to the viewport at `x0/y0`, fills the 1202px viewport height and preserves
   the table as dimmed context.
3. **Dismiss detail — healthy after correction.** The close control receives focus, Escape closes the
   inspector, focus returns to the selected account row, backdrop click closes, and page scrolling is locked
   only while the inspector is open.

## Strengths

- The existing information hierarchy is concise: identity, scopes, credential state and immutable metadata.
- Destructive credential revocation remains visually separated from neutral metadata.
- The final 500px inspector width keeps the underlying list recognizable without compressing the detail copy.

## UX and accessibility risks found

- **P2 — broken spatial model:** a retained `transform` on `.content-stack` made the fixed overlay use the
  content region as its containing block.
- **P2 — incomplete dismissal:** the service-account backdrop did not close the inspector and Escape was not
  handled.
- **P2 — missing dialog behavior:** the panel lacked dialog semantics, an accessible close label, initial
  focus, focus containment and focus restoration.

## Corrections

- Removed the retained page-entry transform after animation completion.
- Made the inspector and backdrop cover the complete viewport with a restrained dim/blur treatment.
- Added `role="dialog"`, `aria-modal`, labelled title/description relationships and an accessible close name.
- Added initial focus, Tab containment, Escape dismissal, focus restoration and temporary body scroll lock.

## Evidence limits

- Browser semantics, focus movement, Escape dismissal, geometry and console output were verified.
- This bounded pass does not claim full WCAG compliance or replace testing with a screen reader.
