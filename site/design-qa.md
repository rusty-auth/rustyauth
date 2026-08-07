# Design QA

## Reference and implementation

- Visual references: the VTR v2 marketing hero and Ziac marketing hero rendered locally at
  1440 × 900 CSS pixels.
- Implementation: the RustyAuth landing page at the same viewport, plus a focused 390 × 844 mobile
  pass.
- Evidence: `design-qa-vtr-reference.png`, `design-qa-ziac-reference.png`,
  `design-qa-implementation.png` and `design-qa-comparison.png` (local QA artifacts, intentionally
  ignored by Git).

## Comparison history

1. The first infrastructure-map direction used a dark container, glossy materials and floating
   card-like blocks. It did not match either reference and was rejected.
2. The scene was rebuilt with an orthographic camera, flat architectural layers, technical edge
   lines, a pale drafting surface, restrained copper accents, anchored labels and low-amplitude
   motion.
3. Desktop framing was widened so the board and labels remain inside the canvas without covering
   the hero copy.
4. Below 900 px the same live Three.js scene becomes a dimmed, non-interactive architectural
   watermark behind the hero copy. Mobile copy and controls remain fully legible.

## Verification

- Desktop hero: passed at 1440 × 900.
- Mobile hero: passed at 390 × 844.
- Documentation route: passed at `/docs`.
- Primary navigation and calls to action: passed.
- Live GitHub star count: passed.
- Browser console: zero errors and zero warnings on the final live desktop and mobile passes.
- Static build: seven routes generated.
- Rendered HTML tests: two passed.

## Final result

passed

