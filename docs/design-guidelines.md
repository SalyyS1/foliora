# Design guidelines

## Brand

Foliora uses a quiet botanical/document metaphor: two offset leaves represent
context connected by an open path. The open end means the user controls what is
shared. The name and mark are provisional pending trademark/domain clearance.

Palette: deep ink `#172d2a`, leaf `#23675d`, warm paper `#f7f5ef`, white panel
`#fffefa`, and amber caution `#b17024`. Use amber for review/warning states, not
for success. Avoid shield/checkmark/infinity/AI imagery that overpromises trust.

## Interaction

- Lead with the user's next safe action.
- Show provenance, status and conflict context next to the value they qualify.
- Use exact-preview language before every irreversible or external action.
- Keep network features visually secondary to the local vault.
- Never hide a missing source, conflict, expiry or sensitivity approval behind a
  generic success state.

## Accessibility

All workflows must be keyboard usable, have visible focus, semantic headings and
localized status/aria text. Respect `prefers-reduced-motion`; animations are
decorative and never convey the only meaning. Keep responsive layouts usable at
320px and support Vietnamese diacritics with a bundled or system-safe font.
