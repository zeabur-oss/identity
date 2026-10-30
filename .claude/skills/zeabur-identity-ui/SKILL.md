---
name: zeabur-identity-ui
description: Change Zeabur Identity's sign-in pages (askama templates, the design system's generated classes, TypeScript, Tailwind CSS, translations) while keeping the strict CSP, committed reproducible assets, size budgets and WCAG 2.2 AA contrast. Use for any change under ui/ or crates/zeabur-identity-ui.
---

# Sign-in pages

- **Where things are.** Sources: `ui/src/*.ts` (one script per page, no framework),
  `ui/styles/app.css` (Tailwind v4 input; imports `@zeabur/design-system/tokens.css`). Templates:
  `crates/zeabur-identity-ui/templates/` (askama). Built output: `crates/zeabur-identity-ui/assets/`
  (committed, embedded with `include_bytes!`). Page routes live in
  `crates/zeabur-identity-signin/src/pages.rs`; rendering in `crates/zeabur-identity-ui/src/pages.rs`.
- **Design system.** `@zeabur/design-system` is a dependency in `ui/package.json`, as in web.
  `ui/scripts/gen-classes.ts` calls its React-free `cva` functions
  (`@zeabur/design-system/variants/<name>`) and writes `templates/ds.html`: one askama macro per
  component part (`ds::button("primary", "lg")`, `ds::card()`, `ds::alert("warn")` …) and the mark.
  Never edit `ds.html`. A component is used as the design system has it; a template adds only
  layout classes (`w-full`, `flex-1`). The generator holds the few identity classes merged over
  the design system's (the card's padding and heading), each one explicit; there are no contrast
  overrides. A value the templates need that is missing from the generator's table goes into the
  table; a treatment the design system lacks goes into the design system. `ui.html` holds the
  markup of the shared macros (card, alert, field, command, disclosure). The Geist font is copied
  from the package by the build. A destructive action on each row of a list (remove a passkey)
  takes `ds::button("secondary-destructive", "sm")`; the solid `destructive` is for the final
  confirm only.
- **Build and check** (inside `nix develop`):
  ```sh
  (cd ui && bun ci && bun run fmt:check && bun run lint && bun run typecheck)
  ./scripts/build-ui.sh && git diff --stat -- crates/zeabur-identity-ui/assets crates/zeabur-identity-ui/templates/ds.html
  ./scripts/ui-budget.sh && python3 .claude/skills/zeabur-identity-ui/contrast.py
  (cd ui && bun run fallow dead-code --baseline fallow-baseline.json && bun run fallow audit --base main)
  cargo nextest run -p zeabur-identity-signin -E 'binary(pages)'
  ```
  Commit the rebuilt assets and `ds.html` with the source change; CI rebuilds and fails on any
  difference. Format with `bun run fmt` in `ui/`. Look at every page state with
  `cargo run -p zeabur-identity-ui --example preview` (http://localhost:8090/).
- **fallow** (`bun run fallow <command>` in `ui/`, config in `ui/.fallowrc.json`). `dead-code` finds
  unused files, exports and dependencies, and a page that imports another page (pages import only
  `webauthn.ts`). `ui/fallow-baseline.json` holds the findings that predate fallow; never add to
  it, and run `bun run fallow baselines prune` after a fix. `audit --base main` is what CI
  gates on: new dead code, complexity and duplication in the changed files. `health` gives the
  score and the complex functions; with no unit tests for `ui/src`, CRAP counts every branch as
  untested. A false positive gets an entry in `.fallowrc.json` with the reason.
- **CSP rules.** No inline `<script>`, `<style>`, `style=""` or `on*=` handlers; no URLs to other
  origins; scripts write only `textContent`, `hidden` and `location` (Trusted Types `'none'`). The
  page tests enforce this.
- **Text.** Every string is a field of `Messages` in `crates/zeabur-identity-ui/src/i18n.rs` with English,
  Traditional Chinese (Taiwan usage, 通行密鑰) and Simplified Chinese (mainland usage, 通行密钥)
  values; scripts get their messages from `data-msg-*` attributes. A missing translation is a
  compile error. Write and review them with the `zeabur-writing` skill, using the terms in Zeabur's
  `docs/internal/wording.md`.
- **Contrast.** After changing a token, a colour class or the design-system pin, run
  `python3 .claude/skills/zeabur-identity-ui/contrast.py` (inside `nix develop`; exits 1 on any
  failure). Try a value first with `--set light:input='rgb(126, 122, 133)'`. Add a pair to its
  inventory when a template starts rendering a new one. Where the design system's own colours
  fall below the WCAG minimum, fix them in the design system, not in the pages.
- **Budgets.** Brotli sizes are checked by `scripts/ui-budget.sh`; raise a budget only with a
  reason in the commit.
