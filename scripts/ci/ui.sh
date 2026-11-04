#!/usr/bin/env bash
# Sign-in pages: format, lint and typecheck; the committed design-system classes must match the
# sources; the built pages' tests with the build embedded; budgets and contrast. fallow: unused code
# and boundaries, then new findings against HEAD^ (on a pull request, the base branch); health does
# not fail the job.
set -euo pipefail
cd "$(dirname "$0")/../.."

(cd ui && bun ci && bun run fmt:check && bun run lint && bun run typecheck)
./scripts/build-ui.sh
git diff --exit-code -- crates/zeabur-identity-ui/templates/ds.html
ZEABUR_IDENTITY_UI_DIST="$PWD/ui/dist" cargo nextest run --locked -p zeabur-identity-ui -p zeabur-identity-signin
./scripts/ui-budget.sh
python3 .claude/skills/zeabur-identity-ui/contrast.py
(cd ui && bun run fallow dead-code --baseline fallow-baseline.json &&
  bun run fallow audit --base HEAD^ && bun run fallow health --report-only)
