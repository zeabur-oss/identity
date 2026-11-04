#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
source "$(dirname "$0")/lib.sh"

bun install --frozen-lockfile
status=0
node_modules/.bin/zeabur-oss-unsafe-report zeabur-identity zeabur-identityctl || status=$?
keep target/unsafe-report.md
exit "$status"
