#!/usr/bin/env bash
# Fails on patterns this repository replaced. Each rule has a violating example, which must match
# its regex, and a reason that names the right way. Use this table only for what types and clippy
# (clippy.toml) cannot catch.
set -euo pipefail
cd "$(dirname "$0")/../.."

failures=0

# $1 = id, $2 = rg globs (space-separated), $3 = regex, $4 = a violating line, $5 = the right way
rule() {
  local id=$1 regex=$3 example=$4 reason=$5 globs=() glob list
  read -r -a list <<<"$2"
  for glob in "${list[@]}"; do globs+=(-g "$glob"); done
  if ! rg -q -e "$regex" <<<"$example"; then
    echo "patterns.sh: rule $id does not match its own example" >&2
    failures=$((failures + 1))
  fi
  if rg -n -e "$regex" "${globs[@]}" -g '!scripts/ci/patterns.sh' .; then
    echo "^ $id: $reason" >&2
    failures=$((failures + 1))
  fi
}

signin='crates/zeabur-identity-signin/src/** !crates/zeabur-identity-signin/src/request.rs'

rule signin-no-store "$signin" '"no-store"' \
  'headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));' \
  'the sign-in routers set Cache-Control once with request::no_store(), errors included; do not set it in a handler'

rule signin-raw-body "$signin" '\w:\s*(axum::(body::|extract::)?)?(Bytes\b|Json<)' \
  'body: Bytes,' \
  'take request::Body<Account or SameOrigin, T>, which refuses a cross-site request before it reads the body'

rule k3d-image-import '*.sh *.md *.mdx *.yml' 'k3d\s+image\s+import(\s|$)' \
  'k3d image import zeabur-identity:e2e --cluster zeabur-identity' \
  'k3d 5.9.0 can report success before ctr reads the tarball; use k3d_import (scripts/lib.sh), which pipes docker image save into ctr in each node'

rule text-scraping 'scripts/**' '\b(grep|sed|awk|cut)\b' \
  'uname -m | sed -e s/arm64/aarch64/' \
  'scraping text breaks without an error when a column or quoting changes; read structured output with jq, yq or kubectl -o jsonpath, filter with flags such as docker ps --filter, search text with rg, and write a long script with branches as a Rust test or a Bun script'

if ((failures > 0)); then
  exit 1
fi
