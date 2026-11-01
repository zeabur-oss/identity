#!/usr/bin/env bash
# Fails if the sign-in page assets exceed their size budget (brotli, the size a browser downloads).
# Budgets are first measurements with headroom; see the zeabur-identity-ui docs.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
assets="${ZEABUR_IDENTITY_UI_DIST:-$root/ui/dist}"
status=0
printf '%-12s %8s %8s %8s\n' asset bytes brotli budget
for entry in app.css:9216 login.js:3072 setup.js:3072 account.js:3072; do
  name="${entry%%:*}"
  budget="${entry##*:}"
  raw=$(brotli -d --stdout "$assets/$name.br" | wc -c | tr -d ' ')
  compressed=$(wc -c <"$assets/$name.br" | tr -d ' ')
  printf '%-12s %8s %8s %8s\n' "$name" "$raw" "$compressed" "$budget"
  if (( compressed > budget )); then
    echo "error: $name is $compressed bytes compressed, over its budget of $budget" >&2
    status=1
  fi
done
exit $status
