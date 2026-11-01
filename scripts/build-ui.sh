#!/usr/bin/env bash
# Builds the sign-in page assets into ui/dist, styles and scripts as brotli only, and the design
# system's classes into crates/zeabur-identity-ui/templates/ds.html. ui/dist is not committed; cargo
# embeds it when ZEABUR_IDENTITY_UI_DIST points at it (crates/zeabur-identity-ui/build.rs). ds.html
# is committed, as askama reads templates from the crate; CI fails if it differs. Run inside
# `nix develop`.
#   scripts/build-ui.sh && ZEABUR_IDENTITY_UI_DIST="$PWD/ui/dist" cargo build --release -p zeabur-identity
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
ui="$root/ui"
out="$ui/dist"
geist="$ui/node_modules/@zeabur-oss/design-system/vendor/geist"

# Installs exactly bun.lock; fails if package.json and the lock file disagree.
(cd "$ui" && bun ci >/dev/null)
rm -rf "$out"
mkdir -p "$out"
(cd "$ui" && bun run --silent build)
for page in login setup account; do
  bun build "$ui/src/$page.ts" --target=browser --format=esm --minify --outfile "$out/$page.js" >/dev/null
done
for file in app.css login.js setup.js account.js; do
  brotli -q 11 -f -o "$out/$file.br" "$out/$file"
  rm "$out/$file"
done
cp "$geist/Geist-Variable.woff2" "$out/Geist-Variable.woff2"
