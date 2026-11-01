#!/usr/bin/env bash
# Builds the sign-in page assets into crates/zeabur-identity-ui/assets and the design system's
# classes into crates/zeabur-identity-ui/templates/ds.html. Both are committed: `cargo build`
# embeds them and never needs this toolchain. CI rebuilds and fails if the committed files
# differ. Run `bun ci` in ui/ first.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
ui="$root/ui"
out="$root/crates/zeabur-identity-ui/assets"
geist="$ui/node_modules/@zeabur-oss/design-system/vendor/geist"

(cd "$ui" && bun run --silent build)
for page in login setup account; do
  bun build "$ui/src/$page.ts" --target=browser --format=esm --minify --outfile "$out/$page.js" >/dev/null
done
cp "$geist/Geist-Variable.woff2" "$out/Geist-Variable.woff2"
cp "$geist/LICENSE.txt" "$out/LICENSE-Geist.txt"
