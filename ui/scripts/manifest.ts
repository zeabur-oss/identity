// Writes dist/manifest.json: every built asset, by the name a page links to. The Rust build
// (crates/zeabur-identity-ui/build.rs) embeds what the manifest lists.
//   bun scripts/manifest.ts <dist>
import { readdirSync, writeFileSync } from "node:fs"
import { join } from "node:path"

const types: Record<string, string> = {
  css: "text/css; charset=utf-8",
  js: "text/javascript; charset=utf-8",
  woff2: "font/woff2",
}

const dist = process.argv[2] ?? "dist"
const manifest: Record<string, { file: string; type: string; brotli: boolean }> = {}
for (const file of readdirSync(dist).sort()) {
  if (file === "manifest.json") continue
  const brotli = file.endsWith(".br")
  const name = brotli ? file.slice(0, -".br".length) : file
  const type = types[name.split(".").pop() ?? ""]
  if (!type) throw new Error(`${file}: no content type for this extension`)
  manifest[name] = { file, type, brotli }
}
writeFileSync(join(dist, "manifest.json"), `${JSON.stringify(manifest, null, 2)}\n`)
