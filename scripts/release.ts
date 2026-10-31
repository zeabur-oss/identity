// One stage of a release, as the shared release workflow of zeabur-oss/.github runs it, in the dev
// shell of the commit being released: `bun scripts/release.ts <stage> <version> ...`.
// @zeabur-oss/release (zeabur-oss/.github, release/) pushes, signs and verifies; the workflow
// itself checks the CHANGELOG.md section, signs SHA256SUMS and writes the notes. This script keeps
// what is Zeabur Identity's own.
//
//   bump    <version>                           after knope set Cargo.toml: Cargo.lock and ui/package.json
//   check   <version>                           the version is the crates' and ui/package.json's
//   build   <version> <os> <arch> <dist>        build the CLI archive and image into <dist>, smoke them on k3s
//   publish <version> <artifacts> <published>   push and sign the image by digest, attest its SBOMs
//   assets  <version> <artifacts> <assets>      copy the archives, SBOMs and digests.txt into <assets>
//   verify  <version> <os> <arch> <downloaded>  check the draft's image and SBOMs, smoke the archive and image
//
// <version> is vX.Y.Z or vX.Y.Z-<pre-release>. <artifacts> holds the workflow's earlier artifacts:
// candidate-linux-<arch>/ from build and published/ from publish. Linux only; build and verify are
// native (amd64 on x86_64, arm64 on aarch64), and Docker 28 or later. Release binaries are always
// compiled, never taken from a compiler cache.
//
// To run verify from a checkout of the tag, with the draft's files in <downloaded>:
//   nix develop --command bun install --frozen-lockfile
//   RELEASE_SOURCE_REF=refs/tags/<version> bun scripts/release.ts verify <version> linux <arch> <downloaded>
import {
  Failure,
  readDigests,
  recorded,
  pushImage,
  verifyImage,
} from "@zeabur-oss/release";
import { $ } from "bun";
import { rmSync } from "node:fs";
import { cp, mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const root = resolve(import.meta.dir, "..");
const scripts = join(root, "scripts");
const archs = ["amd64", "arm64"];
const oidcIssuer = "https://token.actions.githubusercontent.com";
const semver =
  /^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$/;

function fail(message: string): never {
  console.error(message);
  process.exit(1);
}

// A directory of this run's own, removed when it ends, with an empty registry login.
async function scratch(): Promise<{
  dir: string;
  env: Record<string, string>;
}> {
  const dir = await mkdtemp(join(tmpdir(), "release-"));
  process.on("exit", () => rmSync(dir, { recursive: true, force: true }));
  const docker = join(dir, "docker");
  await mkdir(docker);
  return { dir, env: { DOCKER_CONFIG: docker } };
}

function native(os: string, arch: string) {
  if (os !== "linux") fail(`there is no ${os} release; only linux`);
  const machine = process.arch === "x64" ? "amd64" : process.arch;
  if (process.platform !== "linux" || !archs.includes(arch) || arch !== machine)
    fail(`${arch} must be built and checked on a native ${arch} Linux machine`);
}

const names = (version: string, arch: string) => ({
  archive: `zeabur-identityctl-${version}-linux-${arch}.tar.gz`,
  cliSbom: `zeabur-identityctl-${version}-linux-${arch}.cdx.json`,
  imageSbom: `zeabur-identity-${version}-linux-${arch}.cdx.json`,
});

// knope (knope.toml) has set [workspace.package] in Cargo.toml; the workspace's crates in
// Cargo.lock and ui/package.json follow.
async function bump(version: string) {
  const plain = version.slice(1);
  const metadata =
    await $`cargo metadata --manifest-path ${join(root, "Cargo.toml")} --no-deps --format-version 1`.json();
  const lockFile = join(root, "Cargo.lock");
  let lock = await Bun.file(lockFile).text();
  for (const { name } of metadata.packages as { name: string }[]) {
    const entry = new RegExp(`(\nname = "${name}"\nversion = )"[^"]*"`);
    if (!entry.test(lock)) fail(`Cargo.lock has no package ${name}`);
    lock = lock.replace(entry, `$1"${plain}"`);
  }
  await Bun.write(lockFile, lock);
  const uiFile = join(root, "ui/package.json");
  const ui = (await Bun.file(uiFile).text()).replace(
    /^(\s*"version": )"[^"]*"/m,
    `$1"${plain}"`,
  );
  await Bun.write(uiFile, ui);
}

async function check(version: string) {
  const plain = version.slice(1);
  const metadata =
    await $`cargo metadata --manifest-path ${join(root, "Cargo.toml")} --locked --no-deps --format-version 1`.json();
  const problems = metadata.packages
    .filter((p: { version: string }) => p.version !== plain)
    .map((p: { name: string; version: string }) => `${p.name} ${p.version}`);
  const ui = await Bun.file(join(root, "ui/package.json")).json();
  if (ui.version !== plain) problems.push(`ui/package.json ${ui.version}`);
  if (problems.length)
    fail(
      `not at ${plain}, the version of the tag ${version}:\n${problems.join("\n")}`,
    );
}

// Static musl binaries, the CLI archive and both SBOMs, and the image (as image.tar) in <dist>;
// then release-smoke.sh runs that archive and image on a disposable k3s cluster.
async function build(version: string, os: string, arch: string, dist: string) {
  native(os, arch);
  const ca =
    process.env.ZEABUR_IDENTITY_CA_BUNDLE ?? fail("run inside nix develop");
  await mkdir(dist, { recursive: true });
  const { dir: work } = await scratch();
  // mkShell sets SOURCE_DATE_EPOCH to 1980; the commit's time replaces it.
  const epoch = (
    await $`git -C ${root} show -s --format=%ct HEAD`.text()
  ).trim();
  process.env.SOURCE_DATE_EPOCH = epoch;
  delete process.env.RUSTC_WRAPPER;
  const target = `${arch === "amd64" ? "x86_64" : "aarch64"}-unknown-linux-musl`;
  const targetDir = resolve(
    process.env.CARGO_TARGET_DIR ?? join(root, "target"),
  );
  const release = join(targetDir, target, "release");
  const { archive, cliSbom, imageSbom } = names(version, arch);

  // Embedded cargo-auditable metadata lets Syft inventory dependencies in the shipped binaries.
  await $`cargo auditable build --release --locked --target ${target} --target-dir ${targetDir} --manifest-path ${join(root, "Cargo.toml")} -p zeabur-identityctl -p zeabur-identity`;
  for (const binary of ["zeabur-identityctl", "zeabur-identity"]) {
    const elf =
      await $`readelf --program-headers --dynamic ${join(release, binary)}`.text();
    if (elf.includes("INTERP") || elf.includes("(NEEDED)"))
      fail(`${binary} is not a fully static executable`);
  }

  const cli = join(work, "cli");
  await mkdir(cli);
  await $`install -m 0755 ${join(release, "zeabur-identityctl")} ${join(cli, "zeabur-identityctl")}`;
  const archivePath = join(dist, archive);
  await $`tar --format=ustar --sort=name --mtime=${"@" + epoch} --owner=0 --group=0 --numeric-owner --mode=0755 -C ${cli} -cf - zeabur-identityctl | gzip -n -9 > ${archivePath}`;

  // Scan the exact file packaged above, not Cargo manifests or a fresh build.
  const syft = { ...process.env, SYFT_CHECK_FOR_APP_UPDATE: "false" };
  await $`syft scan ${"file:" + join(cli, "zeabur-identityctl")} --output ${"cyclonedx-json=" + join(dist, cliSbom)}`.env(
    syft,
  );
  await cargoComponents(join(dist, cliSbom));

  // The same staged tree as build-image.sh: directories 0755, so the non-root user can traverse them.
  const stage = join(work, "image");
  const certs = join(stage, "etc/ssl/certs");
  await mkdir(certs, { recursive: true });
  await $`install -m 0555 ${join(release, "zeabur-identity")} ${join(stage, "zeabur-identity")}`;
  await $`install -m 0444 ${ca} ${join(certs, "ca-certificates.crt")}`;
  await $`chmod 0755 ${join(stage, "etc")} ${join(stage, "etc/ssl")} ${certs}`;
  await $`touch -d ${"@" + epoch} ${join(stage, "zeabur-identity")} ${join(stage, "etc")} ${join(stage, "etc/ssl")} ${certs} ${join(certs, "ca-certificates.crt")}`;
  const image = `zeabur-identity:release-${arch}`;
  await $`docker build --platform ${"linux/" + arch} --network none --build-arg ${"SOURCE_DATE_EPOCH=" + epoch} --file ${join(root, "Containerfile")} --tag ${image} ${stage}`;
  const tar = join(dist, "image.tar");
  await $`docker image save --output ${tar} ${image}`;

  // A scratch image has no distro package database to own the CA bundle. Capture all file digests
  // in Syft, then record that bundle as a CycloneDX file component.
  const scan = {
    ...syft,
    SYFT_FILE_METADATA_SELECTION: "all",
    SYFT_FILE_METADATA_DIGESTS: "sha256",
  };
  const syftJson = join(work, "image.syft.json");
  const cdx = join(work, "image.cdx.json");
  await $`syft scan ${"docker-archive:" + tar} --output ${"syft-json=" + syftJson} --output ${"cyclonedx-json=" + cdx}`.env(
    scan,
  );
  const bundle = "/etc/ssl/certs/ca-certificates.crt";
  const shas = new Set<string>(
    (await Bun.file(syftJson).json()).files
      .filter((f: { location: { path: string } }) => f.location.path === bundle)
      .flatMap((f: { digests: { algorithm: string; value: string }[] }) =>
        f.digests.filter((d) => d.algorithm === "sha256").map((d) => d.value),
      ),
  );
  if (shas.size !== 1)
    fail("missing or ambiguous CA bundle digest in the image");
  const sbom = await Bun.file(cdx).json();
  sbom.components = [
    ...(sbom.components ?? []),
    {
      type: "file",
      "bom-ref": `file:${bundle}`,
      name: bundle,
      hashes: [{ alg: "SHA-256", content: [...shas][0] }],
      properties: [{ name: "zeabur-identity:nix-source", value: ca }],
    },
  ];
  await Bun.write(join(dist, imageSbom), JSON.stringify(sbom, null, 2) + "\n");
  await cargoComponents(join(dist, imageSbom));
  console.log(`Built ${archivePath} and ${image} (not published).`);

  await $`${join(scripts, "release-smoke.sh")} ${archivePath} ${image}`;
}

async function cargoComponents(file: string) {
  const sbom = await Bun.file(file).json();
  if (
    sbom.bomFormat !== "CycloneDX" ||
    !(sbom.components ?? []).some((c: { purl?: string }) =>
      (c.purl ?? "").startsWith("pkg:cargo/"),
    )
  )
    fail(`${file} is not a CycloneDX document with Cargo components`);
}

// Pushes each platform's smoked image by digest, then the multi-platform index as the tag
// <version> without its v, and signs each. Then attests the CycloneDX SBOMs; the shared workflow
// adds build provenance for every subject in <published>/subjects.json. Never compiles.
async function publish(version: string, artifacts: string, out: string) {
  const plain = version.slice(1);
  const repository =
    process.env.GITHUB_REPOSITORY ?? fail("GITHUB_REPOSITORY is not set");
  const actor = process.env.GITHUB_ACTOR ?? fail("GITHUB_ACTOR is not set");
  const token = process.env.GH_TOKEN ?? fail("GH_TOKEN is not set");
  const { env } = await scratch();
  $.env({ ...process.env, ...env });
  await mkdir(out, { recursive: true });

  if (
    (await $`gh release view ${version} --repo ${repository}`.nothrow().quiet())
      .exitCode === 0
  )
    fail(`release ${version} already exists; inspect it before trying again`);
  const archives: Record<string, string> = {};
  for (const arch of archs) {
    const dir = join(artifacts, `candidate-linux-${arch}`);
    for (const file of ["image.tar", names(version, arch).imageSbom])
      if (!(await Bun.file(join(dir, file)).exists()))
        fail(`${dir} has no ${file}`);
    archives[`linux/${arch}`] = join(dir, "image.tar");
  }
  await $`crane auth login ghcr.io --username ${actor} --password-stdin < ${new Response(token)}`;
  await rm(join(out, "digests.txt"), { force: true });
  await rm(join(out, "subjects.json"), { force: true });
  const index = await pushImage(
    out,
    "",
    `ghcr.io/${repository.toLowerCase()}:${plain}`,
    archives,
  );

  // Each platform image carries its own SBOM; the index carries both.
  const entries = await readDigests(join(out, "digests.txt"));
  for (const arch of archs) {
    const sbom = join(
      artifacts,
      `candidate-linux-${arch}`,
      names(version, arch).imageSbom,
    );
    for (const ref of [recorded(entries, `linux/${arch}`), index])
      await $`cosign attest --yes --type cyclonedx --predicate ${sbom} ${ref}`;
  }
  await $`cat ${join(out, "subjects.json")} ${join(out, "digests.txt")}`;
}

async function assets(version: string, artifacts: string, dir: string) {
  await mkdir(dir, { recursive: true });
  for (const arch of archs) {
    const { archive, cliSbom, imageSbom } = names(version, arch);
    for (const file of [archive, cliSbom, imageSbom])
      await cp(
        join(artifacts, `candidate-linux-${arch}`, file),
        join(dir, file),
      );
  }
  await cp(
    join(artifacts, "published", "digests.txt"),
    join(dir, "digests.txt"),
  );
}

// What a user does with the draft's files, after the workflow has verified SHA256SUMS and each
// asset's provenance: the image is the signed index of the recorded platform images, its SBOM
// attestation is this platform's, and the archive and image run on a disposable k3s.
async function verify(
  version: string,
  os: string,
  arch: string,
  downloaded: string,
) {
  native(os, arch);
  console.log(`verifying ${version} on ${os}/${arch}`);
  // A fresh, empty registry configuration: a publisher's login must not hide a private package.
  const { dir: work, env } = await scratch();
  $.env({ ...process.env, ...env });
  const digests = join(downloaded, "digests.txt");
  const index = String(
    await verifyImage(
      digests,
      "",
      archs.map((a) => `linux/${a}`),
    ),
  );

  const identity =
    process.env.RELEASE_CERT_IDENTITY_REGEXP ??
    "^https://github\\.com/zeabur-oss/\\.github/\\.github/workflows/release\\.yml@";
  const repository =
    process.env.RELEASE_SOURCE_REPOSITORY ?? "zeabur-oss/identity";
  const ref = process.env.RELEASE_SOURCE_REF ?? `refs/tags/${version}`;
  // --type checks the in-toto predicate type, and claim checking binds its subject to the image.
  const attestations =
    await $`cosign verify-attestation --certificate-identity-regexp ${identity} --certificate-oidc-issuer ${oidcIssuer} --certificate-github-workflow-repository ${repository} --certificate-github-workflow-ref ${ref} --type cyclonedx ${index}`.text();
  const statements = attestations
    .split("\n")
    .filter(Boolean)
    .map((line) =>
      JSON.parse(Buffer.from(JSON.parse(line).payload, "base64").toString()),
    );
  const { imageSbom, archive } = names(version, arch);
  const expected = await Bun.file(join(downloaded, imageSbom)).json();
  const valid = (s: Record<string, any>) =>
    s.predicateType === "https://cyclonedx.org/bom" &&
    s.predicate.bomFormat === "CycloneDX" &&
    /^[0-9]+[.][0-9]+$/.test(s.predicate.specVersion) &&
    Number.isInteger(s.predicate.version) &&
    s.predicate.version >= 1 &&
    Array.isArray(s.predicate.components);
  // An actual CycloneDX document inside the verified envelope, this platform's, not only its label.
  if (
    !statements.length ||
    !statements.every(valid) ||
    !statements.some(
      (s) => JSON.stringify(s.predicate) === JSON.stringify(expected),
    )
  )
    fail(`${index} has no valid CycloneDX attestation of ${imageSbom}`);

  await $`docker pull --platform ${"linux/" + arch} ${index}`;
  await $`${join(scripts, "release-smoke.sh")} ${join(downloaded, archive)} ${index}`;
  console.log(`release ${version} verified (${work})`);
}

const [stage, version, ...rest] = process.argv.slice(2);
const usage =
  "usage: bun scripts/release.ts bump|check|build|publish|assets|verify <version> ... (see the script's header)";
if (!version || !semver.test(version))
  fail(`${usage}\n<version> is vX.Y.Z or vX.Y.Z-<pre-release>, without +`);
const args = rest.map((a, i) =>
  (stage === "build" || stage === "verify") && i < 2 ? a : resolve(a),
);
try {
  if (stage === "bump" && args.length === 0) await bump(version);
  else if (stage === "check" && args.length === 0) await check(version);
  else if (stage === "build" && args.length === 3)
    await build(version, args[0], args[1], args[2]);
  else if (stage === "publish" && args.length === 2)
    await publish(version, args[0], args[1]);
  else if (stage === "assets" && args.length === 2)
    await assets(version, args[0], args[1]);
  else if (stage === "verify" && args.length === 3)
    await verify(version, args[0], args[1], args[2]);
  else fail(usage);
} catch (e) {
  if (e instanceof Failure) fail(e.message);
  // The command has printed its own error.
  if (e instanceof $.ShellError) process.exit(e.exitCode);
  throw e;
}
