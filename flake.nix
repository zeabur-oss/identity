{
  description = "zeabur-identity development environment";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    # Rust toolchains. The locked revision sets the nightly (overlays.default).
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # The base shell of every zeabur-oss repository: Bun, the release tools and the shared linters.
    oss = {
      url = "github:zeabur-oss/.github";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, ... }@inputs:

    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
      forEachSupportedSystem =
        f:
        inputs.nixpkgs.lib.genAttrs supportedSystems (
          system:
          f {
            inherit system;
            pkgs = import inputs.nixpkgs {
              inherit system;
              overlays = [
                inputs.rust-overlay.overlays.default
                inputs.self.overlays.default
              ];
            };
          }
        );
    in
    {
      overlays.default = final: _: {
        # The newest nightly in the locked rust-overlay that has all these components and targets.
        rustToolchain = final.rust-bin.selectLatestNightlyWith (
          toolchain:
          toolchain.minimal.override {
            extensions = [
              "rustfmt"
              "clippy"
              "rust-src"
              "rust-analyzer"
            ];
            targets = [
              "x86_64-unknown-linux-musl"
              "aarch64-unknown-linux-musl"
            ];
          }
        );
      };

      devShells = forEachSupportedSystem (
        { pkgs, system }:
        {
          default = pkgs.mkShell {
            inputsFrom = [ inputs.oss.devShells.${system}.base ];
            packages = with pkgs; [
              rustToolchain

              # Quality and supply chain
              cargo-deny
              cargo-nextest
              cargo-auditable
              cargo-cyclonedx
              syft
              curl
              binutils

              # Sign-in page assets: bun installs the rest from ui/bun.lock.
              brotli
              python3 # .claude/skills/zeabur-identity-ui/contrast.py

              # Kubernetes integration tests
              kind
              k3d
              kubectl
            ];

            env = {
              # Required by rust-analyzer
              RUST_SRC_PATH = "${pkgs.rustToolchain}/lib/rustlib/src/rust/library";
              # Mozilla's CA bundle (MPL-2.0), copied into the image for outgoing TLS to identity
              # providers; pinned with nixpkgs.
              ZEABUR_IDENTITY_CA_BUNDLE = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
            }
            // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux (
              # Static musl builds of the host architecture: aws-lc-sys must be compiled against musl
              # headers, not glibc ones (else `__isoc23_strtol`, `__memcpy_chk`... are undefined).
              let
                muslCc = pkgs.pkgsStatic.stdenv.cc;
                bin = "${muslCc}/bin/${muslCc.targetPrefix}";
                triple = "${pkgs.stdenv.hostPlatform.parsed.cpu.name}_unknown_linux_musl";
              in
              {
                "CC_${triple}" = "${bin}cc";
                "AR_${triple}" = "${bin}ar";
                "CARGO_TARGET_${pkgs.lib.toUpper triple}_LINKER" = "${bin}cc";
              }
            );
          };
        }
      );

      formatter = forEachSupportedSystem ({ pkgs, ... }: pkgs.nixfmt);
    };
}
