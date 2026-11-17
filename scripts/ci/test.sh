#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/../.."
source scripts/lib.sh

cargo nextest run --workspace --all-features --locked --no-tests=warn
# nextest does not run doctests; the compile_fail ones prove type-level rules.
cargo test --doc --workspace --all-features --locked
