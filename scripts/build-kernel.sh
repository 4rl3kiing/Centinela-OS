#!/usr/bin/env sh
set -eu

cd "$(dirname "$0")/.."

rustup target add x86_64-unknown-none
cargo fmt --all -- --check
cargo clippy --workspace --target x86_64-unknown-none -- -D warnings
cargo build --workspace --target x86_64-unknown-none

printf '\nKernel ELF: %s\n' "target/x86_64-unknown-none/debug/centinela-kernel"
