#!/usr/bin/env bash
# Install crityoink via cargo from git, or copy a release binary next to this script.
set -euo pipefail

REPO_URL="https://github.com/alex-powell/crityoink"
PREFIX="${PREFIX:-${HOME}/.local}"
BIN_DIR="${BIN_DIR:-${PREFIX}/bin}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<EOF
Install crityoink into ${BIN_DIR}.

Prerequisite: Rust and cargo (https://rustup.rs), unless a prebuilt
\`crityoink\` binary is sitting next to this script.

Equivalent cargo command:
  cargo install --git ${REPO_URL}

Environment:
  PREFIX   install prefix (default: ~/.local)
  BIN_DIR  binary directory (default: \$PREFIX/bin)
EOF
  exit 0
fi

mkdir -p "${BIN_DIR}"

if [[ -f "${SCRIPT_DIR}/crityoink" && -x "${SCRIPT_DIR}/crityoink" ]]; then
  cp "${SCRIPT_DIR}/crityoink" "${BIN_DIR}/crityoink"
  echo "Installed ${SCRIPT_DIR}/crityoink -> ${BIN_DIR}/crityoink"
  exit 0
fi

if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust/cargo is required to install from git." >&2
  echo "Install the toolchain from https://rustup.rs then re-run, or place a" >&2
  echo "prebuilt crityoink binary next to this script." >&2
  echo >&2
  echo "  cargo install --git ${REPO_URL}" >&2
  exit 1
fi

echo "Installing with: cargo install --git ${REPO_URL}"
cargo install --git "${REPO_URL}" --force
echo "crityoink installed (cargo bin directory, usually ~/.cargo/bin)."
