#!/usr/bin/env bash
set -euo pipefail
REPOROOT="$(cd "$(dirname "$0")/.." && pwd -P)"
PYTHON_BIN="${PYTHON_BIN:-${REPOROOT}/src/.venv/bin/python}"
GO_BIN="${GO_BIN:-go}"
GOCACHE="${GOCACHE_DIR:-/tmp/go-build-key-attestation}"
export GOCACHE
TEST_DIR="$(mktemp -d /tmp/pkix-negative.XXXXXX)"
trap 'rm -rf "${TEST_DIR}"' EXIT
cd "${REPOROOT}"
"${GO_BIN}" build -o "${TEST_DIR}/pkix-evidence" ./go-src/cmd/pkix-evidence
export PKIX_GO_BIN="${TEST_DIR}/pkix-evidence"
export PYTHONPATH="${REPOROOT}/src"
"${PYTHON_BIN}" -m unittest -v test_interop.NegativeInteropTests
