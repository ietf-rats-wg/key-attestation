#!/bin/bash
set -euo pipefail

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOROOT="$(cd "${SCRIPTDIR}/.." && pwd -P)"

PYTHON_BIN="${PYTHON_BIN:-${REPOROOT}/src/.venv/bin/python}"
GO_BIN="${GO_BIN:-go}"
OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
GOCACHE_DIR="${GOCACHE_DIR:-/tmp/go-build-key-attestation}"
WORK_DIR="${WORK_DIR:-${REPOROOT}/go-cache}"

EVIDENCE_FILE="${REPOROOT}/sampledata/evidence1.b64"
AK_CERT_FILE="${REPOROOT}/sampledata/ak.crt"
INT_CERT_FILE="${REPOROOT}/sampledata/int.crt"
CA_CERT_FILE="${REPOROOT}/sampledata/ca.crt"

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

require_file() {
	local file="$1"
	[[ -f "${file}" ]] || fail "missing file: ${file}"
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

echo "[1/5] Checking prerequisites"
require_cmd "${GO_BIN}"
require_cmd "${OPENSSL_BIN}"
[[ -x "${PYTHON_BIN}" ]] || fail "Python virtual environment not found at ${PYTHON_BIN}. Run 'make python-install' first."

mkdir -p "${GOCACHE_DIR}"
mkdir -p "${WORK_DIR}"

echo "[2/5] Generating fresh sample evidence with Python"
(
	cd "${REPOROOT}"
	"${PYTHON_BIN}" src/generate_test_data.py >${WORK_DIR}/pkix-python-interop.log
)

require_file "${EVIDENCE_FILE}"
require_file "${AK_CERT_FILE}"
require_file "${INT_CERT_FILE}"
require_file "${CA_CERT_FILE}"

echo "[3/5] Verifying Python-generated certificate chain"
(
	cd "${REPOROOT}/sampledata"
	"${OPENSSL_BIN}" verify -CAfile "./ca.crt" -untrusted "./int.crt" "./ak.crt"
)

echo "[4/5] Running Go decode/validate/verify against Python output"
(
	cd "${REPOROOT}"
	GOCACHE="${GOCACHE_DIR}" "${GO_BIN}" run ./go-src/cmd/pkix-evidence decode -in "${EVIDENCE_FILE}" -format base64 >${WORK_DIR}/pkix-go-decode.json
)

VALIDATE_OUTPUT="$(
	cd "${REPOROOT}" &&
	GOCACHE="${GOCACHE_DIR}" "${GO_BIN}" run ./go-src/cmd/pkix-evidence validate -in "${EVIDENCE_FILE}" -format base64
)"
[[ "${VALIDATE_OUTPUT}" == "ok" ]] || fail "Go validate failed: ${VALIDATE_OUTPUT}"

VERIFY_OUTPUT="$(
	cd "${REPOROOT}" &&
	GOCACHE="${GOCACHE_DIR}" "${GO_BIN}" run ./go-src/cmd/pkix-evidence verify -in "${EVIDENCE_FILE}" -format base64
)"
grep -q "signature\\[0\\]: ok" <<<"${VERIFY_OUTPUT}" || fail "Go verify failed: ${VERIFY_OUTPUT}"

CHAIN_OUTPUT="$(
	cd "${REPOROOT}" &&
	GOCACHE="${GOCACHE_DIR}" "${GO_BIN}" run ./go-src/cmd/pkix-evidence verify -in "${EVIDENCE_FILE}" -format base64 -verify-chain -ca "${CA_CERT_FILE}"
)"
grep -q "signature\\[0\\]: ok" <<<"${CHAIN_OUTPUT}" || fail "Go chain verification failed: ${CHAIN_OUTPUT}"

echo "[5/5] Interop test passed"
echo "Python log: ${WORK_DIR}/pkix-python-interop.log"
echo "Go decode output: ${WORK_DIR}/pkix-go-decode.json"
