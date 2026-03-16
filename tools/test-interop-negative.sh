#!/bin/bash
set -euo pipefail

SCRIPTDIR="$(cd "$(dirname "$0")" && pwd -P)"
REPOROOT="$(cd "${SCRIPTDIR}/.." && pwd -P)"

PYTHON_BIN="${PYTHON_BIN:-${REPOROOT}/src/.venv/bin/python}"
GO_BIN="${GO_BIN:-go}"
GOCACHE_DIR="${GOCACHE_DIR:-/tmp/go-build-key-attestation}"
WORK_DIR="${WORK_DIR:-${REPOROOT}/go-work}"
TMPDIR_INTEROP="$(mktemp -d /tmp/pkix-interop-negative.XXXXXX)"
trap 'rm -rf "${TMPDIR_INTEROP}"' EXIT

SOURCE_EVIDENCE="${REPOROOT}/sampledata/evidence1.b64"
BAD_SIG_EVIDENCE="${TMPDIR_INTEROP}/evidence-bad-signature.b64"
BAD_CLAIM_EVIDENCE="${TMPDIR_INTEROP}/evidence-bad-claim.b64"

fail() {
	echo "ERROR: $*" >&2
	exit 1
}

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || fail "required command not found: $1"
}

echo "[1/4] Checking prerequisites"
require_cmd "${GO_BIN}"
[[ -x "${PYTHON_BIN}" ]] || fail "Python virtual environment not found at ${PYTHON_BIN}. Run 'make python-install' first."
mkdir -p "${GOCACHE_DIR}"
mkdir -p "${WORK_DIR}"

echo "[2/4] Generating fresh baseline evidence with Python"
(
	cd "${REPOROOT}"
	"${PYTHON_BIN}" src/generate_test_data.py >${WORK_DIR}/pkix-python-negative-interop.log
)
[[ -f "${SOURCE_EVIDENCE}" ]] || fail "baseline evidence not generated: ${SOURCE_EVIDENCE}"

echo "[3/4] Creating manipulated evidence variants"
PYTHONPATH="${REPOROOT}/src" "${PYTHON_BIN}" - "${SOURCE_EVIDENCE}" "${BAD_SIG_EVIDENCE}" "${BAD_CLAIM_EVIDENCE}" <<'PY'
import base64
import sys
from pathlib import Path

import pkix_evidence as mod

source_path = Path(sys.argv[1])
bad_sig_path = Path(sys.argv[2])
bad_claim_path = Path(sys.argv[3])

source_der = base64.b64decode(source_path.read_text())

ev_bad_sig = mod.decode_evidence(source_der)
sig_bytes = bytearray(bytes(ev_bad_sig["signatures"][0]["signatureValue"]))
sig_bytes[0] ^= 0x01
ev_bad_sig["signatures"][0]["signatureValue"] = bytes(sig_bytes)
bad_sig_path.write_text(base64.b64encode(mod.encode_evidence(ev_bad_sig)).decode("ascii"))

ev_bad_claim = mod.decode_evidence(source_der)
key_entity_oid = mod.mkoid("id-evidence-entity-key")
identifier_oid = mod.mkoid("id-evidence-claim-key-identifier")
for entity in ev_bad_claim["tbs"]["reportedEntities"]:
    if entity["entityType"] != key_entity_oid:
        continue
    for claim in entity["claims"]:
        if claim["claimType"] == identifier_oid:
            claim["value"] = mod.make_claim_value(b"bad-id")
            bad_claim_path.write_text(base64.b64encode(mod.encode_evidence(ev_bad_claim)).decode("ascii"))
            raise SystemExit(0)
raise SystemExit("failed to find key.identifier claim")
PY

echo "[4/4] Expecting Go to reject manipulated evidence"
if (
	cd "${REPOROOT}" &&
	GOCACHE="${GOCACHE_DIR}" "${GO_BIN}" run ./go-src/cmd/pkix-evidence verify -in "${BAD_SIG_EVIDENCE}" -format base64
) >${WORK_DIR}/pkix-go-negative-verify.log 2>&1; then
	fail "Go verify unexpectedly accepted evidence with a corrupted signature"
fi
grep -q "signature\\[0\\]:" ${WORK_DIR}/pkix-go-negative-verify.log || fail "Go verify failure log did not contain a signature result"
grep -qv "signature\\[0\\]: ok" ${WORK_DIR}/pkix-go-negative-verify.log || fail "Go verify reported success for corrupted signature"

if (
	cd "${REPOROOT}" &&
	GOCACHE="${GOCACHE_DIR}" "${GO_BIN}" run ./go-src/cmd/pkix-evidence validate -in "${BAD_CLAIM_EVIDENCE}" -format base64
) >${WORK_DIR}/pkix-go-negative-validate.log 2>&1; then
	fail "Go validate unexpectedly accepted evidence with an invalid identifier claim type"
fi
grep -q "claim identifier must be utf8String" ${WORK_DIR}/pkix-go-negative-validate.log || fail "Go validate failure log did not contain the expected identifier type error"

echo "Negative interop test passed"
echo "Negative verify log: ${WORK_DIR}/pkix-go-negative-verify.log"
echo "Negative validate log: ${WORK_DIR}/pkix-go-negative-validate.log"
