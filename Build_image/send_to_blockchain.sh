#!/bin/bash
# =============================================================================
# Build_image/send_to_blockchain.sh
#
# Registers built firmware metadata on-chain by calling:
#   writeFirmwareMetadata(firmwareHash, firmwareVersion, timestamp,
#                         signerIdentity, downloadUrl, imageFilename,
#                         imageSizeBytes, finalImageFilename, finalImageSizeBytes)
#
# Signs the transaction locally with SIGNER_KEY (eth_sendRawTransaction).
# No unlocked node account required.
#
# Usage:
#   bash scripts/Build_image/send_to_blockchain.sh [PROJECT_DIR]
#
# Required env vars (set via .env.secrets):
#   RPC_URL        Ethereum JSON-RPC  e.g. http://192.168.1.5:8545
#   CONTRACT_ADDR  FirmwareMetadataStore contract address (0x...)
#   SIGNER_KEY     Ethereum private key of the signing account (0x...)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${1:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"

METADATA_JSON="$SCRIPT_DIR/firmware-metadata.json"

# ─────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────────────────────
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
ok()   { echo "[$(date '+%H:%M:%S')] ✔  $*"; }
warn() { echo "[$(date '+%H:%M:%S')] ⚠  $*" >&2; }
err()  { echo "[$(date '+%H:%M:%S')] ✘  $*" >&2; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# Load secrets — repo root first, then script-local override
# ─────────────────────────────────────────────────────────────────────────────
for _secrets in "$PROJECT_DIR/.env.secrets" "$SCRIPT_DIR/.env.secrets"; do
    if [ -f "$_secrets" ]; then
        set -a
        # shellcheck disable=SC1090
        source "$_secrets"
        set +a
        log "Loaded secrets from $_secrets"
    fi
done

# ─────────────────────────────────────────────────────────────────────────────
# Validate prerequisites
# ─────────────────────────────────────────────────────────────────────────────
[ -f "$METADATA_JSON" ]      || err "firmware-metadata.json not found: $METADATA_JSON"
[ -n "${RPC_URL:-}"       ]  || err "RPC_URL is not set in .env.secrets"
[ -n "${CONTRACT_ADDR:-}" ]  || err "CONTRACT_ADDR is not set in .env.secrets"
[ -n "${SIGNER_KEY:-}"    ]  || err "SIGNER_KEY is not set in .env.secrets"

# Install required Python packages if missing
_missing_pkgs=""
python3 -c "from eth_account import Account" 2>/dev/null || _missing_pkgs="$_missing_pkgs eth-account eth-hash[pycryptodome]"
python3 -c "import requests"                 2>/dev/null || _missing_pkgs="$_missing_pkgs requests"

if [ -n "$_missing_pkgs" ]; then
    log "Installing missing Python packages:$_missing_pkgs"
    python3 -m pip install --quiet $_missing_pkgs \
        || python3 -m pip install --quiet --break-system-packages $_missing_pkgs \
        || err "Failed to install:$_missing_pkgs — activate a venv first: source ~/.venvs/web3/bin/activate"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Firmware Blockchain Registration"
echo "============================================================"
log "  Metadata  : $METADATA_JSON"
log "  RPC       : $RPC_URL"
log "  Contract  : $CONTRACT_ADDR"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Register on-chain via Python (eth_account + requests)
# ─────────────────────────────────────────────────────────────────────────────
TX_HASH=$(
    METADATA_JSON_PATH="$METADATA_JSON" \
    RPC_URL="$RPC_URL" \
    CONTRACT_ADDR="$CONTRACT_ADDR" \
    SIGNER_KEY="$SIGNER_KEY" \
    python3 - <<'PYEOF'
import json, os, sys, requests
from eth_account import Account
from eth_hash.auto import keccak

meta_path     = os.environ["METADATA_JSON_PATH"]
rpc_url       = os.environ["RPC_URL"]
contract_addr = os.environ["CONTRACT_ADDR"]
signer_key    = os.environ["SIGNER_KEY"]

with open(meta_path) as f:
    meta = json.load(f)

# ── Validate required metadata fields ────────────────────────────────────────
required = [
    "firmware_hash", "firmware_version", "timestamp", "signer_identity",
    "download_url", "image_filename", "image_size_bytes",
    "final_image_filename", "final_image_size_bytes",
]
missing = [k for k in required if not meta.get(k) and meta.get(k) != 0]
if missing:
    print(f"ERROR: missing metadata fields: {missing}", file=sys.stderr)
    sys.exit(1)

# ── ABI encoding helpers ──────────────────────────────────────────────────────
def uint256_word(n: int) -> bytes:
    return n.to_bytes(32, "big")

def encode_string(s: str) -> bytes:
    data = s.encode("utf-8")
    pad  = (32 - len(data) % 32) % 32
    return uint256_word(len(data)) + data + b"\x00" * pad

# ── Function selector (14-param signature matching blockchain_logger.cpp) ────
SIG      = ("writeFirmwareMetadata("
            "string,string,string,string,string,string,"
            "uint256,string,uint256,uint8,"
            "string,string,string,string)")
selector = keccak(SIG.encode("utf-8"))[:4]

# ── 14 params matching blockchain_logger.cpp ABI layout ──────────────────────
# [0]  firmwareHash        string
# [1]  firmwareVersion     string
# [2]  timestamp           string
# [3]  signerIdentity      string
# [4]  downloadUrl         string
# [5]  imageFilename       string
# [6]  imageSizeBytes      uint256  (inline)
# [7]  finalImageFilename  string
# [8]  finalImageSizeBytes uint256  (inline)
# [9]  approvalStage       uint8    (inline, default 0 = PENDING_OEM)
# [10] approvedByOem       string
# [11] oemApprovedAt       string
# [12] approvedByFleet     string
# [13] fleetApprovedAt     string
params = [
    ("string",  meta["firmware_hash"]),
    ("string",  meta["firmware_version"]),
    ("string",  meta["timestamp"]),
    ("string",  meta["signer_identity"]),
    ("string",  meta["download_url"]),
    ("string",  meta["image_filename"]),
    ("uint256", meta["image_size_bytes"]),
    ("string",  meta["final_image_filename"]),
    ("uint256", meta["final_image_size_bytes"]),
    ("uint8",   meta.get("approval_stage", 0)),
    ("string",  meta.get("approved_by_oem",   "")),
    ("string",  meta.get("oem_approved_at",    "")),
    ("string",  meta.get("approved_by_fleet",  "")),
    ("string",  meta.get("fleet_approved_at",  "")),
]

head   = bytearray()
tail   = bytearray()
offset = len(params) * 32   # head section = 14 × 32 bytes

for ptype, pval in params:
    if ptype == "string":
        head += uint256_word(offset)
        enc   = encode_string(str(pval))
        tail += enc
        offset += len(enc)
    else:   # uint256 / uint8 — inline
        head += uint256_word(int(pval))

calldata = "0x" + (selector + bytes(head) + bytes(tail)).hex()

# ── JSON-RPC helpers ──────────────────────────────────────────────────────────
def rpc(method, params):
    r = requests.post(rpc_url,
                      json={"jsonrpc": "2.0", "method": method,
                            "params": params, "id": 1},
                      timeout=15)
    r.raise_for_status()
    resp = r.json()
    if "error" in resp:
        raise RuntimeError(f"RPC error: {resp['error']}")
    return resp["result"]

# ── Build and sign transaction ────────────────────────────────────────────────
acct      = Account.from_key(signer_key)
nonce     = int(rpc("eth_getTransactionCount", [acct.address, "latest"]), 16)
gas_price = int(rpc("eth_gasPrice", []), 16)
chain_id  = int(rpc("eth_chainId",  []), 16)

tx = {
    "to":       contract_addr,
    "value":    0,
    "gas":      1_200_000,
    "gasPrice": gas_price,
    "nonce":    nonce,
    "data":     calldata,
    "chainId":  chain_id,
}

signed   = acct.sign_transaction(tx)
tx_hash  = rpc("eth_sendRawTransaction", [signed.raw_transaction.hex()])

# ── Print diagnostics to stderr (not captured by $(...)) ─────────────────────
print(f"  signer         : {acct.address}", file=sys.stderr)
print(f"  chain_id       : {chain_id}", file=sys.stderr)
print(f"  nonce          : {nonce}", file=sys.stderr)
print(f"  gas            : {tx['gas']}", file=sys.stderr)
print(f"  approval_stage : {meta.get('approval_stage', 0)}", file=sys.stderr)
print(f"  calldata       : {len(calldata)} chars", file=sys.stderr)

# ── Write tx_hash back to metadata ───────────────────────────────────────────
meta["tx_hash"] = tx_hash
with open(meta_path, "w") as f:
    json.dump(meta, f, indent=2)

print(tx_hash)
PYEOF
)

# ─────────────────────────────────────────────────────────────────────────────
# Result
# ─────────────────────────────────────────────────────────────────────────────
[ -n "$TX_HASH" ] || err "No tx_hash returned — registration may have failed."

echo ""
ok "writeFirmwareMetadata registered on-chain"
ok "tx_hash  : $TX_HASH"
ok "Metadata : $METADATA_JSON  (tx_hash written)"
echo ""
echo "============================================================"
echo "  Blockchain Registration — COMPLETE"
echo "============================================================"
echo ""
echo "  To verify on Hardhat node:"
echo "    cast tx $TX_HASH --rpc-url $RPC_URL"
echo ""
