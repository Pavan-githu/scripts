#!/bin/bash
# =============================================================================
# scripts/Build_image/register_blockchain.sh
#
# Standalone blockchain registration step — same transport method as
# blockchain_logger.cpp: uses eth_sendTransaction with an UNLOCKED account
# on the Hardhat node.  No eth_account / eth-hash Python libraries needed.
#
# How it works (mirrors blockchain_logger.cpp exactly):
#   1. Python builds the ABI-encoded calldata for writeFirmwareMetadata()
#      — uses pycryptodome for keccak256 (selector), rest is stdlib
#   2. curl POSTs eth_sendTransaction to the Hardhat node
#      — the node signs with the unlocked DEVICE_ADDR (no private key needed)
#   3. tx_hash is written back into firmware-metadata.json
#
# Usage:
#   bash scripts/Build_image/register_blockchain.sh [PROJECT_DIR]
#
# Required in .env.secrets:
#   RPC_URL        Hardhat JSON-RPC endpoint  e.g. http://192.168.1.5:8545
#   CONTRACT_ADDR  Deployed FirmwareMetadataStore address  e.g. 0xABC...
#   DEVICE_ADDR    Hardhat unlocked account address        e.g. 0xf39F...
#                  (Hardhat account #0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${1:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"

OUTPUT_DIR="$SCRIPT_DIR"
METADATA_JSON="$OUTPUT_DIR/firmware-metadata.json"
ENV_SECRETS="$OUTPUT_DIR/.env.secrets"

# ─────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────────────────────
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
ok()   { echo "[$(date '+%H:%M:%S')] ✔  $*"; }
warn() { echo "[$(date '+%H:%M:%S')] ⚠  $*" >&2; }
err()  { echo "[$(date '+%H:%M:%S')] ✘  $*" >&2; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# Load .env.secrets
# ─────────────────────────────────────────────────────────────────────────────
if [ -f "$ENV_SECRETS" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_SECRETS"
    set +a
    log "Loaded secrets from $ENV_SECRETS"
else
    warn ".env.secrets not found at $ENV_SECRETS — using environment variables."
fi

# ─────────────────────────────────────────────────────────────────────────────
# Validate required variables and files
# ─────────────────────────────────────────────────────────────────────────────
[ -f "$METADATA_JSON" ] || err "firmware-metadata.json not found: $METADATA_JSON"
[ -n "${RPC_URL:-}"       ] || err "RPC_URL is not set.       Add it to $ENV_SECRETS"
[ -n "${CONTRACT_ADDR:-}" ] || err "CONTRACT_ADDR is not set. Add it to $ENV_SECRETS"
[ -n "${DEVICE_ADDR:-}"   ] || err "DEVICE_ADDR is not set.   Add it to $ENV_SECRETS
  This is the Hardhat unlocked account address (not the private key).
  Default Hardhat account #0: 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"

command -v curl >/dev/null 2>&1 || err "curl not found. Install with: apt-get install curl"

export RPC_URL CONTRACT_ADDR DEVICE_ADDR

# ─────────────────────────────────────────────────────────────────────────────
# Ensure pycryptodome is available (only dep needed — for keccak256 selector)
# ─────────────────────────────────────────────────────────────────────────────
log "Checking Python dependencies..."
if ! python3 -c "from Crypto.Hash import keccak" 2>/dev/null; then
    log "Installing pycryptodome (missing)..."
    python3 -m pip install --quiet pycryptodome \
        || err "Failed to install pycryptodome. Run: pip3 install pycryptodome"
fi
ok "pycryptodome OK"

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Blockchain Registration — FirmwareMetadataStore"
echo "  Method: eth_sendTransaction (unlocked account, like C++ logger)"
echo "============================================================"
log "  Metadata     : $METADATA_JSON"
log "  RPC endpoint : $RPC_URL"
log "  Contract     : $CONTRACT_ADDR"
log "  Device addr  : $DEVICE_ADDR"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — Build ABI-encoded calldata (Python stdlib + pycryptodome only)
# ─────────────────────────────────────────────────────────────────────────────
CALLDATA=$(METADATA_JSON_PATH="$METADATA_JSON" python3 - <<'PYEOF'
import json, os, sys

# ── keccak256 using pycryptodome (no eth_account needed) ────────────────────
from Crypto.Hash import keccak as _keccak
def keccak256(data: bytes) -> bytes:
    h = _keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()

meta_path     = os.environ["METADATA_JSON_PATH"]
CONTRACT_ADDR = os.environ["CONTRACT_ADDR"]

with open(meta_path) as f:
    meta = json.load(f)

# ── Validate required metadata fields ───────────────────────────────────────
required = ["firmware_hash", "firmware_version", "timestamp", "signer_identity",
            "download_url", "image_filename", "image_size_bytes",
            "final_image_filename", "final_image_size_bytes"]
missing = [k for k in required if meta.get(k) is None or meta.get(k) == ""]
if missing:
    print(f"ERROR: missing metadata fields: {missing}", file=sys.stderr)
    sys.exit(1)

# ── ABI encoding helpers (pure stdlib) ──────────────────────────────────────
def uint256_word(n: int) -> bytes:
    return n.to_bytes(32, 'big')

def encode_string(s: str) -> bytes:
    data = s.encode('utf-8')
    pad  = (32 - len(data) % 32) % 32
    return uint256_word(len(data)) + data + b'\x00' * pad

# ── Function selector: keccak256(signature)[:4] ─────────────────────────────
SIG      = "writeFirmwareMetadata(string,string,string,string,string,string,uint256,string,uint256)"
selector = keccak256(SIG.encode())[:4]

# ── Encode 9 parameters (7 strings + 2 uint256) ─────────────────────────────
# Layout: [selector 4B][head 9×32B][tail: dynamic string data]
# Param order: firmwareHash(0) firmwareVersion(1) timestamp(2)
#              signerIdentity(3) downloadUrl(4) imageFilename(5)
#              imageSizeBytes(6=uint256) finalImageFilename(7) finalImageSizeBytes(8=uint256)
strs = [
    meta['firmware_hash'], meta['firmware_version'], meta['timestamp'],
    meta['signer_identity'], meta['download_url'], meta['image_filename'],
    meta['final_image_filename']
]
encoded_strs = [encode_string(s) for s in strs]

head   = bytearray()
tail   = bytearray()
offset = 9 * 32   # head section = 9 × 32 bytes
si     = 0
for i in range(9):
    if i == 6:                           # imageSizeBytes  (uint256)
        head += uint256_word(meta['image_size_bytes'])
    elif i == 8:                         # finalImageSizeBytes (uint256)
        head += uint256_word(meta['final_image_size_bytes'])
    else:                                # string → offset pointer
        head += uint256_word(offset)
        tail += encoded_strs[si]
        offset += len(encoded_strs[si])
        si += 1

calldata = "0x" + (selector + bytes(head) + bytes(tail)).hex()

# ── Print fields being registered ───────────────────────────────────────────
print(f"##firmware_hash    : {meta['firmware_hash']}", file=sys.stderr)
print(f"##firmware_version : {meta['firmware_version']}", file=sys.stderr)
print(f"##timestamp        : {meta['timestamp']}", file=sys.stderr)
print(f"##download_url     : {meta['download_url']}", file=sys.stderr)
print(f"##calldata_len     : {len(calldata)} chars", file=sys.stderr)

# Output only the calldata hex (captured by bash $(...))
print(calldata)
PYEOF
)

echo ""
log "  ABI calldata built (${#CALLDATA} chars)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — Send transaction via curl (same as blockchain_logger.cpp)
#           eth_sendTransaction — node signs with unlocked DEVICE_ADDR
# ─────────────────────────────────────────────────────────────────────────────
log "  Sending eth_sendTransaction via curl..."

JSON_BODY=$(cat <<EOF
{
  "jsonrpc": "2.0",
  "method":  "eth_sendTransaction",
  "params": [{
    "from": "$DEVICE_ADDR",
    "to":   "$CONTRACT_ADDR",
    "gas":  "0x61A80",
    "data": "$CALLDATA"
  }],
  "id": 1
}
EOF
)

RESPONSE=$(curl -s -X POST "$RPC_URL" \
    -H "Content-Type: application/json" \
    -d "$JSON_BODY")

echo "  RPC response: $RESPONSE"

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — Extract tx_hash and write back to firmware-metadata.json
# ─────────────────────────────────────────────────────────────────────────────
TX_HASH=$(echo "$RESPONSE" | python3 -c "
import json, sys
resp = json.load(sys.stdin)
if 'error' in resp:
    print(f'ERROR: {resp[\"error\"]}', file=sys.stderr)
    sys.exit(1)
print(resp.get('result', ''))
")

[ -n "$TX_HASH" ] || err "Transaction failed — no tx_hash in response. Check RPC response above."

# Write tx_hash back into firmware-metadata.json
python3 -c "
import json
meta_path = '$METADATA_JSON'
with open(meta_path) as f:
    meta = json.load(f)
meta['tx_hash'] = '$TX_HASH'
with open(meta_path, 'w') as f:
    json.dump(meta, f, indent=2)
"

echo ""
ok "writeFirmwareMetadata registered on-chain"
ok "tx_hash  : $TX_HASH"
ok "Metadata : $METADATA_JSON"
echo ""
echo "============================================================"
echo "  Registration COMPLETE"
echo "============================================================"


