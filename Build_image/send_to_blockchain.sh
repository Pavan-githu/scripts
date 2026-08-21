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

# Install eth_account if missing (needed for local tx signing)
if ! python3 -c "from eth_account import Account" 2>/dev/null; then
    log "Installing eth-account..."
    python3 -m pip install --quiet eth-account eth-hash[pycryptodome] \
        || err "Failed to install eth-account. Run: pip3 install eth-account"
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

# ── Function selector ─────────────────────────────────────────────────────────
SIG      = "writeFirmwareMetadata(string,string,string,string,string,string,uint256,string,uint256)"
selector = keccak(SIG.encode("utf-8"))[:4]

# ── Encode 9 params: 7 strings + 2 uint256 ───────────────────────────────────
# index: 0=firmwareHash  1=firmwareVersion  2=timestamp  3=signerIdentity
#        4=downloadUrl  5=imageFilename  6=imageSizeBytes(uint256)
#        7=finalImageFilename  8=finalImageSizeBytes(uint256)
string_vals = [
    meta["firmware_hash"], meta["firmware_version"], meta["timestamp"],
    meta["signer_identity"], meta["download_url"],
    meta["image_filename"], meta["final_image_filename"],
]
encoded_strs = [encode_string(s) for s in string_vals]

head   = bytearray()
tail   = bytearray()
offset = 9 * 32   # 9 head slots × 32 bytes each
si     = 0
for i in range(9):
    if i == 6:      # imageSizeBytes (uint256)
        head += uint256_word(meta["image_size_bytes"])
    elif i == 8:    # finalImageSizeBytes (uint256)
        head += uint256_word(meta["final_image_size_bytes"])
    else:           # string — emit offset pointer, append data to tail
        head += uint256_word(offset)
        tail += encoded_strs[si]
        offset += len(encoded_strs[si])
        si += 1

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
    "gas":      400_000,
    "gasPrice": gas_price,
    "nonce":    nonce,
    "data":     calldata,
    "chainId":  chain_id,
}

signed   = acct.sign_transaction(tx)
tx_hash  = rpc("eth_sendRawTransaction", [signed.raw_transaction.hex()])

# ── Print diagnostics to stderr (not captured by $(...)) ─────────────────────
print(f"  signer   : {acct.address}", file=sys.stderr)
print(f"  chain_id : {chain_id}", file=sys.stderr)
print(f"  nonce    : {nonce}", file=sys.stderr)
print(f"  gas      : {tx['gas']}", file=sys.stderr)
print(f"  calldata : {len(calldata)} chars", file=sys.stderr)

# ── Write tx_hash back to metadata ───────────────────────────────────────────
meta["tx_hash"] = tx_hash
with open(meta_path, "w") as f:
    json.dump(meta, f, indent=2)

# stdout — captured by bash $(...) — only the hash
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
