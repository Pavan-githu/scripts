#!/bin/bash
# =============================================================================
# scripts/Build_image/register_blockchain.sh
#
# Standalone blockchain registration step.
# Reads firmware-metadata.json and calls writeFirmwareMetadata() on the
# deployed IoTFirmwareRegistry / FirmwareMetadataStore contract.
#
# Usage:
#   bash scripts/Build_image/register_blockchain.sh [PROJECT_DIR]
#
#   PROJECT_DIR defaults to the workspace root (two levels up from this script).
#
# Required (set in .env.secrets or as environment variables):
#   RPC_URL        Ethereum JSON-RPC endpoint  e.g. http://192.168.1.5:8545
#   CONTRACT_ADDR  Deployed contract address   e.g. 0xABC...
#   SIGNER_KEY     Ethereum private key (hex)  e.g. 0xDEF...
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
[ -n "${SIGNER_KEY:-}"    ] || err "SIGNER_KEY is not set.    Add it to $ENV_SECRETS"

export RPC_URL CONTRACT_ADDR SIGNER_KEY

# ─────────────────────────────────────────────────────────────────────────────
# Show what we are about to register
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Blockchain Registration — FirmwareMetadataStore"
echo "============================================================"
log "  Metadata     : $METADATA_JSON"
log "  RPC endpoint : $RPC_URL"
log "  Contract     : $CONTRACT_ADDR"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Register on-chain
# ─────────────────────────────────────────────────────────────────────────────
METADATA_JSON_PATH="$METADATA_JSON" python3 - <<'PYEOF'
import json, os, sys, requests
from eth_account import Account
from eth_hash.auto import keccak

meta_path     = os.environ["METADATA_JSON_PATH"]
RPC_URL       = os.environ["RPC_URL"]
CONTRACT_ADDR = os.environ["CONTRACT_ADDR"]
SIGNER_KEY    = os.environ["SIGNER_KEY"]

with open(meta_path) as f:
    meta = json.load(f)

# Validate required metadata fields are present
required = ["firmware_hash", "firmware_version", "timestamp", "signer_identity",
            "download_url", "image_filename", "image_size_bytes",
            "final_image_filename", "final_image_size_bytes"]
missing = [k for k in required if not meta.get(k) and meta.get(k) != 0]
if missing:
    print(f"  ERROR: missing fields in metadata: {missing}", file=sys.stderr)
    sys.exit(1)

def uint256_word(n):
    return n.to_bytes(32, 'big')

def encode_string(s):
    data = s.encode('utf-8')
    pad  = (32 - len(data) % 32) % 32
    return uint256_word(len(data)) + data + b'\x00' * pad

def build_calldata(m):
    sig      = ("writeFirmwareMetadata("
                "string,string,string,string,string,string,"
                "uint256,string,uint256)")
    selector = keccak(sig.encode())[:4]
    strs = [
        m['firmware_hash'], m['firmware_version'], m['timestamp'],
        m['signer_identity'], m['download_url'], m['image_filename'],
        m['final_image_filename']
    ]
    encoded = [encode_string(s) for s in strs]
    head   = bytearray()
    tail   = bytearray()
    offset = 9 * 32
    si     = 0
    for i in range(9):
        if i == 6:
            head += uint256_word(m['image_size_bytes'])
        elif i == 8:
            head += uint256_word(m['final_image_size_bytes'])
        else:
            head += uint256_word(offset)
            tail += encoded[si]
            offset += len(encoded[si])
            si += 1
    return selector + bytes(head) + bytes(tail)

def rpc(method, params):
    r = requests.post(RPC_URL,
        json={"jsonrpc": "2.0", "method": method, "params": params, "id": 1},
        timeout=15)
    r.raise_for_status()
    res = r.json()
    if 'error' in res:
        raise RuntimeError(res['error'])
    return res['result']

print(f"  firmware_hash    : {meta['firmware_hash']}")
print(f"  firmware_version : {meta['firmware_version']}")
print(f"  timestamp        : {meta['timestamp']}")
print(f"  download_url     : {meta['download_url']}")
print()

calldata  = build_calldata(meta)
acct      = Account.from_key(SIGNER_KEY)
nonce     = int(rpc("eth_getTransactionCount", [acct.address, "latest"]), 16)
gas_price = int(rpc("eth_gasPrice", []), 16)
chain_id  = int(rpc("eth_chainId",  []), 16)

print(f"  Signer address : {acct.address}")
print(f"  Chain ID       : {chain_id}")
print(f"  Nonce          : {nonce}")
print()

tx = {
    "to":       CONTRACT_ADDR,
    "value":    0,
    "gas":      400_000,
    "gasPrice": gas_price,
    "nonce":    nonce,
    "data":     "0x" + calldata.hex(),
    "chainId":  chain_id,
}
signed  = acct.sign_transaction(tx)
tx_hash = rpc("eth_sendRawTransaction", [signed.raw_transaction.hex()])
print(f"  tx_hash : {tx_hash}")

meta["tx_hash"] = tx_hash
with open(meta_path, "w") as f:
    json.dump(meta, f, indent=2)
PYEOF

if [ $? -eq 0 ]; then
    BC_TX=$(python3 -c "
import json
with open('$METADATA_JSON') as f:
    m = json.load(f)
print(m.get('tx_hash', 'n/a'))
")
    echo ""
    ok "writeFirmwareMetadata registered on-chain"
    ok "tx_hash  : $BC_TX"
    ok "Metadata : $METADATA_JSON"
else
    err "Blockchain registration failed."
fi

echo ""
echo "============================================================"
echo "  Registration COMPLETE"
echo "============================================================"
