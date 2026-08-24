#!/bin/bash
# =============================================================================
# Build_image/send_to_blockchain_from_fleet.sh
#
# Fleet approval step — reads current on-chain firmware state, validates that:
#   - approved_by_oem  is non-empty  (OEM has signed off)
#   - oem_approved_at  is non-empty
#   - approval_stage   == 1  (OEM_APPROVED)
# Then re-registers with:
#   approved_by_fleet = FLEET_IDENTITY env var
#   fleet_approved_at = current ISO-8601 timestamp
#   approval_stage    = 2  (RELEASED_TO_DEVICE)
#
# Usage:
#   bash scripts/Build_image/send_to_blockchain_from_fleet.sh [PROJECT_DIR]
#
# Required env vars (set via .env.secrets):
#   RPC_URL          Ethereum JSON-RPC  e.g. http://192.168.1.5:8545
#   CONTRACT_ADDR    FirmwareMetadataStore contract address (0x...)
#   SIGNER_KEY       Ethereum private key of fleet signer (0x...)
#   FLEET_IDENTITY   Human-readable fleet approver ID  e.g. "Fleet-Mgr:ops1"
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
[ -f "$METADATA_JSON" ]        || err "firmware-metadata.json not found: $METADATA_JSON"
[ -n "${RPC_URL:-}"         ]  || err "RPC_URL is not set"
[ -n "${CONTRACT_ADDR:-}"   ]  || err "CONTRACT_ADDR is not set"
[ -n "${SIGNER_KEY:-}"      ]  || err "SIGNER_KEY is not set"
[ -n "${FLEET_IDENTITY:-}"  ]  || err "FLEET_IDENTITY is not set. Add to .env.secrets: export FLEET_IDENTITY=\"Fleet-Mgr:ops1\""

_missing_pkgs=""
python3 -c "from eth_account import Account" 2>/dev/null || _missing_pkgs="$_missing_pkgs eth-account eth-hash[pycryptodome]"
python3 -c "import requests"                 2>/dev/null || _missing_pkgs="$_missing_pkgs requests"
if [ -n "$_missing_pkgs" ]; then
    log "Installing:$_missing_pkgs"
    python3 -m pip install --quiet $_missing_pkgs \
        || python3 -m pip install --quiet --break-system-packages $_missing_pkgs \
        || err "Install failed — activate a venv: source ~/.venvs/web3/bin/activate"
fi

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Fleet Approval — Firmware Blockchain Registration"
echo "============================================================"
log "  Metadata        : $METADATA_JSON"
log "  RPC             : $RPC_URL"
log "  Contract        : $CONTRACT_ADDR"
log "  Fleet identity  : $FLEET_IDENTITY"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Run: read on-chain state → validate OEM approval → fleet approve → register
# ─────────────────────────────────────────────────────────────────────────────
TX_HASH=$(
    METADATA_JSON_PATH="$METADATA_JSON" \
    RPC_URL="$RPC_URL" \
    CONTRACT_ADDR="$CONTRACT_ADDR" \
    SIGNER_KEY="$SIGNER_KEY" \
    FLEET_IDENTITY="$FLEET_IDENTITY" \
    python3 - <<'PYEOF'
import json, os, sys, requests
from datetime import datetime, timezone
from eth_account import Account
from eth_hash.auto import keccak

meta_path       = os.environ["METADATA_JSON_PATH"]
rpc_url         = os.environ["RPC_URL"]
contract_addr   = os.environ["CONTRACT_ADDR"]
signer_key      = os.environ["SIGNER_KEY"]
fleet_identity  = os.environ["FLEET_IDENTITY"]

with open(meta_path) as f:
    meta = json.load(f)

fw_version = meta.get("firmware_version", "")
if not fw_version:
    print("ERROR: firmware_version missing from metadata", file=sys.stderr)
    sys.exit(1)

# ── ABI helpers ───────────────────────────────────────────────────────────────
def uint256_word(n: int) -> bytes:
    return n.to_bytes(32, "big")

def encode_string(s: str) -> bytes:
    data = s.encode("utf-8")
    pad  = (32 - len(data) % 32) % 32
    return uint256_word(len(data)) + data + b"\x00" * pad

def rpc(method, params):
    r = requests.post(rpc_url,
                      json={"jsonrpc":"2.0","method":method,"params":params,"id":1},
                      timeout=15)
    r.raise_for_status()
    resp = r.json()
    if "error" in resp:
        raise RuntimeError(f"RPC error: {resp['error']}")
    return resp["result"]

# ── Read current on-chain state via readFirmwareMetadata(string) ──────────────
print(f"  Reading on-chain state for {fw_version} ...", file=sys.stderr)

read_sig      = "readFirmwareMetadata(string)"
read_selector = keccak(read_sig.encode())[:4]
ver_bytes     = fw_version.encode("utf-8")
ver_pad       = (32 - len(ver_bytes) % 32) % 32
read_calldata = "0x" + (
    read_selector +
    uint256_word(32) +
    uint256_word(len(ver_bytes)) +
    ver_bytes + b"\x00" * ver_pad
).hex()

resp = requests.post(rpc_url, json={
    "jsonrpc":"2.0","method":"eth_call",
    "params":[{"to": contract_addr, "data": read_calldata}, "latest"],
    "id": 10
}, timeout=15)
resp.raise_for_status()
call_resp = resp.json()
if "error" in call_resp:
    raise RuntimeError(f"readFirmwareMetadata eth_call error: {call_resp['error']}")

result_hex = call_resp.get("result", "0x")
if not result_hex or result_hex == "0x":
    print(f"ERROR: firmware version {fw_version!r} not found on-chain.", file=sys.stderr)
    sys.exit(1)

# ── Decode the 15-slot ABI return ─────────────────────────────────────────────
data = bytes.fromhex(result_hex[2:] if result_hex.startswith("0x") else result_hex)

def read_uint(slot):
    off = slot * 32
    return int.from_bytes(data[off:off+32], "big") if off+32 <= len(data) else 0

def read_str(abs_offset):
    if abs_offset + 32 > len(data): return ""
    length = int.from_bytes(data[abs_offset:abs_offset+32], "big")
    if length == 0: return ""
    start = abs_offset + 32
    return data[start:start+length].decode("utf-8", errors="replace") if start+length <= len(data) else ""

on_chain = {
    "firmware_hash":          read_str(read_uint(0)),
    "firmware_version":       read_str(read_uint(1)),
    "timestamp":              read_str(read_uint(2)),
    "signer_identity":        read_str(read_uint(3)),
    "download_url":           read_str(read_uint(4)),
    "image_filename":         read_str(read_uint(5)),
    "image_size_bytes":       read_uint(6),
    "final_image_filename":   read_str(read_uint(7)),
    "final_image_size_bytes": read_uint(8),
    "approval_stage":         read_uint(9),
    "approved_by_oem":        read_str(read_uint(10)),
    "oem_approved_at":        read_str(read_uint(11)),
    "approved_by_fleet":      read_str(read_uint(12)),
    "fleet_approved_at":      read_str(read_uint(13)),
    "exists":                 bool(data[14*32+31]) if len(data) >= 15*32 else False,
}

print(f"  On-chain approval_stage  : {on_chain['approval_stage']}", file=sys.stderr)
print(f"  On-chain approved_by_oem : {on_chain['approved_by_oem']!r}", file=sys.stderr)
print(f"  On-chain oem_approved_at : {on_chain['oem_approved_at']!r}", file=sys.stderr)

if not on_chain["exists"]:
    print(f"ERROR: firmware {fw_version!r} does not exist on-chain.", file=sys.stderr)
    sys.exit(1)

# ── Validate OEM has approved ─────────────────────────────────────────────────
stage_names = {0:"PENDING_OEM", 1:"OEM_APPROVED", 2:"RELEASED_TO_DEVICE"}

if not on_chain["approved_by_oem"].strip():
    print("ERROR: approved_by_oem is empty on-chain.", file=sys.stderr)
    print("       Run send_to_blockchain_from_oem.sh first.", file=sys.stderr)
    sys.exit(1)

if not on_chain["oem_approved_at"].strip():
    print("ERROR: oem_approved_at is empty on-chain.", file=sys.stderr)
    print("       Run send_to_blockchain_from_oem.sh first.", file=sys.stderr)
    sys.exit(1)

if on_chain["approval_stage"] != 1:
    label = stage_names.get(on_chain["approval_stage"], str(on_chain["approval_stage"]))
    print(f"ERROR: Cannot apply Fleet approval — current stage is {label} ({on_chain['approval_stage']}).", file=sys.stderr)
    print( "       Fleet approval requires approval_stage == 1 (OEM_APPROVED).", file=sys.stderr)
    sys.exit(1)

# ── Prepare updated fields ────────────────────────────────────────────────────
fleet_approved_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
approval_stage    = 2   # RELEASED_TO_DEVICE

print(f"  OEM approver     : {on_chain['approved_by_oem']} @ {on_chain['oem_approved_at']}", file=sys.stderr)
print(f"  Fleet approving  : {fleet_identity}", file=sys.stderr)
print(f"  Timestamp        : {fleet_approved_at}", file=sys.stderr)

# ── Build writeFirmwareMetadata calldata (14 params) ─────────────────────────
SIG      = ("writeFirmwareMetadata("
            "string,string,string,string,string,string,"
            "uint256,string,uint256,uint8,"
            "string,string,string,string)")
selector = keccak(SIG.encode())[:4]

params = [
    ("string",  on_chain["firmware_hash"]),
    ("string",  on_chain["firmware_version"]),
    ("string",  on_chain["timestamp"]),
    ("string",  on_chain["signer_identity"]),
    ("string",  on_chain["download_url"]),
    ("string",  on_chain["image_filename"]),
    ("uint256", on_chain["image_size_bytes"]),
    ("string",  on_chain["final_image_filename"]),
    ("uint256", on_chain["final_image_size_bytes"]),
    ("uint8",   approval_stage),
    ("string",  on_chain["approved_by_oem"]),    # preserved from chain
    ("string",  on_chain["oem_approved_at"]),    # preserved from chain
    ("string",  fleet_identity),
    ("string",  fleet_approved_at),
]

head   = bytearray()
tail   = bytearray()
offset = len(params) * 32

for ptype, pval in params:
    if ptype == "string":
        head += uint256_word(offset)
        enc   = encode_string(str(pval))
        tail += enc
        offset += len(enc)
    else:
        head += uint256_word(int(pval))

calldata = "0x" + (selector + bytes(head) + bytes(tail)).hex()

# ── Sign and send ─────────────────────────────────────────────────────────────
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
signed  = acct.sign_transaction(tx)
tx_hash = rpc("eth_sendRawTransaction", [signed.raw_transaction.hex()])

print(f"  signer       : {acct.address}", file=sys.stderr)
print(f"  chain_id     : {chain_id}", file=sys.stderr)
print(f"  calldata     : {len(calldata)} chars", file=sys.stderr)

# ── Update local firmware-metadata.json ──────────────────────────────────────
meta["approval_stage"]    = approval_stage
meta["approved_by_fleet"] = fleet_identity
meta["fleet_approved_at"] = fleet_approved_at
meta["tx_hash"]           = tx_hash
with open(meta_path, "w") as f:
    json.dump(meta, f, indent=2)

print(tx_hash)
PYEOF
)

[ -n "$TX_HASH" ] || err "No tx_hash returned — Fleet approval may have failed."

echo ""
ok "Fleet approval registered on-chain"
ok "tx_hash        : $TX_HASH"
ok "approval_stage : 2 (RELEASED_TO_DEVICE)"
ok "approved_by    : $FLEET_IDENTITY"
ok "Metadata       : $METADATA_JSON  (updated)"
echo ""
echo "============================================================"
echo "  Fleet Approval — COMPLETE"
echo "  Firmware is now RELEASED_TO_DEVICE"
echo "============================================================"
echo ""
echo "  To verify on Hardhat node:"
echo "    cast tx $TX_HASH --rpc-url $RPC_URL"
echo ""
