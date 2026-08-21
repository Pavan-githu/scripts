#!/bin/bash
# =============================================================================
# Build_image/build_image.sh
#
# Full IoT Gateway firmware build pipeline for Raspberry Pi 3.
#
# Usage:
#   bash Build_image/build_image.sh [PROJECT_DIR]
#
#   PROJECT_DIR defaults to /home/ubuntu/raceiotprj if not supplied.
#
# What this script does:
#   [1] Sources the Yocto OpenEmbedded build environment
#   [2] Runs  bitbake iot-gateway-bundle
#   [3] Verifies the build succeeded (Tasks Summary check)
#   [4] Locates the output .raucb bundle
#   [5] Computes SHA-256 of the image  (firmware_hash – integrity)
#   [6] Reads firmware version from sources/meta-userapp-package/…/VERSION
#   [7] Records ISO-8601 build timestamp           (audit trail)
#   [8] Records signer identity                    (accountability)
#   [9] Constructs firmware download URL
#   [10] Writes Build_image/firmware-metadata.json
#   [11] Invokes scripts/deploy_firmware.py if GCP / GitHub env vars are set
#        (HSM signing via Google Cloud KMS + blockchain registration)
#
# Environment variables (optional – enable full pipeline):
#   SIGNER_IDENTITY  Human/CI identity, e.g. "TechID:5678"  (default: TechID:5678)
#   DOWNLOAD_URL     Override the firmware download URL
#   GITHUB_TOKEN     GitHub PAT (repo scope) – required for GitHub Release upload
#   GCP_PROJECT      Google Cloud project ID  – required for HSM signing
#   GCP_KEYRING      Cloud KMS key ring name  (default: firmware-signing)
#   GCP_KEY_NAME     Cloud KMS key name       (default: firmware-key)
#   GCP_KEY_VERSION  Key version number       (default: 1)
#   RPC_URL          Ethereum JSON-RPC URL    (default: http://127.0.0.1:8545)
#   CONTRACT_ADDR    IoTFirmwareRegistry contract address
#   SIGNER_KEY       Ethereum private key of build host / CI signer
#   GOOGLE_APPLICATION_CREDENTIALS  Path to GCP service-account JSON
# =============================================================================

set -euo pipefail

# ─────────────────────────────────────────────────────────────────────────────
# Load repo-root .env.secrets (two levels up from this script)
# ─────────────────────────────────────────────────────────────────────────────
_ROOT_SECRETS="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.env.secrets"
if [ -f "$_ROOT_SECRETS" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$_ROOT_SECRETS"
    set +a
fi

# ─────────────────────────────────────────────────────────────────────────────
# Resolve project root from $1 or default
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${1:-$(cd "$SCRIPT_DIR/../.." && pwd)}"

if [ ! -d "$PROJECT_DIR" ]; then
    echo "ERROR: PROJECT_DIR does not exist: $PROJECT_DIR"
    exit 1
fi

# Canonical absolute path (no trailing slash)
PROJECT_DIR="$(cd "$PROJECT_DIR" && pwd)"

# ─────────────────────────────────────────────────────────────────────────────
# Fixed paths derived from project root
# ─────────────────────────────────────────────────────────────────────────────
OE_INIT="$PROJECT_DIR/sources/poky/oe-init-build-env"
IMAGE_DEPLOY_DIR="$PROJECT_DIR/build/tmp/deploy/images/raspberrypi3"
VERSION_FILE="$PROJECT_DIR/sources/meta-userapp-package/recipes-apps/iot-gateway/VERSION"
META_LAYER="$PROJECT_DIR/sources/meta-userapp-package"
OUTPUT_DIR="$PROJECT_DIR/scripts/Build_image"
METADATA_JSON="$OUTPUT_DIR/firmware-metadata.json"
TMP_META_JSON="/tmp/firmware-meta.json"
DEPLOY_SCRIPT="$PROJECT_DIR/scripts/deploy_firmware.py"
IMAGE_RECIPE="iot-gateway-bundle"
BOARD="raspberrypi3"

# ─────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────────────────────
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
ok()   { echo "[$(date '+%H:%M:%S')] ✔  $*"; }
warn() { echo "[$(date '+%H:%M:%S')] ⚠  $*" >&2; }
err()  { echo "[$(date '+%H:%M:%S')] ✘  $*" >&2; exit 1; }

separator() { echo "──────────────────────────────────────────────────────────────"; }

# ─────────────────────────────────────────────────────────────────────────────
# Load secrets from .env.secrets (never commit this file to version control)
# Expected location: $PROJECT_DIR/scripts/Build_image/.env.secrets
# ─────────────────────────────────────────────────────────────────────────────
ENV_SECRETS="$OUTPUT_DIR/.env.secrets"
if [ -f "$ENV_SECRETS" ]; then
    # shellcheck disable=SC1090
    set -a
    source "$ENV_SECRETS"
    set +a
    log "Loaded secrets from $ENV_SECRETS"
else
    warn ".env.secrets not found at $ENV_SECRETS — blockchain/signing vars must be set in environment."
    warn "  Create $ENV_SECRETS with: RPC_URL, CONTRACT_ADDR, SIGNER_KEY, GITHUB_TOKEN, GCP_PROJECT, etc."
fi

# ─────────────────────────────────────────────────────────────────────────────
# Signer identity (accountability field)
# ─────────────────────────────────────────────────────────────────────────────
SIGNER_IDENTITY="${SIGNER_IDENTITY:-TechID:5678}"

# ─────────────────────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  IoT Gateway — Firmware Build Pipeline"
echo "  Target  : $IMAGE_RECIPE ($BOARD)"
echo "  Project : $PROJECT_DIR"
echo "  Started : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
echo "============================================================"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [1] Validate prerequisites
# ─────────────────────────────────────────────────────────────────────────────
separator
log "[1/11] Validating prerequisites..."

[ -f "$OE_INIT" ]      || err "OE init script not found: $OE_INIT"
[ -f "$VERSION_FILE" ] || err "VERSION file not found: $VERSION_FILE"
command -v sha256sum >/dev/null 2>&1 || \
    command -v shasum >/dev/null 2>&1 || \
    err "sha256sum / shasum not found in PATH"

ok "Prerequisites OK"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [2] Source OE environment + [3] Run bitbake
# ─────────────────────────────────────────────────────────────────────────────
separator
log "[2/11] Sourcing OpenEmbedded build environment..."
log "[3/11] Running: bitbake $IMAGE_RECIPE"
echo ""

# Build log for post-analysis
BUILD_LOG="$OUTPUT_DIR/build-$(date +%Y%m%d-%H%M%S).log"
mkdir -p "$OUTPUT_DIR"

# oe-init-build-env must run in the same shell (uses 'source').
# We capture stdout+stderr with 'tee' so both the terminal and the log file
# receive live output.
BUILD_CMD="cd $PROJECT_DIR && source $OE_INIT && bitbake $IMAGE_RECIPE"

set +e
bash -c "$BUILD_CMD" 2>&1 | tee "$BUILD_LOG"
BITBAKE_EXIT="${PIPESTATUS[0]}"
set -e

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [4] Verify build success via Tasks Summary line
# ─────────────────────────────────────────────────────────────────────────────
separator
log "[4/11] Verifying build result..."

SUCCESS_LINE=$(grep -m1 "Tasks Summary:.*all succeeded" "$BUILD_LOG" 2>/dev/null || true)

if [ "$BITBAKE_EXIT" -ne 0 ] || [ -z "$SUCCESS_LINE" ]; then
    err "Build FAILED (exit=$BITBAKE_EXIT). Check log: $BUILD_LOG"
fi

ok "Build verified: $SUCCESS_LINE"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [5] Locate the output image
# ─────────────────────────────────────────────────────────────────────────────
separator
log "[5/11] Locating firmware image in $IMAGE_DEPLOY_DIR ..."

# Pick the most-recently modified .raucb bundle for this recipe
IMAGE_PATH=$(ls -t "$IMAGE_DEPLOY_DIR/${IMAGE_RECIPE}-${BOARD}"*.raucb \
             2>/dev/null | head -n 1 || true)

if [ -z "$IMAGE_PATH" ]; then
    # Fallback: any .raucb in the deploy directory
    IMAGE_PATH=$(ls -t "$IMAGE_DEPLOY_DIR/"*.raucb 2>/dev/null | head -n 1 || true)
fi

[ -n "$IMAGE_PATH" ] || err "No .raucb bundle found in $IMAGE_DEPLOY_DIR"

IMAGE_FILENAME="$(basename "$IMAGE_PATH")"
IMAGE_SIZE_BYTES=$(wc -c < "$IMAGE_PATH")
IMAGE_SIZE_HUMAN=$(du -sh "$IMAGE_PATH" | cut -f1)

ok "Image found : $IMAGE_PATH"
ok "Size        : $IMAGE_SIZE_HUMAN ($IMAGE_SIZE_BYTES bytes)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [6] Compute SHA-256 — Firmware Hash (Integrity Check)
# ─────────────────────────────────────────────────────────────────────────────
separator
log "[6/11] Computing SHA-256 of firmware image..."

if command -v sha256sum >/dev/null 2>&1; then
    SHA256_HEX=$(sha256sum "$IMAGE_PATH" | awk '{print $1}')
else
    # macOS / BSD fallback
    SHA256_HEX=$(shasum -a 256 "$IMAGE_PATH" | awk '{print $1}')
fi

FIRMWARE_HASH="sha256:${SHA256_HEX}"

ok "Firmware Hash (Integrity) : $FIRMWARE_HASH"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [7] Read firmware version — Version Control
# ─────────────────────────────────────────────────────────────────────────────
separator
log "[7/11] Reading firmware version..."

VERSION_RAW=$(head -n1 "$VERSION_FILE" | tr -d '[:space:]')
# Normalise: ensure it starts with 'v'
case "$VERSION_RAW" in
    v*) FIRMWARE_VERSION="$VERSION_RAW" ;;
    *)  FIRMWARE_VERSION="v${VERSION_RAW}" ;;
esac

ok "Firmware Version (Version Control) : $FIRMWARE_VERSION"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [8] Build timestamp — Audit Trail
# ─────────────────────────────────────────────────────────────────────────────
separator
log "[8/11] Recording build timestamp..."

# Use the image file's mtime as the authoritative build completion time.
# This is the moment bitbake finished writing the image — more accurate than
# the current shell time.
if stat --version 2>/dev/null | grep -q GNU; then
    # GNU coreutils
    IMAGE_MTIME_UNIX=$(stat -c '%Y' "$IMAGE_PATH")
else
    # BSD / macOS
    IMAGE_MTIME_UNIX=$(stat -f '%m' "$IMAGE_PATH")
fi

TIMESTAMP=$(date -u -d "@$IMAGE_MTIME_UNIX" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || \
            date -u -r "$IMAGE_MTIME_UNIX"  '+%Y-%m-%dT%H:%M:%SZ')

ok "Timestamp (Audit Trail) : $TIMESTAMP"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [9] Signer Identity — Accountability
# ─────────────────────────────────────────────────────────────────────────────
separator
log "[9/11] Resolving signer identity..."

# If GCP_PROJECT is set, derive the signer identity from the full Google Cloud
# KMS key resource path — this ties accountability directly to the HSM key that
# will sign the firmware, making the identity cryptographically verifiable.
# Format: projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key>/cryptoKeyVersions/<ver>
# Falls back to the SIGNER_IDENTITY env var when GCP is not configured.
_GCP_PROJECT="${GCP_PROJECT:-project-9d4ab863-a976-47a2-9f2}"
_GCP_LOCATION="${GCP_LOCATION:-global}"
_GCP_KEYRING="${GCP_KEYRING:-firmware-signing}"
_GCP_KEY_NAME="${GCP_KEY_NAME:-firmware-key}"
_GCP_KEY_VERSION="${GCP_KEY_VERSION:-1}"

if [ -n "$_GCP_PROJECT" ]; then
    SIGNER_IDENTITY="projects/${_GCP_PROJECT}/locations/${_GCP_LOCATION}/keyRings/${_GCP_KEYRING}/cryptoKeys/${_GCP_KEY_NAME}/cryptoKeyVersions/${_GCP_KEY_VERSION}"
fi

# Export resolved KMS settings so downstream scripts use the same values.
export GCP_PROJECT="$_GCP_PROJECT"
export GCP_LOCATION="$_GCP_LOCATION"
export GCP_KEYRING="$_GCP_KEYRING"
export GCP_KEY_NAME="$_GCP_KEY_NAME"
export GCP_KEY_VERSION="$_GCP_KEY_VERSION"

# git commit from meta-userapp-package for full traceability
if git -C "$META_LAYER" rev-parse HEAD >/dev/null 2>&1; then
    GIT_COMMIT=$(git -C "$META_LAYER" rev-parse HEAD)
    GIT_COMMIT_SHORT="${GIT_COMMIT:0:12}"
else
    GIT_COMMIT="unknown"
    GIT_COMMIT_SHORT="unknown"
fi

ok "Signer Identity (Accountability) : $SIGNER_IDENTITY"
ok "Git commit (meta-userapp-package) : $GIT_COMMIT_SHORT"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [10] Firmware download URL
# ─────────────────────────────────────────────────────────────────────────────
separator
log "[10/11] Resolving firmware download URL..."
export DOWNLOAD_URL="https://github.com/Pavan-githu/meta-userapp-package/releases"
if [ -n "${DOWNLOAD_URL:-}" ]; then
    FIRMWARE_DOWNLOAD_URL="$DOWNLOAD_URL"
    ok "Download URL (provided via env) : $FIRMWARE_DOWNLOAD_URL"
else
    # Construct from GitHub Releases pattern used by deploy_firmware.py
    GITHUB_REPO="${GITHUB_REPO:-Pavan-githu/meta-userapp-package}"
    TAG="v${VERSION_RAW}-${IMAGE_MTIME_UNIX}"
    FIRMWARE_DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/${TAG}/${IMAGE_FILENAME}"
    warn "DOWNLOAD_URL not set — constructed from GitHub Releases pattern:"
    warn "  $FIRMWARE_DOWNLOAD_URL"
    warn "  Run with DOWNLOAD_URL=<url> to override, or let deploy_firmware.py populate it."
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [11] Write firmware-metadata.json
# ─────────────────────────────────────────────────────────────────────────────
separator
log "[11/12] Writing firmware metadata..."

export FIRMWARE_HASH FIRMWARE_VERSION TIMESTAMP SIGNER_IDENTITY \
       FIRMWARE_DOWNLOAD_URL IMAGE_FILENAME IMAGE_SIZE_BYTES \
       METADATA_JSON TMP_META_JSON

bash "$OUTPUT_DIR/write_firmware_metadata.sh"

ok "Metadata written : $METADATA_JSON"
ok "Metadata copy    : $TMP_META_JSON"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [12] Prepend binary firmware header → produce final_image.ldr
# ─────────────────────────────────────────────────────────────────────────────
separator
log "[12/12] Prepending firmware header (header + payload → final_image.ldr)..."

HEADER_SCRIPT="$OUTPUT_DIR/add_firmware_header.py"

if [ ! -f "$HEADER_SCRIPT" ]; then
    err "add_firmware_header.py not found at $HEADER_SCRIPT"
fi

if python3 "$HEADER_SCRIPT" "$PROJECT_DIR"; then
    LDR_FILE=$(python3 -c "
import json, os
with open('$METADATA_JSON') as f:
    m = json.load(f)
print(m.get('final_image_filename', ''))
")
    LDR_PATH=$(python3 -c "
import json, os
with open('$METADATA_JSON') as f:
    m = json.load(f)
print(m.get('final_image_path', ''))
")
    ok "Header packer complete : $LDR_PATH"
else
    err "add_firmware_header.py failed — aborting pipeline."
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [Optional – GCP] Google Cloud KMS signing of RPIF_*.ldr
#
# Activated when GCP_PROJECT (or the default service-account JSON) is present.
# Does NOT require GITHUB_TOKEN / CONTRACT_ADDR / SIGNER_KEY.
# ─────────────────────────────────────────────────────────────────────────────
SIGN_SCRIPT="$OUTPUT_DIR/sign_firmware.py"
DEFAULT_SA_JSON="$PROJECT_DIR/Google-HSM-Sign/firmware-signer-key.json"
SA_JSON="${GOOGLE_APPLICATION_CREDENTIALS:-$DEFAULT_SA_JSON}"

separator
if [ ! -f "$SIGN_SCRIPT" ]; then
    warn "sign_firmware.py not found at $SIGN_SCRIPT — skipping KMS signing."
elif [ ! -f "$SA_JSON" ] && [ -z "${GCP_PROJECT:-}" ]; then
    warn "Skipping Google Cloud KMS signing."
    warn "Provide one of:"
    warn "  export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json"
    warn "  export GCP_PROJECT=<project-id>  (+ GCP_KEYRING, GCP_KEY_NAME)"
    warn "Or place service-account JSON at: $DEFAULT_SA_JSON"
    echo ""
    warn "To sign manually afterwards:"
    warn "  python3 $SIGN_SCRIPT $PROJECT_DIR"
else
    log "[KMS] Signing RPIF .ldr with Google Cloud KMS..."
    export GCP_LOCATION="${GCP_LOCATION:-global}"
    export GCP_KEY_VERSION="${GCP_KEY_VERSION:-1}"
    if python3 "$SIGN_SCRIPT" "$PROJECT_DIR"; then
        HSM_SIG=$(python3 -c "
import json
with open('$METADATA_JSON') as f:
    m = json.load(f)
print(m.get('hsm_signature','')[:48] + '...')
")
        HSM_KEY=$(python3 -c "
import json
with open('$METADATA_JSON') as f:
    m = json.load(f)
print(m.get('hsm_key_id',''))
")
        ok "[KMS] Signed  : $HSM_KEY"
        ok "[KMS] Sig hex : $HSM_SIG"
    else
        warn "[KMS] sign_firmware.py exited with errors — signature not written."
    fi
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [Optional] Append RPIS signature tail to .ldr
#
# Activated when KMS signing wrote hsm_signature into firmware-metadata.json.
# Appends a 264-byte RPIS tail: "RPIS"(4) + sig_alg(2) + sig_len(2) + sig(256).
# Produces a fully self-contained authenticated package:
#   [ 84-byte RPIF header ][ .raucb payload ][ 264-byte RPIS tail ]
# ─────────────────────────────────────────────────────────────────────────────
separator
METADATA_JSON_PATH="$METADATA_JSON" LDR_PATH_ENV="${LDR_PATH:-}" python3 - <<'PYEOF'
import json, os, struct

meta_path = os.environ["METADATA_JSON_PATH"]
ldr_path  = os.environ.get("LDR_PATH_ENV", "")

with open(meta_path) as f:
    meta = json.load(f)

hsm_sig_hex = meta.get("hsm_signature", "")

# Diagnose exactly which condition is blocking the RPIS tail step
if not hsm_sig_hex:
    print("  Skipping RPIS tail — hsm_signature is missing from metadata.")
    print("  Cause: KMS signing was skipped or failed (check [KMS] lines above).")
    raise SystemExit(0)
if not ldr_path:
    print("  Skipping RPIS tail — LDR_PATH is empty.")
    print("  Cause: add_firmware_header.py did not write final_image_path to metadata.")
    raise SystemExit(0)
if not os.path.exists(ldr_path):
    print(f"  Skipping RPIS tail — .ldr file not found on disk: {ldr_path}")
    print("  Cause: add_firmware_header.py may have written it to a different path.")
    raise SystemExit(0)

sig_bytes = bytes.fromhex(hsm_sig_hex)
sig_len   = len(sig_bytes)

# Pad/truncate to exactly 256 bytes (RSA-2048 DER signature is always 256 bytes)
sig_padded = (sig_bytes + b"\x00" * 256)[:256]

# RPIS tail: "RPIS"(4) + sig_alg uint16 LE + sig_len uint16 LE + signature(256)
RPIS_MAGIC           = b"RPIS"
SIG_ALG_RSA_PSS_2048 = 1
tail = RPIS_MAGIC + struct.pack("<HH", SIG_ALG_RSA_PSS_2048, sig_len) + sig_padded
assert len(tail) == 264, f"RPIS tail must be 264 bytes, got {len(tail)}"

with open(ldr_path, "ab") as f:
    f.write(tail)

final_size   = os.path.getsize(ldr_path)
tail_offset  = final_size - 264

meta["final_image_size_bytes"] = final_size
meta["rpis_tail"] = {
    "sig_alg":     "RSA_SIGN_PSS_2048_SHA256",
    "sig_len":     sig_len,
    "tail_offset": tail_offset,
}
with open(meta_path, "w") as f:
    json.dump(meta, f, indent=2)

print(f"  RPIS tail appended to : {ldr_path}")
print(f"  sig_alg               : RSA_SIGN_PSS_2048_SHA256")
print(f"  sig_len               : {sig_len} bytes")
print(f"  tail_offset           : {tail_offset:,} (byte 84 + payload_size)")
print(f"  Total .ldr size       : {final_size:,} bytes  (84 hdr + payload + 264 tail)")
PYEOF

if [ $? -eq 0 ]; then
    ok "[RPIS] Signature tail appended — .ldr is now a self-contained authenticated package."
else
    warn "[RPIS] Tail append skipped or failed — no signature embedded in .ldr."
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# [Optional] Upload .ldr firmware to GitHub Releases — establishes the real download URL
#
# Must run BEFORE blockchain registration so writeFirmwareMetadata() receives
# the actual verified URL, not a predicted placeholder.
# Activated when GITHUB_TOKEN is present.
# ─────────────────────────────────────────────────────────────────────────────
separator
if [ -z "${GITHUB_TOKEN:-}" ]; then
    warn "Skipping GitHub upload (GITHUB_TOKEN not set)."
    warn "  The download_url in metadata is a predicted value."
    warn "  export GITHUB_TOKEN=<token>  to upload and lock in the real URL before"
    warn "  blockchain registration."
else
    log "[GitHub] Uploading firmware to GitHub Releases..."
    export GITHUB_TOKEN
    export GITHUB_REPO="${GITHUB_REPO:-Pavan-githu/meta-userapp-package}"

    if python3 "$OUTPUT_DIR/upload_to_github.py" "$PROJECT_DIR"; then
        FIRMWARE_DOWNLOAD_URL=$(python3 -c "
import json
with open('$METADATA_JSON') as f:
    m = json.load(f)
print(m.get('download_url', ''))
")
        ok "[GitHub] Firmware uploaded. Real download URL locked in metadata."
        ok "[GitHub] URL : $FIRMWARE_DOWNLOAD_URL"
    else
        warn "[GitHub] Upload failed — download_url in metadata remains a predicted value."
    fi
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# Summary
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  Build Pipeline — COMPLETE"
echo "============================================================"
echo ""
echo "  Firmware Hash     (Integrity)    : $FIRMWARE_HASH"
echo "  Firmware Version  (Version Ctrl) : $FIRMWARE_VERSION"
echo "  Timestamp         (Audit Trail)  : $TIMESTAMP"
echo "  Signer Identity   (Accountability): $SIGNER_IDENTITY"
echo "  Download URL                     : $FIRMWARE_DOWNLOAD_URL"
echo ""
echo "  Image path   : $IMAGE_PATH"
echo "  Image size   : $IMAGE_SIZE_HUMAN"
echo "  Final image  : ${LDR_PATH:-n/a}"
echo "  Metadata     : $METADATA_JSON"
echo "  Build log    : $BUILD_LOG"
echo ""
echo "  To install the RAUC bundle on the device:"
echo "    python3 -c \"import sys; data=open('${LDR_PATH:-}','rb').read(); open('/tmp/payload.raucb','wb').write(data[84:])\""
echo "    rauc install /tmp/payload.raucb"
echo ""
echo "  To copy the final image to your local machine:"
echo "    scp ubuntu@<vps-ip>:${LDR_PATH:-$IMAGE_PATH} ./"
echo "============================================================"
