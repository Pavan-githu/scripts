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
#   [2] Runs  bitbake core-image-minimal
#   [3] Verifies the build succeeded (Tasks Summary check)
#   [4] Locates the output .rootfs.wic.bz2 image
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
# Resolve project root from $1 or default
# ─────────────────────────────────────────────────────────────────────────────
PROJECT_DIR="${1:-/home/ubuntu/raceiotprj}"

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
DEPLOY_DIR="$PROJECT_DIR/build/tmp/deploy/images/raspberrypi3"
VERSION_FILE="$PROJECT_DIR/sources/meta-userapp-package/recipes-apps/iot-gateway/VERSION"
META_LAYER="$PROJECT_DIR/sources/meta-userapp-package"
OUTPUT_DIR="$PROJECT_DIR/Build_image"
METADATA_JSON="$OUTPUT_DIR/firmware-metadata.json"
TMP_META_JSON="/tmp/firmware-meta.json"
DEPLOY_SCRIPT="$PROJECT_DIR/scripts/deploy_firmware.py"
IMAGE_RECIPE="core-image-minimal"
BOARD="raspberrypi3"

# ─────────────────────────────────────────────────────────────────────────────
# Signer identity (accountability field)
# ─────────────────────────────────────────────────────────────────────────────
SIGNER_IDENTITY="${SIGNER_IDENTITY:-TechID:5678}"

# ─────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ─────────────────────────────────────────────────────────────────────────────
log()  { echo "[$(date '+%H:%M:%S')] $*"; }
ok()   { echo "[$(date '+%H:%M:%S')] ✔  $*"; }
warn() { echo "[$(date '+%H:%M:%S')] ⚠  $*" >&2; }
err()  { echo "[$(date '+%H:%M:%S')] ✘  $*" >&2; exit 1; }

separator() { echo "──────────────────────────────────────────────────────────────"; }

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
log "[5/11] Locating firmware image in $DEPLOY_DIR ..."

# Pick the most-recently modified .rootfs.wic.bz2 for this recipe
IMAGE_PATH=$(ls -t "$DEPLOY_DIR/${IMAGE_RECIPE}-${BOARD}-"*.rootfs.wic.bz2 \
             2>/dev/null | head -n 1 || true)

if [ -z "$IMAGE_PATH" ]; then
    # Fallback: any .wic.bz2 in the deploy directory
    IMAGE_PATH=$(ls -t "$DEPLOY_DIR/"*.rootfs.wic.bz2 2>/dev/null | head -n 1 || true)
fi

[ -n "$IMAGE_PATH" ] || err "No .rootfs.wic.bz2 image found in $DEPLOY_DIR"

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

# firmware_id = keccak256(version || build_ts || git_commit) computed in Python
# For the shell-only metadata file we record the raw inputs and leave
# firmware_id to be filled by deploy_firmware.py if invoked below.

cat > "$METADATA_JSON" <<EOF
{
  "firmware_hash":     "$FIRMWARE_HASH",
  "firmware_version":  "$FIRMWARE_VERSION",
  "timestamp":         "$TIMESTAMP",
  "signer_identity":   "$SIGNER_IDENTITY",
  "download_url":      "$FIRMWARE_DOWNLOAD_URL",
  "image_filename":    "$IMAGE_FILENAME",
  "image_size_bytes":  $IMAGE_SIZE_BYTES,
  "git_commit":        "$GIT_COMMIT",
  "board":             "$BOARD",
  "image_recipe":      "$IMAGE_RECIPE",
  "build_log":         "$BUILD_LOG"
}
EOF
# Note: hsm_signature / sig_file / pubkey_file / ldr_sha256 / hsm_key_id /
#       hsm_algorithm are added by sign_firmware.py (KMS step) after the
#       RPIF .ldr is built in step 12.
# Note: firmware_id / tx_hash are added by deploy_firmware.py (blockchain step).

# Mirror to /tmp for downstream tools
cp "$METADATA_JSON" "$TMP_META_JSON"

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
# [Optional] Full pipeline — GitHub upload + blockchain registration
#
# Activated when ALL of the following are present:
#   GCP_PROJECT, GCP_KEYRING, GCP_KEY_NAME, GITHUB_TOKEN,
#   CONTRACT_ADDR, SIGNER_KEY
# ─────────────────────────────────────────────────────────────────────────────
REQUIRED_FOR_PIPELINE="GCP_PROJECT GCP_KEYRING GCP_KEY_NAME GITHUB_TOKEN CONTRACT_ADDR SIGNER_KEY"
MISSING_VARS=""
for VAR in $REQUIRED_FOR_PIPELINE; do
    [ -n "${!VAR:-}" ] || MISSING_VARS="${MISSING_VARS} ${VAR}"
done

separator
if [ -n "$MISSING_VARS" ]; then
    warn "Skipping GitHub upload / blockchain registration."
    warn "Set the following environment variables to enable the full pipeline:"
    for V in $MISSING_VARS; do
        warn "  export $V=..."
    done
    echo ""
    warn "You can run the full pipeline manually afterwards:"
    warn "  export GCP_PROJECT=... GCP_KEYRING=... GCP_KEY_NAME=..."
    warn "  export GITHUB_TOKEN=... CONTRACT_ADDR=... SIGNER_KEY=..."
    warn "  python3 $DEPLOY_SCRIPT"
else
    log "All pipeline env vars present — invoking deploy_firmware.py ..."
    echo ""

    # Pass metadata already computed so the Python script doesn't need to
    # rebuild; it will still locate the image via DEPLOY_DIR.
    export VERSION="$VERSION_RAW"
    export GCP_LOCATION="${GCP_LOCATION:-global}"
    export GCP_KEY_VERSION="${GCP_KEY_VERSION:-1}"
    export RPC_URL="${RPC_URL:-http://127.0.0.1:8545}"

    if python3 "$DEPLOY_SCRIPT"; then
        ok "deploy_firmware.py completed."
        # Merge firmware_id, hsm_signature, tx_hash back into our JSON
        if [ -f "$TMP_META_JSON" ]; then
            python3 - <<'PYEOF'
import json, sys

meta_path   = "/tmp/firmware-meta.json"
output_path = None  # filled below

import os
output_path = os.environ.get("METADATA_JSON_PATH")

with open(meta_path) as f:
    deployed = json.load(f)

with open(output_path) as f:
    local = json.load(f)

# Merge deployed fields into the local metadata
for key in ("firmware_id", "hsm_signature", "hsm_key", "tx_hash", "download_url"):
    if deployed.get(key):
        local[key] = deployed[key]

with open(output_path, "w") as f:
    json.dump(local, f, indent=2)

print(f"  firmware_id  : {local.get('firmware_id', 'n/a')}")
print(f"  hsm_signature: {str(local.get('hsm_signature', ''))[:32]}...")
print(f"  download_url : {local.get('download_url', 'n/a')}")
print(f"  tx_hash      : {local.get('tx_hash', 'n/a')}")
PYEOF
            METADATA_JSON_PATH="$METADATA_JSON" python3 - <<'PYEOF2'
import json, os

meta_path   = "/tmp/firmware-meta.json"
output_path = os.environ["METADATA_JSON_PATH"]

with open(meta_path) as f:
    deployed = json.load(f)

with open(output_path) as f:
    local = json.load(f)

for key in ("firmware_id", "hsm_signature", "hsm_key", "tx_hash", "download_url"):
    if deployed.get(key):
        local[key] = deployed[key]

with open(output_path, "w") as f:
    json.dump(local, f, indent=2)
PYEOF2
            ok "Metadata merged with HSM + blockchain fields: $METADATA_JSON"
        fi
    else
        warn "deploy_firmware.py exited with errors — partial metadata in $METADATA_JSON"
    fi
fi

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
echo "  To flash the final image to an SD card:"
echo "    python3 -c \"import sys; data=open('${LDR_PATH:-}','rb').read(); open('/tmp/payload.wic.bz2','wb').write(data[116:])\""
echo "    bzcat /tmp/payload.wic.bz2 | sudo dd of=/dev/sdX bs=4M status=progress"
echo ""
echo "  To copy the final image to your local machine:"
echo "    scp ubuntu@<vps-ip>:${LDR_PATH:-$IMAGE_PATH} ./"
echo "============================================================"
