#!/bin/bash
# =============================================================================
# Build_image/write_firmware_metadata.sh
#
# Writes firmware-metadata.json and mirrors it to /tmp/firmware-meta.json.
#
# Called by build_image.sh after all metadata fields are resolved.
# All inputs are consumed from exported environment variables.
#
# Required env vars (set and exported by build_image.sh):
#   FIRMWARE_HASH          sha256:<hex>
#   FIRMWARE_VERSION       e.g. v0.2.0
#   TIMESTAMP              ISO-8601, e.g. 2026-08-21T17:04:21Z
#   SIGNER_IDENTITY        GCP KMS key path or TechID string
#   FIRMWARE_DOWNLOAD_URL  GitHub Releases URL (predicted or real)
#   IMAGE_FILENAME         e.g. iot-gateway-bundle-raspberrypi3.raucb
#   IMAGE_SIZE_BYTES       integer byte count
#   METADATA_JSON          absolute path for output JSON
#   TMP_META_JSON          mirror path, typically /tmp/firmware-meta.json
# =============================================================================

set -euo pipefail

# ── Validate required vars ────────────────────────────────────────────────────
for _var in FIRMWARE_HASH FIRMWARE_VERSION TIMESTAMP SIGNER_IDENTITY \
            FIRMWARE_DOWNLOAD_URL IMAGE_FILENAME IMAGE_SIZE_BYTES \
            METADATA_JSON TMP_META_JSON; do
    [ -n "${!_var:-}" ] || { echo "ERROR: $0: required var $_var is unset or empty" >&2; exit 1; }
done

# ── Write JSON ────────────────────────────────────────────────────────────────
# firmware_id is computed by deploy_firmware.py (keccak256); leave absent here.
# final_image_filename / final_image_size_bytes added by add_firmware_header.py.
# tx_hash added by blockchain registration step.
cat > "$METADATA_JSON" <<EOF
{
  "firmware_hash":     "$FIRMWARE_HASH",
  "firmware_version":  "$FIRMWARE_VERSION",
  "timestamp":         "$TIMESTAMP",
  "signer_identity":   "$SIGNER_IDENTITY",
  "download_url":      "$FIRMWARE_DOWNLOAD_URL",
  "image_filename":    "$IMAGE_FILENAME",
  "image_size_bytes":  $IMAGE_SIZE_BYTES
}
EOF

cp "$METADATA_JSON" "$TMP_META_JSON"
