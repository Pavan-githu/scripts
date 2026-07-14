#!/usr/bin/env python3
"""
Build_image/sign_firmware.py
-----------------------------
Signs the RPIF_<version>.ldr firmware package using Google Cloud KMS
(HSM-backed key).  The private key never leaves Google's hardware.

What this script does:
  [1] Loads Build_image/firmware-metadata.json to locate RPIF_*.ldr
  [2] Computes SHA-256 of the entire .ldr file (header + payload)
  [3] Calls Cloud KMS  AsymmetricSign  with that digest
  [4] Writes the DER signature to  RPIF_<version>.ldr.sig
  [5] Fetches and saves the signer public key PEM  (for RPi-side verify)
  [6] Updates firmware-metadata.json with:
        ldr_sha256     – SHA-256 of the .ldr file
        hsm_signature  – hex-encoded DER signature bytes
        hsm_key_id     – full KMS key-version resource name
        hsm_algorithm  – key algorithm reported by KMS
        sig_file       – absolute path to .sig file
        pubkey_file    – absolute path to public key PEM

Raspberry Pi offline verification (OpenSSL, RSA-PSS 2048):
    openssl dgst -sha256 \\
        -sigopt rsa_padding_mode:pss \\
        -sigopt rsa_pss_saltlen:-1 \\
        -verify  <pubkey_file> \\
        -signature <sig_file> \\
        RPIF_<version>.ldr

Usage:
    python3 Build_image/sign_firmware.py [PROJECT_DIR]
    PROJECT_DIR defaults to /home/ubuntu/raceiotprj

Environment variables (all optional — have sensible defaults):
    GOOGLE_APPLICATION_CREDENTIALS
        Path to GCP service-account JSON.
        Default: <PROJECT_DIR>/Google-HSM-Sign/firmware-signer-key.json

    GCP_PROJECT      GCP project ID          (default: read from service-account JSON)
    GCP_LOCATION     KMS location            (default: global)
    GCP_KEYRING      KMS key ring name       (default: firmware-signing)
    GCP_KEY_NAME     KMS key name            (default: firmware-key)
    GCP_KEY_VERSION  Key version number      (default: 1)
"""

import sys
import os
import json
import hashlib
import warnings

# Suppress google-cloud FutureWarnings about Python version end-of-life
warnings.filterwarnings("ignore", category=FutureWarning)

# ─────────────────────────────────────────────────────────────────────────────
# Resolve project root
# ─────────────────────────────────────────────────────────────────────────────
PROJECT_DIR     = os.path.abspath(sys.argv[1] if len(sys.argv) > 1
                                  else "/home/ubuntu/raceiotprj")
BUILD_IMAGE_DIR = os.path.join(PROJECT_DIR, "Build_image")
METADATA_PATH   = os.path.join(BUILD_IMAGE_DIR, "firmware-metadata.json")
DEFAULT_SA_JSON = os.path.join(PROJECT_DIR, "Google-HSM-Sign",
                               "firmware-signer-key.json")

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def log(msg):  print(f"[{_ts()}] {msg}")
def ok(msg):   print(f"[{_ts()}] ✔  {msg}")
def warn(msg): print(f"[{_ts()}] ⚠  {msg}", file=sys.stderr)
def err(msg):
    print(f"[{_ts()}] ✘  {msg}", file=sys.stderr)
    sys.exit(1)

def _ts():
    import datetime
    return datetime.datetime.now().strftime("%H:%M:%S")


def sha256_file(path: str) -> bytes:
    """Return raw 32-byte SHA-256 digest of a file (streaming 1 MB chunks)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────
def main():
    print()
    print("=" * 62)
    print("  IoT Gateway — Google Cloud KMS Firmware Signer")
    print("=" * 62)
    print(f"  Project dir : {PROJECT_DIR}")
    print()

    # ── [1] Load firmware-metadata.json ──────────────────────────────────────
    log("[1/6] Loading firmware-metadata.json...")
    if not os.path.exists(METADATA_PATH):
        err(f"firmware-metadata.json not found at {METADATA_PATH}\n"
            "       Run Build_image/build_image.sh first.")

    with open(METADATA_PATH) as f:
        meta = json.load(f)

    ldr_path = meta.get("final_image_path", "")
    if not ldr_path or not os.path.exists(ldr_path):
        err(f"final_image_path not found in metadata or file missing: {ldr_path}\n"
            "       Run Build_image/build_image.sh first (step 12 must complete).")

    fw_version = meta.get("firmware_version", "unknown")
    ok(f"Firmware version : {fw_version}")
    ok(f"LDR file         : {ldr_path}")
    print()

    # ── [2] Compute SHA-256 of the .ldr file ─────────────────────────────────
    log("[2/6] Computing SHA-256 of RPIF .ldr file...")
    ldr_digest_raw = sha256_file(ldr_path)
    ldr_sha256_hex = ldr_digest_raw.hex()
    ok(f"SHA-256 : {ldr_sha256_hex}")
    print()

    # ── [3] Resolve GCP credentials + KMS config ─────────────────────────────
    log("[3/6] Resolving GCP credentials and KMS configuration...")

    sa_json_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", DEFAULT_SA_JSON)
    if not os.path.exists(sa_json_path):
        err(f"Service-account JSON not found: {sa_json_path}\n"
            "       Set GOOGLE_APPLICATION_CREDENTIALS or place the file at:\n"
            f"       {DEFAULT_SA_JSON}")

    # Point the GCP SDK at the service-account file
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = sa_json_path
    ok(f"Credentials : {sa_json_path}")

    # Read project from service-account JSON if not overridden by env
    with open(sa_json_path) as f:
        sa_data = json.load(f)

    gcp_project  = os.environ.get("GCP_PROJECT",     sa_data.get("project_id", ""))
    gcp_location = os.environ.get("GCP_LOCATION",    "global")
    gcp_keyring  = os.environ.get("GCP_KEYRING",     "firmware-signing")
    gcp_key      = os.environ.get("GCP_KEY_NAME",    "firmware-key")
    gcp_version  = os.environ.get("GCP_KEY_VERSION", "1")

    if not gcp_project:
        err("GCP project ID could not be determined.\n"
            "       Set GCP_PROJECT env var or ensure project_id is in the "
            "service-account JSON.")

    ok(f"GCP project  : {gcp_project}")
    ok(f"KMS location : {gcp_location}")
    ok(f"Key ring     : {gcp_keyring}")
    ok(f"Key name     : {gcp_key}  (version {gcp_version})")
    print()

    # ── [4] Call Cloud KMS AsymmetricSign ────────────────────────────────────
    log("[4/6] Calling Google Cloud KMS AsymmetricSign...")

    try:
        from google.cloud import kms as gcp_kms
    except ImportError:
        err("google-cloud-kms not installed.\n"
            "       Run: pip3 install google-cloud-kms")

    client = gcp_kms.KeyManagementServiceClient()
    key_version_name = client.crypto_key_version_path(
        gcp_project, gcp_location, gcp_keyring, gcp_key, gcp_version
    )

    # Fetch key metadata to log the algorithm
    try:
        pub_key_obj  = client.get_public_key(request={"name": key_version_name})
        algorithm    = pub_key_obj.algorithm.name      # e.g. RSA_SIGN_PSS_2048_SHA256
        pubkey_pem   = pub_key_obj.pem                 # PEM string
    except Exception as exc:
        err(f"Failed to fetch public key from KMS: {exc}\n"
            "       Check GCP_PROJECT / GCP_KEYRING / GCP_KEY_NAME / GCP_KEY_VERSION\n"
            "       and ensure the service account has roles/cloudkms.signerVerifier.")

    ok(f"HSM key      : {key_version_name}")
    ok(f"Algorithm    : {algorithm}")

    # Sign the SHA-256 digest of the .ldr file
    digest_proto = gcp_kms.Digest(sha256=ldr_digest_raw)
    try:
        sign_response = client.asymmetric_sign(
            request={"name": key_version_name, "digest": digest_proto}
        )
    except Exception as exc:
        err(f"AsymmetricSign API call failed: {exc}")

    sig_bytes    = sign_response.signature
    sig_hex      = sig_bytes.hex()
    ok(f"Signature    : {sig_hex[:48]}...  ({len(sig_bytes)} bytes DER)")
    print()

    # ── [5] Write .sig file + public key PEM ─────────────────────────────────
    log("[5/6] Writing signature and public key files...")

    sig_file    = ldr_path + ".sig"
    pubkey_file = os.path.join(BUILD_IMAGE_DIR, "fw-signer-pubkey.pem")

    with open(sig_file, "wb") as f:
        f.write(sig_bytes)
    ok(f"Signature file : {sig_file}  ({len(sig_bytes)} bytes)")

    with open(pubkey_file, "w") as f:
        f.write(pubkey_pem)
    ok(f"Public key PEM : {pubkey_file}")
    print()

    # ── [6] Update firmware-metadata.json ────────────────────────────────────
    log("[6/6] Updating firmware-metadata.json...")

    meta["ldr_sha256"]    = ldr_sha256_hex
    meta["hsm_signature"] = sig_hex
    meta["hsm_key_id"]    = key_version_name
    meta["hsm_algorithm"] = algorithm
    meta["sig_file"]      = sig_file
    meta["pubkey_file"]   = pubkey_file

    with open(METADATA_PATH, "w") as f:
        json.dump(meta, f, indent=2)

    ok(f"firmware-metadata.json updated")
    print()

    # ── Summary ───────────────────────────────────────────────────────────────
    print("=" * 62)
    print("  KMS Signing — COMPLETE")
    print("=" * 62)
    print(f"  LDR file       : {ldr_path}")
    print(f"  ldr_sha256     : {ldr_sha256_hex}")
    print(f"  hsm_key_id     : {key_version_name}")
    print(f"  hsm_algorithm  : {algorithm}")
    print(f"  hsm_signature  : {sig_hex[:48]}...")
    print(f"  sig_file       : {sig_file}")
    print(f"  pubkey_file    : {pubkey_file}")
    print()
    print("  Offline verification (OpenSSL):")
    print(f"    openssl dgst -sha256 \\")
    print(f"        -sigopt rsa_padding_mode:pss \\")
    print(f"        -sigopt rsa_pss_saltlen:-1 \\")
    print(f"        -verify  {pubkey_file} \\")
    print(f"        -signature {sig_file} \\")
    print(f"        {ldr_path}")
    print("=" * 62)
    print()


if __name__ == "__main__":
    main()
