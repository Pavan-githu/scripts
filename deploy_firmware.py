#!/usr/bin/env python3
"""
deploy_firmware.py
------------------
Full pipeline for building and deploying IoT gateway firmware.

Steps:
  1. cd to project root and run: source sources/poky/oe-init-build-env
  2. Run: bitbake core-image-minimal
  3. Verify build succeeded (check Tasks Summary line in log)
  4. Find the built .wic.bz2 image in DEPLOYDIR
  5. Compute SHA-256 + file size
  6. Sign the firmware image digest via Google Cloud KMS (HSM-backed key)
  7. Create a GitHub Release, upload the image + detached signature → get download URL
  8. ABI-encode + send registerFirmware() to blockchain via JSON-RPC
  9. Write /tmp/firmware-meta.json for baking onto SD card

Dependencies:
    pip install eth-account requests google-cloud-kms

Environment variables (required at runtime):
    RPC_URL          Ethereum JSON-RPC, e.g. http://127.0.0.1:8545
    CONTRACT_ADDR    Deployed IoTFirmwareRegistry contract address (0x...)
    SIGNER_KEY       Ethereum private key of build host / CI signer (0x...)
    GITHUB_TOKEN     GitHub personal access token (repo scope)
    VERSION          Firmware version string, e.g. 0.1.0  (default: 0.1.0)

    -- Google Cloud KMS (HSM signing) --
    GCP_PROJECT      GCP project ID, e.g. my-iot-project
    GCP_LOCATION     KMS location,   e.g. global  (default: global)
    GCP_KEYRING      KMS key ring,   e.g. firmware-signing
    GCP_KEY_NAME     KMS key name,   e.g. firmware-key
    GCP_KEY_VERSION  Key version number (default: 1)
    GOOGLE_APPLICATION_CREDENTIALS  Path to service-account JSON (if not on GCE)

    One-time GCP KMS setup:
        gcloud kms keyrings create firmware-signing --location=global
        gcloud kms keys create firmware-key \
            --keyring=firmware-signing --location=global \
            --purpose=asymmetric-signing \
            --default-algorithm=rsa-sign-pss-2048-sha256 \
            --protection-level=hsm

Usage:
    cd /home/pg3930/capstone1/raceiotprj
    export RPC_URL="http://127.0.0.1:8545"
    export CONTRACT_ADDR="0xYourContractAddress"
    export SIGNER_KEY="0xYourPrivateKey"
    export GITHUB_TOKEN="ghp_yourtoken"
    python3 scripts/deploy_firmware.py
"""

import os
import sys
import re
import json
import time
import hashlib
import subprocess
import tempfile
import requests
from eth_account import Account
from eth_hash.auto import keccak

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────

PROJECT_ROOT = "/home/pg3930/capstone1/raceiotprj"
OE_INIT      = os.path.join(PROJECT_ROOT, "sources/poky/oe-init-build-env")
DEPLOY_DIR   = os.path.join(PROJECT_ROOT,
               "build/tmp/deploy/images/raspberrypi3")
IMAGE_RECIPE = "core-image-minimal"
BOARD        = "raspberrypi3"

# ─────────────────────────────────────────────────────────────────────────────
# Config from environment
# ─────────────────────────────────────────────────────────────────────────────

RPC_URL       = os.environ.get("RPC_URL",       "http://127.0.0.1:8545")
CONTRACT_ADDR = os.environ.get("CONTRACT_ADDR", "0xYOUR_CONTRACT_ADDRESS")
SIGNER_KEY    = os.environ.get("SIGNER_KEY",    "")
GITHUB_TOKEN  = os.environ.get("GITHUB_TOKEN",  "")
GITHUB_REPO   = "Pavan-githu/meta-userapp-package"
# Read version from the iot-gateway VERSION file (first line only);
# env var overrides if set.
_VERSION_FILE = os.path.join(
    PROJECT_ROOT,
    "sources/meta-userapp-package/recipes-apps/iot-gateway/VERSION"
)
_version_from_file = (
    open(_VERSION_FILE).readline().strip()
    if os.path.exists(_VERSION_FILE) else "0.1.0"
)
VERSION       = os.environ.get("VERSION", _version_from_file)

# ─────────────────────────────────────────────────────────────────────────────
# Google Cloud KMS (HSM signing) config
# ─────────────────────────────────────────────────────────────────────────────

GCP_PROJECT     = os.environ.get("GCP_PROJECT",     "")
GCP_LOCATION    = os.environ.get("GCP_LOCATION",    "global")
GCP_KEYRING     = os.environ.get("GCP_KEYRING",     "firmware-signing")
GCP_KEY_NAME    = os.environ.get("GCP_KEY_NAME",    "firmware-key")
GCP_KEY_VERSION = os.environ.get("GCP_KEY_VERSION", "1")

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 + 2 + 3: Build with bitbake and verify success
# ─────────────────────────────────────────────────────────────────────────────

def run_bitbake_build() -> None:
    """
    Sources oe-init-build-env and runs bitbake core-image-minimal inside
    a single bash -c call (required because oe-init-build-env uses 'source').
    Streams output live. Raises RuntimeError if build fails.
    """
    print(f"[1/6] Sourcing OE environment and building {IMAGE_RECIPE}...")
    print(f"      Project root : {PROJECT_ROOT}")
    print(f"      OE init      : {OE_INIT}")
    print()

    # Build the shell command:
    #   cd <project_root>
    #   source sources/poky/oe-init-build-env   (changes cwd to build/)
    #   bitbake core-image-minimal
    cmd = (
        f"cd {PROJECT_ROOT} && "
        f"source {OE_INIT} && "
        f"bitbake {IMAGE_RECIPE}"
    )

    # Use a temp file to capture full log for success-pattern checking
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log",
                                    delete=False) as logfile:
        log_path = logfile.name

    try:
        proc = subprocess.Popen(
            ["bash", "-c", cmd],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        success_line = None
        with open(log_path, "w") as lf:
            for line in proc.stdout:
                print(line, end="", flush=True)
                lf.write(line)
                # Track the Tasks Summary line
                if "Tasks Summary:" in line and "all succeeded" in line:
                    success_line = line.strip()

        proc.wait()

    except Exception as e:
        raise RuntimeError(f"Failed to launch build process: {e}")

    # ── Verify build success ──────────────────────────────────────────────────
    print()
    if proc.returncode != 0:
        raise RuntimeError(
            f"bitbake exited with code {proc.returncode}. "
            f"Check log: {log_path}"
        )

    # Expected pattern:
    #   NOTE: Tasks Summary: Attempted 3823 tasks of which 3823 didn't need
    #         to be rerun and all succeeded.
    if success_line is None:
        # Search saved log as fallback
        with open(log_path) as lf:
            for line in lf:
                if "Tasks Summary:" in line and "all succeeded" in line:
                    success_line = line.strip()
                    break

    if success_line is None:
        raise RuntimeError(
            "Build may have failed — could not find success summary line:\n"
            '  "NOTE: Tasks Summary: Attempted X tasks ... all succeeded."\n'
            f"Check full log: {log_path}"
        )

    print(f"[1/6] Build verified: {success_line}")
    os.unlink(log_path)


# ─────────────────────────────────────────────────────────────────────────────
# Step 4: Find the built image
# ─────────────────────────────────────────────────────────────────────────────

def find_image() -> tuple[str, str]:
    """
    Returns (full_path, filename) of the most recently modified .wic.bz2
    image in DEPLOY_DIR.
    """
    print(f"[2/6] Locating firmware image in {DEPLOY_DIR} ...")
    candidates = [
        f for f in os.listdir(DEPLOY_DIR)
        if f.endswith(".wic.bz2") and IMAGE_RECIPE in f
    ]
    if not candidates:
        raise RuntimeError(f"No .wic.bz2 image found in {DEPLOY_DIR}")

    # Pick the one with the latest mtime (in case there are symlinks + timestamped)
    candidates.sort(
        key=lambda f: os.path.getmtime(os.path.join(DEPLOY_DIR, f)),
        reverse=True
    )
    filename  = candidates[0]
    full_path = os.path.join(DEPLOY_DIR, filename)
    print(f"      Found: {filename}")
    return full_path, filename


# ─────────────────────────────────────────────────────────────────────────────
# Step 5: Compute metadata
# ─────────────────────────────────────────────────────────────────────────────

def compute_metadata(image_path: str) -> dict:
    """SHA-256 + file size + firmware_id + git commit."""
    print("[3/6] Computing metadata...")

    sha256  = hashlib.sha256()
    size    = 0
    with open(image_path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):   # 1 MB chunks
            sha256.update(chunk)
            size += len(chunk)

    sha256_hex = sha256.hexdigest()
    build_ts   = int(time.time())

    # git commit from the meta layer
    try:
        commit = subprocess.check_output(
            ["git", "-C", PROJECT_ROOT, "rev-parse", "HEAD"],
            stderr=subprocess.DEVNULL
        ).decode().strip()
    except Exception:
        commit = "unknown"

    # firmware_id = keccak256(version || build_ts || git_commit)
    firmware_id_bytes = keccak(f"{VERSION}{build_ts}{commit}".encode("utf-8"))
    firmware_id_hex   = firmware_id_bytes.hex()

    meta = {
        "firmware_id_bytes": firmware_id_bytes,
        "firmware_id":       f"0x{firmware_id_hex}",
        "sha256":            sha256_hex,
        "sha256_bytes":      bytes.fromhex(sha256_hex),
        "file_size":         size,
        "build_ts":          build_ts,
        "git_commit":        commit,
        "version":           VERSION,
        "board":             BOARD,
        "image_recipe":      IMAGE_RECIPE,
    }

    print(f"      firmware_id : 0x{firmware_id_hex}")
    print(f"      sha256      : {sha256_hex}")
    print(f"      size        : {size:,} bytes")
    print(f"      git_commit  : {commit[:12]}")
    print(f"      build_ts    : {build_ts}")
    return meta


# ─────────────────────────────────────────────────────────────────────────────
# Step 4 (new): Sign firmware with Google Cloud KMS (HSM-backed)
# ─────────────────────────────────────────────────────────────────────────────

def sign_firmware_hsm(image_path: str, sha256_bytes: bytes) -> tuple[bytes, str]:
    """
    Signs the firmware image's SHA-256 digest using a Google Cloud KMS
    HSM-backed RSA-PSS 2048-bit key (RSA_SIGN_PSS_2048_SHA256).
    The private key never leaves the HSM.

    The detached DER-encoded signature is written next to the image:
        <image_path>.sig

    To verify offline (RSA-PSS 2048 example):
        # export public key once:
        gcloud kms keys versions get-public-key 1 \\
            --keyring=$GCP_KEYRING --location=$GCP_LOCATION \\
            --key=$GCP_KEY_NAME --output-file=firmware-pubkey.pem
        # verify:
        openssl dgst -sha256 -sigopt rsa_padding_mode:pss \\
            -sigopt rsa_pss_saltlen:-1 \\
            -verify firmware-pubkey.pem \\
            -signature <image>.wic.bz2.sig <image>.wic.bz2

    Returns (signature_bytes, sig_file_path).
    """
    try:
        from google.cloud import kms as gcp_kms
    except ImportError:
        raise RuntimeError(
            "google-cloud-kms not installed. "
            "Run: pip install google-cloud-kms"
        )

    print("[4/6] Signing firmware with Google Cloud KMS (HSM)...")

    if not all([GCP_PROJECT, GCP_KEYRING, GCP_KEY_NAME]):
        raise RuntimeError(
            "Set GCP_PROJECT, GCP_KEYRING, and GCP_KEY_NAME "
            "environment variables to enable HSM signing."
        )

    client = gcp_kms.KeyManagementServiceClient()
    key_version_name = client.crypto_key_version_path(
        GCP_PROJECT, GCP_LOCATION, GCP_KEYRING, GCP_KEY_NAME, GCP_KEY_VERSION
    )

    # Fetch key metadata so we can show the algorithm
    pub_key = client.get_public_key(request={"name": key_version_name})
    print(f"      HSM Key      : {key_version_name}")
    print(f"      Algorithm    : {pub_key.algorithm.name}")
    print(f"      Digest (hex) : {sha256_bytes.hex()}")

    # Sign — the digest type (sha256) must match the key algorithm
    digest   = gcp_kms.Digest(sha256=sha256_bytes)
    response = client.asymmetric_sign(
        request={"name": key_version_name, "digest": digest}
    )

    signature_bytes = response.signature
    sig_path        = image_path + ".sig"
    with open(sig_path, "wb") as f:
        f.write(signature_bytes)

    print(f"      Signature    : {signature_bytes.hex()[:48]}...")
    print(f"      Sig file     : {sig_path}")
    return signature_bytes, sig_path


# ─────────────────────────────────────────────────────────────────────────────
# Step 5 (was 4): GitHub Release + upload
# ─────────────────────────────────────────────────────────────────────────────

GH_API = "https://api.github.com"

def gh_headers() -> dict:
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
    }

def upload_to_github(image_path: str, filename: str, meta: dict,
                     sig_path: str | None = None) -> str:
    """Create GitHub release, upload image (+ optional .sig), return browser_download_url."""
    print("[5/6] Creating GitHub Release and uploading image...")

    tag      = f"v{VERSION}-{meta['build_ts']}"
    rel_name = f"Firmware v{VERSION} ({BOARD})"
    rel_body = (
        f"Recipe   : {IMAGE_RECIPE}\n"
        f"Board    : {BOARD}\n"
        f"Version  : {VERSION}\n"
        f"Commit   : {meta['git_commit']}\n"
        f"SHA-256  : {meta['sha256']}\n"
        f"Size     : {meta['file_size']:,} bytes\n"
        f"Built at : {meta['build_ts']}"
    )

    r = requests.post(
        f"{GH_API}/repos/{GITHUB_REPO}/releases",
        headers=gh_headers(),
        json={"tag_name": tag, "name": rel_name, "body": rel_body,
              "draft": False, "prerelease": False},
        timeout=30,
    )
    r.raise_for_status()
    release = r.json()

    upload_url = release["upload_url"].split("{")[0]  # strip {?name,label}
    print(f"      Release created: {release['html_url']}")
    print(f"      Uploading {filename} ({meta['file_size']:,} bytes) ...")

    with open(image_path, "rb") as f:
        r2 = requests.post(
            upload_url,
            headers={**gh_headers(), "Content-Type": "application/octet-stream"},
            params={"name": filename},
            data=f,
            timeout=600,   # large file — up to 10 minutes
        )
    r2.raise_for_status()

    download_url = r2.json()["browser_download_url"]
    print(f"      Download URL: {download_url}")

    # Upload detached HSM signature alongside the image
    if sig_path and os.path.exists(sig_path):
        sig_filename = os.path.basename(sig_path)
        print(f"      Uploading signature {sig_filename} ...")
        with open(sig_path, "rb") as f:
            r3 = requests.post(
                upload_url,
                headers={**gh_headers(),
                         "Content-Type": "application/octet-stream"},
                params={"name": sig_filename},
                data=f,
                timeout=30,
            )
        r3.raise_for_status()
        print(f"      Sig URL      : {r3.json()['browser_download_url']}")

    return download_url


# ─────────────────────────────────────────────────────────────────────────────
# Step 7: ABI encoding + blockchain registration
# ─────────────────────────────────────────────────────────────────────────────

def left_pad32(hex_str: str) -> str:
    return hex_str.lstrip("0x").zfill(64)

def right_pad32(hex_str: str) -> str:
    return hex_str.lstrip("0x").ljust(64, "0")

def uint256_word(n: int) -> str:
    return left_pad32(hex(n)[2:])

def func_selector(sig: str) -> str:
    return keccak(sig.encode("utf-8")).hex()[:8]

def encode_string_abi(s: str) -> str:
    """ABI-encode a dynamic string: length_word + right-padded data."""
    data         = s.encode("utf-8")
    length_word  = uint256_word(len(data))
    padded_data  = data.hex().ljust(((len(data) + 31) // 32) * 64, "0")
    return length_word + padded_data

def build_register_calldata(meta: dict, download_url: str) -> str:
    """
    ABI-encode: registerFirmware(bytes32,bytes32,bytes32,uint256,uint256,string)
      [0:4]    selector
      [4:36]   bytes32 firmware_id
      [36:68]  bytes32 name          (right-padded ASCII "iot-gateway")
      [68:100] bytes32 sha256
      [100:132]uint256 file_size
      [132:164]uint256 build_ts
      [164:196]uint256 offset → 0xC0 (192)  -- points to string data
      [196:... ]string download_url (length + data)
    """
    sel      = func_selector(
        "registerFirmware(bytes32,bytes32,bytes32,uint256,uint256,string)")
    fid      = right_pad32(meta["firmware_id_bytes"].hex())
    name     = "iot-gateway".encode("utf-8").ljust(32, b"\x00").hex()
    sha      = right_pad32(meta["sha256_bytes"].hex())
    fsize    = uint256_word(meta["file_size"])
    bts      = uint256_word(meta["build_ts"])
    offset   = uint256_word(192)    # 6 static words × 32 = 192 bytes
    url_data = encode_string_abi(download_url)

    return "0x" + sel + fid + name + sha + fsize + bts + offset + url_data

def rpc_call(method: str, params: list) -> dict:
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    r = requests.post(RPC_URL, json=payload, timeout=10)
    r.raise_for_status()
    return r.json()

def register_on_blockchain(meta: dict, download_url: str) -> str:
    """Sign and broadcast registerFirmware tx. Returns tx hash."""
    print("[6/6] Registering metadata on blockchain...")

    calldata  = build_register_calldata(meta, download_url)
    acct      = Account.from_key(SIGNER_KEY)
    nonce     = int(rpc_call("eth_getTransactionCount",
                              [acct.address, "latest"])["result"], 16)
    gas_price = int(rpc_call("eth_gasPrice", [])["result"], 16)
    chain_id  = int(rpc_call("eth_chainId",  [])["result"], 16)

    tx = {
        "to":       CONTRACT_ADDR,
        "value":    0,
        "gas":      300_000,
        "gasPrice": gas_price,
        "nonce":    nonce,
        "data":     calldata,
        "chainId":  chain_id,
    }

    signed = acct.sign_transaction(tx)
    res    = rpc_call("eth_sendRawTransaction", [signed.raw_transaction.hex()])

    if "error" in res:
        raise RuntimeError(f"Blockchain rejected tx: {res['error']}")

    tx_hash = res["result"]
    print(f"      TX hash : {tx_hash}")
    print(f"      Signer  : {acct.address}")
    print(f"      Chain   : {chain_id}")
    return tx_hash


# ─────────────────────────────────────────────────────────────────────────────
# Write on-device meta
# ─────────────────────────────────────────────────────────────────────────────

def write_device_meta(meta: dict, download_url: str, tx_hash: str,
                      signature_hex: str | None = None) -> None:
    record = {
        "firmware_id":   meta["firmware_id"],
        "sha256":        meta["sha256"],
        "version":       meta["version"],
        "download_url":  download_url,
        "tx_hash":       tx_hash,
    }
    if signature_hex:
        record["hsm_signature"] = signature_hex
        record["hsm_key"] = (
            f"projects/{GCP_PROJECT}/locations/{GCP_LOCATION}"
            f"/keyRings/{GCP_KEYRING}/cryptoKeys/{GCP_KEY_NAME}"
            f"/cryptoKeyVersions/{GCP_KEY_VERSION}"
        )
    out = "/tmp/firmware-meta.json"
    with open(out, "w") as f:
        json.dump(record, f, indent=2)
    print(f"\n  On-device meta written to {out}")
    print(f"  Copy to /etc/firmware-meta.json on the SD card before flashing.")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    # Validate required env vars
    missing = [v for v in ("SIGNER_KEY", "GITHUB_TOKEN", "CONTRACT_ADDR",
                           "GCP_PROJECT", "GCP_KEYRING", "GCP_KEY_NAME")
               if not os.environ.get(v)]
    if missing:
        print("ERROR: set these environment variables before running:")
        for v in missing:
            print(f"  export {v}=...")
        sys.exit(1)

    print("=" * 60)
    print("  IoT Gateway Firmware Build + Deploy Pipeline")
    print("=" * 60)
    print()

    # Step 1/2/3 — build + verify
    run_bitbake_build()
    print()

    # Step 2 — find image
    image_path, filename = find_image()
    print()

    # Step 3 — compute metadata
    meta = compute_metadata(image_path)
    print()

    # Step 4 — HSM signing
    sig_bytes, sig_path = sign_firmware_hsm(image_path, meta["sha256_bytes"])
    signature_hex = sig_bytes.hex()
    print()

    # Step 5 — GitHub release + upload (image + .sig)
    download_url = upload_to_github(image_path, filename, meta, sig_path)
    print()

    # Step 6 — blockchain registration
    tx_hash = register_on_blockchain(meta, download_url)
    print()

    # Write on-device meta
    write_device_meta(meta, download_url, tx_hash, signature_hex)

    print()
    print("=" * 60)
    print("  Pipeline complete.")
    print(f"  firmware_id  : {meta['firmware_id']}")
    print(f"  HSM sig      : {signature_hex[:32]}...")
    print(f"  GitHub URL   : {download_url}")
    print(f"  TX hash      : {tx_hash}")
    print("=" * 60)


if __name__ == "__main__":
    main()
