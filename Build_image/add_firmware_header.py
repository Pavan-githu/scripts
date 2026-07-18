#!/usr/bin/env python3
"""
Build_image/add_firmware_header.py
-----------------------------------
Prepends a compact binary header to the Yocto .wic.bz2 image, producing a
single-file firmware package:

    final_image.ldr  =  [ HEADER  84 bytes ]  +  [ .wic.bz2 payload ]  +  [ RPIS tail  264 bytes ]

Header layout  (all integers little-endian, total = 84 bytes):

    Offset   Size  Type      Field          Description
    ──────   ────  ────────  ─────────────  ────────────────────────────────────
       0       4   bytes     magic          b"RPIF"  (RasPi Image Firmware)
       4       2   uint16    hdr_version    = 2
       6       2   uint16    hdr_size       = 84
       8      32   char[32]  fw_version     null-padded ASCII  e.g. "v0.1.0"
      40      32   bytes     sha256         raw 32-byte SHA-256 of .wic.bz2 payload
      72       8   uint64    payload_size   size of .wic.bz2 in bytes
      80       4   uint32    hdr_crc32      CRC32 of header bytes [0 .. 79]
    ──────────────────────────────────────────────────────────────────────────
      84     ...   bytes     payload        the .wic.bz2 image
    84+N     264   bytes     RPIS tail      optional signature tail (see below)

RPIS Signature Tail layout  (appended after payload, 264 bytes):

    Offset   Size  Type      Field          Description
    ──────   ────  ────────  ─────────────  ────────────────────────────────────
       0       4   bytes     magic          b"RPIS"  (RPIF Signature)
       4       2   uint16    sig_alg        1 = RSA_SIGN_PSS_2048_SHA256
       6       2   uint16    sig_len        actual signature bytes used (≤ 256)
       8     256   bytes     signature      DER-encoded HSM signature
    ──────────────────────────────────────────────────────────────────────────
     264             total tail size

    Signs:   header.sha256  (the 32-byte SHA-256 of the .wic.bz2 payload)
    Key:     GCP KMS key identified by signer_identity on blockchain

Raspberry Pi verification steps:

    1. Read first 84 bytes → parse header
    2. Assert  header.magic       == b"RPIF"
    3. Assert  header.hdr_version == 2
    4. Assert  crc32(header[0:80]) == header.hdr_crc32            (header intact)
    5. Assert  header.fw_version  > current_device_version        (rollback check)
    6. Compare header.fw_version  == blockchain["firmware_version"] (version match)
    7. Read next header.payload_size bytes → .wic.bz2 payload
    8. Assert  sha256(payload)    == header.sha256                (payload intact)
    9. If 264 bytes remain after payload:
         Assert  tail.magic       == b"RPIS"
         Fetch GCP KMS public key for signer_identity (from blockchain)
         Assert  verify(tail.signature[:tail.sig_len], header.sha256, pubkey)
   10. All assertions pass → image is authentic → proceed with flash

C struct reference for the RPi-side verifier (https_server.cpp / OTA updater):

    #include <stdint.h>
    #define FW_MAGIC     "RPIF"
    #define HDR_VERSION  2
    #define HDR_SIZE     84

    typedef struct __attribute__((packed)) {
        uint8_t  magic[4];       /* "RPIF"                           */
        uint16_t hdr_version;    /* 2                                */
        uint16_t hdr_size;       /* 84                               */
        char     fw_version[32]; /* e.g. "v0.1.0\\0..."               */
        uint8_t  sha256[32];     /* raw SHA-256 digest of payload    */
        uint64_t payload_size;   /* bytes                            */
        uint32_t hdr_crc32;      /* crc32 of header[0..79]           */
    } FirmwareHeader;            /* sizeof = 84                      */

    /* RPIS Signature Tail (264 bytes, appended after payload) */
    #define RPIS_MAGIC      "RPIS"
    #define RPIS_TAIL_SIZE  264

    typedef struct __attribute__((packed)) {
        uint8_t  magic[4];       /* "RPIS"                           */
        uint16_t sig_alg;        /* 1 = RSA_SIGN_PSS_2048_SHA256     */
        uint16_t sig_len;        /* actual sig bytes used (≤ 256)    */
        uint8_t  signature[256]; /* DER-encoded HSM signature        */
    } RPISTail;                  /* sizeof = 264                     */

Usage:
    python3 Build_image/add_firmware_header.py [PROJECT_DIR]

    PROJECT_DIR defaults to /home/ubuntu/raceiotprj
"""

import sys
import os
import struct
import hashlib
import json
import zlib


# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

MAGIC           = b"RPIF"
HDR_VERSION     = 2
HDR_SIZE        = 84    # bytes

# struct format: little-endian, fixed 84 bytes
#   4s  magic
#   H   hdr_version (uint16)
#   H   hdr_size    (uint16)
#   32s fw_version  (char[32])
#   32s sha256      (bytes[32])
#   Q   payload_size(uint64)
#   I   hdr_crc32   (uint32)  — covers bytes [0..79]
HEADER_STRUCT   = struct.Struct("<4s H H 32s 32s Q I")
assert HEADER_STRUCT.size == HDR_SIZE, f"Header struct size mismatch: {HEADER_STRUCT.size}"

# Bytes covered by the CRC (everything except the last 4-byte crc32 field)
HDR_CRC_BYTES   = HDR_SIZE - 4   # 80

# RPIS signature tail constants
RPIS_MAGIC           = b"RPIS"
RPIS_TAIL_SIZE       = 264   # 4 magic + 2 sig_alg + 2 sig_len + 256 signature
SIG_ALG_RSA_PSS_2048 = 1


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def encode_field(s: str, size: int) -> bytes:
    """Encode a string to a fixed-size null-padded bytes field."""
    b = s.encode("ascii")
    if len(b) > size:
        raise ValueError(f"Field '{s}' is {len(b)} bytes, max {size}")
    return b.ljust(size, b"\x00")


def sha256_of_file(path: str) -> bytes:
    """Return raw 32-byte SHA-256 digest of file contents (streaming, 1 MB chunks)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.digest()


def build_header(fw_version: str,
                 sha256_raw: bytes, payload_size: int) -> bytes:
    """
    Pack the 84-byte firmware header (hdr_version=2, no timestamp field).
    hdr_crc32 covers bytes [0..79] (all fields except the CRC field itself).
    """
    # Pack with placeholder CRC = 0 first to compute the actual CRC
    hdr_no_crc = HEADER_STRUCT.pack(
        MAGIC,
        HDR_VERSION,
        HDR_SIZE,
        encode_field(fw_version, 32),
        sha256_raw,
        payload_size,
        0,              # placeholder CRC
    )
    crc = zlib.crc32(hdr_no_crc[:HDR_CRC_BYTES]) & 0xFFFFFFFF

    # Repack with real CRC
    return HEADER_STRUCT.pack(
        MAGIC,
        HDR_VERSION,
        HDR_SIZE,
        encode_field(fw_version, 32),
        sha256_raw,
        payload_size,
        crc,
    )


def verify_header(data: bytes) -> dict:
    """Parse and self-verify an 84-byte header blob. Returns field dict."""
    if len(data) < HDR_SIZE:
        raise ValueError(f"Data too short: {len(data)} < {HDR_SIZE}")

    (magic, hdr_ver, hdr_sz,
     fw_ver_b, sha256_raw,
     payload_size, stored_crc) = HEADER_STRUCT.unpack(data[:HDR_SIZE])

    if magic != MAGIC:
        raise ValueError(f"Bad magic: {magic!r}, expected {MAGIC!r}")

    if hdr_ver != HDR_VERSION:
        raise ValueError(f"Unsupported hdr_version: {hdr_ver}, expected {HDR_VERSION}")

    computed_crc = zlib.crc32(data[:HDR_CRC_BYTES]) & 0xFFFFFFFF
    if computed_crc != stored_crc:
        raise ValueError(
            f"Header CRC32 mismatch: computed 0x{computed_crc:08x}, "
            f"stored 0x{stored_crc:08x}"
        )

    return {
        "hdr_version":  hdr_ver,
        "hdr_size":     hdr_sz,
        "fw_version":   fw_ver_b.rstrip(b"\x00").decode("ascii"),
        "sha256_hex":   sha256_raw.hex(),
        "payload_size": payload_size,
        "hdr_crc32":    f"0x{stored_crc:08x}",
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    _script_dir = os.path.dirname(os.path.abspath(__file__))
    _default_project_dir = os.path.abspath(os.path.join(_script_dir, "..", ".."))
    project_dir = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else _default_project_dir)

    build_image_dir = os.path.join(project_dir, "scripts", "Build_image")
    metadata_path   = os.path.join(build_image_dir, "firmware-metadata.json")
    deploy_dir      = os.path.join(project_dir,
                                   "build", "tmp", "deploy", "images", "raspberrypi3")

    # ── Load metadata ─────────────────────────────────────────────────────────
    if not os.path.exists(metadata_path):
        print(f"ERROR: firmware-metadata.json not found at {metadata_path}")
        print("       Run Build_image/build_image.sh first.")
        sys.exit(1)

    with open(metadata_path) as f:
        meta = json.load(f)

    fw_version   = meta["firmware_version"]   # e.g. "v0.1.0"
    img_filename = meta["image_filename"]     # e.g. "core-image-minimal-rpi3-....wic.bz2"

    print()
    print("=" * 62)
    print("  IoT Gateway — Firmware Header Packer")
    print("=" * 62)
    print(f"  firmware_version : {fw_version}")
    print(f"  image file       : {img_filename}")
    print()

    # ── Locate payload file ──────────────────────────────────────────────────
    image_path = os.path.join(deploy_dir, img_filename)
    if not os.path.exists(image_path):
        # Fallback: search build_image_dir
        alt = os.path.join(build_image_dir, img_filename)
        if os.path.exists(alt):
            image_path = alt
        else:
            print(f"ERROR: payload image not found:\n  {image_path}")
            sys.exit(1)

    payload_size = os.path.getsize(image_path)
    print(f"[1/4] Payload  : {image_path}")
    print(f"       Size    : {payload_size:,} bytes  ({payload_size / (1<<20):.1f} MB)")

    # ── Compute SHA-256 of payload ────────────────────────────────────────────
    print("[2/4] Computing SHA-256 of payload...")
    sha256_raw = sha256_of_file(image_path)
    sha256_hex = sha256_raw.hex()
    print(f"       SHA-256 : {sha256_hex}")

    # Cross-check against firmware-metadata.json (field is "sha256:<hex>")
    meta_hash = meta.get("firmware_hash", "")
    if meta_hash:
        expected_hex = meta_hash.replace("sha256:", "")
        if sha256_hex != expected_hex:
            print(f"WARNING: SHA-256 mismatch with firmware-metadata.json!")
            print(f"         metadata : {expected_hex}")
            print(f"         computed : {sha256_hex}")
            print( "         The payload may have changed since build_image.sh ran.")

    # ── Build header ──────────────────────────────────────────────────────────
    print("[3/4] Building 84-byte firmware header (hdr_version=2, no timestamp)...")
    header_bytes = build_header(fw_version, sha256_raw, payload_size)

    # Self-verify immediately
    parsed = verify_header(header_bytes)
    print(f"       magic        : {MAGIC.decode()}")
    print(f"       hdr_version  : {parsed['hdr_version']}")
    print(f"       hdr_size     : {parsed['hdr_size']} bytes")
    print(f"       fw_version   : {parsed['fw_version']}")
    print(f"       sha256       : {parsed['sha256_hex']}")
    print(f"       payload_size : {parsed['payload_size']:,} bytes")
    print(f"       hdr_crc32    : {parsed['hdr_crc32']}")

    # ── Write final_image.ldr ─────────────────────────────────────────────────
    # Filename: RPIF_<version>.ldr  e.g. RPIF_v0.1.0.ldr
    ldr_name    = f"RPIF_{fw_version}.ldr"
    ldr_path    = os.path.join(build_image_dir, ldr_name)

    print(f"[4/4] Writing  : {ldr_path}")

    CHUNK = 1 << 20   # 1 MB copy chunks
    with open(ldr_path, "wb") as out:
        out.write(header_bytes)
        with open(image_path, "rb") as src:
            for chunk in iter(lambda: src.read(CHUNK), b""):
                out.write(chunk)

    final_size = os.path.getsize(ldr_path)
    print(f"       Total   : {final_size:,} bytes  "
          f"(84 header + {payload_size:,} payload)")

    # ── Update firmware-metadata.json ────────────────────────────────────────
    meta["final_image_path"]      = ldr_path
    meta["final_image_filename"]  = ldr_name
    meta["final_image_size_bytes"] = final_size
    meta["header"] = {
        "magic":        MAGIC.decode(),
        "hdr_version":  parsed["hdr_version"],
        "hdr_size":     parsed["hdr_size"],
        "fw_version":   parsed["fw_version"],
        "sha256":       parsed["sha256_hex"],
        "payload_size": parsed["payload_size"],
        "hdr_crc32":    parsed["hdr_crc32"],
    }
    with open(metadata_path, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"\n  firmware-metadata.json updated with header + final image fields.")

    # ── Summary ───────────────────────────────────────────────────────────────
    print()
    print("=" * 62)
    print("  Header Packer — COMPLETE")
    print("=" * 62)
    print(f"  Output     : {ldr_path}")
    print(f"  Total size : {final_size:,} bytes")
    print()
    print("  ── Header fields ──")
    print(f"  fw_version   : {parsed['fw_version']:<32}  ← compare against blockchain firmware_version")
    print(f"  sha256       : {parsed['sha256_hex'][:32]}...")
    print(f"                  ← SHA-256 of .wic.bz2 payload; also what KMS signed")
    print(f"  payload_size : {parsed['payload_size']:,} bytes")
    print(f"  hdr_crc32    : {parsed['hdr_crc32']}  ← verify header not corrupted")
    print()
    print("  ── RPi verification sequence ──")
    print("  1. Fetch blockchain metadata  → get firmware_version, signer_identity")
    print("  2. Download final_image.ldr   → read first 84 bytes as header")
    print("  3. Assert magic == 'RPIF' and hdr_version == 2")
    print("  4. Assert crc32(header[0:80]) == header.hdr_crc32")
    print("  5. Assert header.fw_version > current_device_version  (rollback check)")
    print("  6. Assert header.fw_version  == blockchain.firmware_version")
    print("  7. Read next header.payload_size bytes (payload)")
    print("  8. Assert sha256(payload)    == header.sha256")
    print("  9. If 264 bytes remain → parse RPIS tail")
    print("     Assert tail.magic == 'RPIS'")
    print("     Fetch GCP KMS pubkey for signer_identity")
    print("     Assert verify(tail.signature[:tail.sig_len], header.sha256, pubkey)")
    print(" 10. All pass → authentic → extract .wic.bz2 → flash")
    print("=" * 62)
    print()


if __name__ == "__main__":
    main()
