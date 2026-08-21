#!/usr/bin/env python3
"""
Build_image/upload_to_github.py
---------------------------------
Standalone step: upload the packaged RPIF_*.ldr firmware to a GitHub Release
and update firmware-metadata.json with the real download URL.

Usage:
    python3 scripts/Build_image/upload_to_github.py [PROJECT_DIR]

Required environment variables:
    GITHUB_TOKEN   GitHub personal access token with 'repo' scope

Optional:
    GITHUB_REPO    owner/repo  (default: Pavan-githu/meta-userapp-package)
"""

import os
import sys
import json
import requests

# ─────────────────────────────────────────────────────────────────────────────
# Paths
# ─────────────────────────────────────────────────────────────────────────────
SCRIPT_DIR          = os.path.dirname(os.path.abspath(__file__))
DEFAULT_PROJECT_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, "..", ".."))
PROJECT_DIR         = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else DEFAULT_PROJECT_DIR)
BUILD_IMAGE_DIR     = os.path.join(PROJECT_DIR, "scripts", "Build_image")
METADATA_PATH       = os.path.join(BUILD_IMAGE_DIR, "firmware-metadata.json")

GH_API       = "https://api.github.com"
GITHUB_REPO  = os.environ.get("GITHUB_REPO", "Pavan-githu/meta-userapp-package")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")


def headers():
    return {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept":        "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def validate_token():
    """Check token is present and has repo access before touching releases."""
    if not GITHUB_TOKEN:
        print("ERROR: GITHUB_TOKEN is not set.")
        print("  export GITHUB_TOKEN=<your-pat>  (needs 'repo' scope)")
        sys.exit(1)

    r = requests.get(f"{GH_API}/repos/{GITHUB_REPO}", headers=headers(), timeout=15)
    if r.status_code == 401:
        print("ERROR: GitHub token is invalid or expired (401 Unauthorized).")
        print("  Generate a new PAT at: https://github.com/settings/tokens")
        print("  Required scope: repo")
        sys.exit(1)
    if r.status_code == 404:
        print(f"ERROR: Repository '{GITHUB_REPO}' not found or token lacks access (404).")
        sys.exit(1)
    r.raise_for_status()
    print(f"  Token OK — repo access confirmed: {GITHUB_REPO}")


def create_or_replace_release(tag: str, name: str, body: str) -> dict:
    """Create release; if tag already exists delete it first and retry."""
    r = requests.post(
        f"{GH_API}/repos/{GITHUB_REPO}/releases",
        headers=headers(),
        json={"tag_name": tag, "name": name, "body": body,
              "draft": False, "prerelease": False},
        timeout=30,
    )
    if r.status_code == 422:
        existing = requests.get(
            f"{GH_API}/repos/{GITHUB_REPO}/releases/tags/{tag}",
            headers=headers(), timeout=15,
        )
        if existing.status_code == 200:
            rel_id = existing.json()["id"]
            requests.delete(
                f"{GH_API}/repos/{GITHUB_REPO}/releases/{rel_id}",
                headers=headers(), timeout=15,
            ).raise_for_status()
            print(f"  Deleted existing release for tag {tag!r}, retrying...")
        requests.delete(
            f"{GH_API}/repos/{GITHUB_REPO}/git/refs/tags/{tag}",
            headers=headers(), timeout=15,
        )
        r = requests.post(
            f"{GH_API}/repos/{GITHUB_REPO}/releases",
            headers=headers(),
            json={"tag_name": tag, "name": name, "body": body,
                  "draft": False, "prerelease": False},
            timeout=30,
        )
    r.raise_for_status()
    return r.json()


def main():
    print()
    print("=" * 62)
    print("  IoT Gateway — GitHub Firmware Upload")
    print("=" * 62)
    print(f"  Project dir : {PROJECT_DIR}")
    print(f"  Repository  : {GITHUB_REPO}")
    print()

    # ── Validate token before touching the API ────────────────────────────────
    print("[1/4] Validating GitHub token...")
    validate_token()
    print()

    # ── Load metadata ─────────────────────────────────────────────────────────
    print("[2/4] Loading firmware-metadata.json...")
    if not os.path.exists(METADATA_PATH):
        print(f"ERROR: {METADATA_PATH} not found. Run build_image.sh first.")
        sys.exit(1)

    with open(METADATA_PATH) as f:
        meta = json.load(f)

    ldr_path = meta.get("final_image_path", "")
    if not ldr_path or not os.path.exists(ldr_path):
        print(f"ERROR: final_image_path not found: {ldr_path!r}")
        print("  Run add_firmware_header.py (step 12 of build_image.sh) first.")
        sys.exit(1)

    fw_version = meta["firmware_version"].lstrip("v")
    build_ts   = int(os.path.getmtime(ldr_path))
    tag        = f"v{fw_version}-{build_ts}"
    ldr_name   = os.path.basename(ldr_path)
    ldr_size   = os.path.getsize(ldr_path)

    print(f"  firmware_version : v{fw_version}")
    print(f"  ldr file         : {ldr_name}  ({ldr_size:,} bytes)")
    print(f"  release tag      : {tag}")
    print()

    # ── Create GitHub Release ────────────────────────────────────────────────
    print("[3/4] Creating GitHub Release...")
    body = (
        f"firmware_hash : {meta.get('firmware_hash', '')}\n"
        f"fw_version    : v{fw_version}\n"
        f"timestamp     : {meta.get('timestamp', '')}\n"
        f"hsm_key_id    : {meta.get('hsm_key_id', 'n/a')}"
    )
    release    = create_or_replace_release(tag, f"Firmware v{fw_version}", body)
    upload_url = release["upload_url"].split("{")[0]
    print(f"  Release created : {release['html_url']}")
    print()

    # ── Upload .ldr asset ─────────────────────────────────────────────────────
    print(f"[4/4] Uploading {ldr_name} ({ldr_size:,} bytes)...")
    with open(ldr_path, "rb") as f:
        r = requests.post(
            upload_url,
            headers={**headers(), "Content-Type": "application/octet-stream"},
            params={"name": ldr_name},
            data=f,
            timeout=600,
        )
    r.raise_for_status()
    real_url = r.json()["browser_download_url"]
    print(f"  Download URL    : {real_url}")

    # ── Update metadata with real URL ─────────────────────────────────────────
    meta["download_url"] = real_url
    with open(METADATA_PATH, "w") as f:
        json.dump(meta, f, indent=2)
    print(f"  firmware-metadata.json updated with real download_url")
    print()

    print("=" * 62)
    print("  GitHub Upload — COMPLETE")
    print("=" * 62)
    print(f"  URL : {real_url}")
    print()


if __name__ == "__main__":
    main()
