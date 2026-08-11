#!/usr/bin/env python3
# Generate a Logos package catalog (logos-repo.json + index.json + files/) from
# a directory of built .lgx bundles. Mirrors the schema served by
# logos-modules-release: a repo descriptor (schemaVersion 1) whose indexUrl
# points at a package index (schemaVersion 2) whose per-version entries embed
# each bundle's full manifest — so the package manager reads dependencies
# before downloading. Signing is done to the .lgx beforehand; this only reads
# and hashes them, so signed bundles carry their signature into the catalog.
import argparse
import hashlib
import io
import json
import os
import shutil
import tarfile

REPO_NAME = "logos-rln-membership"
REPO_DISPLAY = "Logos RLN Membership"
REPO_DESC = "RLN membership management for Logos Basecamp (UI + backend modules)."
REPO_HOMEPAGE = "https://github.com/logos-co/logos-lez-rln"


def read_manifest(lgx_path):
    with tarfile.open(lgx_path, "r:gz") as tar:
        return json.load(io.TextIOWrapper(tar.extractfile(tar.getmember("manifest.json")), "utf-8"))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser(description="Generate a Logos package catalog from .lgx files.")
    ap.add_argument("--files-dir", required=True, help="Directory containing the built .lgx bundles.")
    ap.add_argument("--base-url", required=True, help="Base URL the .lgx and index will be served from.")
    ap.add_argument("--out", required=True, help="Output catalog directory.")
    ap.add_argument("--generated-at", required=True, help="ISO-8601 timestamp (passed in for reproducibility).")
    args = ap.parse_args()

    files_out = os.path.join(args.out, "files")
    if os.path.isdir(args.out):
        shutil.rmtree(args.out)
    os.makedirs(files_out)

    packages = []
    for name in sorted(os.listdir(args.files_dir)):
        if not name.endswith(".lgx"):
            continue
        src = os.path.join(args.files_dir, name)
        manifest = read_manifest(src)
        pkg, version = manifest["name"], manifest["version"]
        fname = f"{pkg}-{version}.lgx"
        dst = os.path.join(files_out, fname)
        shutil.copyfile(src, dst)
        packages.append({"name": pkg, "versions": [{
            "releasedAt": args.generated_at,
            "publisherRef": f"{pkg}-v{version}",
            "url": f"{args.base_url}/{fname}",
            "size": os.path.getsize(dst),
            "sha256": sha256_file(dst),
            "rootHash": manifest.get("hashes", {}).get("root", ""),
            "manifest": manifest,
        }]})
        print(f"  + {pkg} {version} ({manifest['type']}) deps={manifest.get('dependencies', [])}")

    if not packages:
        raise SystemExit("no .lgx files found in " + args.files_dir)

    with open(os.path.join(args.out, "index.json"), "w") as f:
        json.dump({
            "schemaVersion": 2,
            "repositoryName": REPO_NAME,
            "generatedAt": args.generated_at,
            "packages": packages,
        }, f, indent=2)

    with open(os.path.join(args.out, "logos-repo.json"), "w") as f:
        json.dump({
            "schemaVersion": 1,
            "name": REPO_NAME,
            "displayName": REPO_DISPLAY,
            "description": REPO_DESC,
            "homepage": REPO_HOMEPAGE,
            "indexUrl": f"{args.base_url}/index.json",
            "trustedSigners": [],
        }, f, indent=2)

    print(f"\ncatalog written to {args.out} ({len(packages)} packages)")
    print(f"  descriptor: {args.base_url}/logos-repo.json")


if __name__ == "__main__":
    main()
