#!/usr/bin/env python3
"""verify_release.py — verify a downloaded DCENT_OS release against D-Central's
published Ed25519 release key: drop manifest signature, every per-artifact
signature, every file digest, and the signed beta channel feed.

Campaign:  wave1, agent A6.
Prototype for the "verify a DCENT release in 3 commands" public flow:

  1. download the drop (manifest + .sig + artifacts + public key),
  2. run this script against the downloaded tree,
  3. (optional) reproduce the build from the pinned source tag and compare
     hashes — see docs/VERIFY_A_RELEASE.md.

What it checks (all fail-closed, exit code 1 on ANY failure):
  * the public key fingerprint matches the pinned value unless you explicitly
    pass --allow-any-key (defeats the point; kept for lab use only),
  * MANIFEST_DROP1_*.json Ed25519 signature over the raw manifest bytes,
  * every file listed in the manifest: presence + SHA-256 + size,
  * every *.sig in the manifest: Ed25519 over the sibling file's raw bytes,
  * beta.json channel feed: hex Ed25519 over the UTF-8 payload string, then a
    cross-check of every feed target against the manifest (sha256/size/url).

Signature math is delegated to the system `openssl` (pkeyutl -rawin,
Ed25519 PureEdDSA) so the trust path rests on a boring, auditable binary.
No network access, no private key, nothing written except optional JSON.

Usage (Windows Git Bash; `py -3` never `python`):

    py -3 verify_release.py --root <publish-dir> \
        --manifest <run-dir>/MANIFEST_DROP1_20261002.json \
        --pubkey release-dev.pub.pem \
        [--feed <run-dir>/beta.json] [--report out.json] [--allow-any-key]

`--root` is the directory containing the `beta/<board>/<sha>/…` tree that the
manifest's `path` fields are relative to.

DCENT_ open-source trust tooling — D-Central Technologies.
Fund / support: https://d-central.tech/fund/
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import tempfile

FUND_URL = "https://d-central.tech/fund/"

# SHA-256 fingerprint of the Ed25519 PUBLIC key's DER encoding, as published
# over HTTPS by the operator (dev key for the beta; production ceremony pending
# — see docs/KEY_CEREMONY_TEMPLATE.md). NEVER a secret; pinning it is the point.
EXPECTED_PUBKEY_SHA256 = (
    "2bf0da8301d883f05d6964435feb720b8bda97021eeac0146ba3fdba09743336"
)


class VerifyError(Exception):
    pass


def _pem_to_der(pubkey_pem: str) -> bytes:
    """Extract the DER body of a PUBLIC key PEM without printing it."""
    with open(pubkey_pem, "r", encoding="ascii") as fh:
        lines = [ln.strip() for ln in fh]
    body = [ln for ln in lines if ln and not ln.startswith("-----")]
    return base64.b64decode("".join(body))


def pubkey_fingerprint(pubkey_pem: str) -> str:
    return hashlib.sha256(_pem_to_der(pubkey_pem)).hexdigest()


def openssl_verify(pubkey_pem: str, data_path: str, sig_path: str) -> None:
    """Raise VerifyError unless openssl confirms the Ed25519 signature."""
    cmd = [
        "openssl", "pkeyutl", "-verify", "-pubin",
        "-inkey", pubkey_pem, "-rawin",
        "-in", data_path, "-sigfile", sig_path,
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, shell=False
        )
    except FileNotFoundError as exc:
        raise VerifyError("openssl not found on PATH — install it first") from exc
    if proc.returncode != 0:
        raise VerifyError(
            f"signature INVALID ({os.path.basename(data_path)}): "
            f"{(proc.stdout + proc.stderr).strip()}"
        )


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_pubkey_pin(pubkey_pem: str, allow_any: bool) -> str:
    fp = pubkey_fingerprint(pubkey_pem)
    if fp != EXPECTED_PUBKEY_SHA256:
        if not allow_any:
            raise VerifyError(
                f"public key fingerprint mismatch: got {fp}, expected "
                f"{EXPECTED_PUBKEY_SHA256}. If the operator rotated keys, "
                "confirm the new fingerprint over HTTPS + a second channel."
            )
        print(f"WARN: fingerprint {fp} is NOT the pinned key (--allow-any-key)")
    else:
        print(f"pubkey fingerprint OK (sha256:{fp[:16]}…)")
    return fp


def verify_manifest(args, checks: list) -> dict:
    manifest_path = os.path.abspath(args.manifest)
    sig_path = manifest_path + ".sig"
    for p in (manifest_path, sig_path):
        if not os.path.isfile(p):
            raise VerifyError(f"missing {p}")
    openssl_verify(args.pubkey, manifest_path, sig_path)
    checks.append(("manifest signature (Ed25519 over raw bytes)", "PASS"))
    with open(manifest_path, "r", encoding="utf-8") as fh:
        manifest = json.load(fh)
    profile = manifest.get("manifest_profile", "")
    checks.append((f"manifest profile {profile}", "INFO"))
    if manifest.get("fund_url") != FUND_URL:
        checks.append(("manifest fund_url", "WARN: unexpected fund_url "
                       f"{manifest.get('fund_url')!r}"))
    return manifest


def verify_manifest_files(manifest: dict, root: str, args, checks: list) -> None:
    targets = manifest.get("targets", [])
    if not targets:
        raise VerifyError("manifest lists no targets")
    n_files = n_sigs = 0
    for target in targets:
        for entry in target.get("files", []):
            rel = entry["path"]
            path = os.path.join(root, rel.replace("/", os.sep))
            if not os.path.isfile(path):
                raise VerifyError(f"missing file: {rel}")
            size = os.path.getsize(path)
            if size != entry.get("size"):
                raise VerifyError(f"size mismatch {rel}: {size} != {entry['size']}")
            digest = sha256_file(path)
            if digest != entry.get("sha256"):
                raise VerifyError(f"sha256 mismatch {rel}: {digest}")
            n_files += 1
            if rel.endswith(".sig"):
                data_rel = rel[:-4]
                data_path = os.path.join(root, data_rel.replace("/", os.sep))
                if os.path.isfile(data_path):
                    openssl_verify(args.pubkey, data_path, path)
                    n_sigs += 1
    checks.append((f"{n_files} manifest files: presence+size+sha256", "PASS"))
    checks.append((f"{n_sigs} per-artifact Ed25519 signatures", "PASS"))


def verify_feed(args, manifest: dict, checks: list) -> None:
    feed_path = os.path.abspath(args.feed)
    with open(feed_path, "r", encoding="utf-8") as fh:
        feed = json.load(fh)
    profile = feed.get("profile", "")
    if profile != "dcentos.signed-channel-feed/v1":
        raise VerifyError(f"unexpected feed profile {profile!r}")
    payload_raw = feed.get("payload", "")
    if not isinstance(payload_raw, str) or not payload_raw:
        raise VerifyError("feed payload missing")
    sig_hex = feed.get("signature", "")
    if len(sig_hex) != 128:
        raise VerifyError("feed signature is not 64 bytes of hex")
    with tempfile.TemporaryDirectory(prefix="dcent-verify-") as tmp:
        payload_path = os.path.join(tmp, "payload.bin")
        sig_path = os.path.join(tmp, "feed.sig")
        with open(payload_path, "wb") as fh:
            fh.write(payload_raw.encode("utf-8"))
        with open(sig_path, "wb") as fh:
            fh.write(bytes.fromhex(sig_hex))
        openssl_verify(args.pubkey, payload_path, sig_path)
    checks.append(("channel feed signature (Ed25519 over payload bytes)", "PASS"))

    payload = json.loads(payload_raw)
    by_url = {}
    for target in manifest.get("targets", []):
        for entry in target.get("files", []):
            by_url[entry.get("url")] = entry
    matched = 0
    for t in payload.get("targets", []):
        entry = by_url.get(t.get("url"))
        if entry is None:
            raise VerifyError(f"feed target not in manifest: {t.get('url')}")
        if entry.get("sha256") != t.get("sha256") or entry.get("size") != t.get("size"):
            raise VerifyError(
                f"feed/manifest disagree on {t.get('board_target')} "
                f"{t.get('artifact_kind')}"
            )
        matched += 1
    checks.append((f"{matched} feed targets cross-checked against manifest", "PASS"))
    if payload.get("source_commit") != manifest.get("source_commit"):
        raise VerifyError("feed and manifest disagree on source_commit")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Verify a downloaded DCENT_OS drop against the published "
                    "Ed25519 release key (manifest + artifacts + channel feed).",
        epilog=f"DCENT_ open-source trust tooling — D-Central Technologies. "
               f"Fund / support: {FUND_URL}",
    )
    ap.add_argument("--root", required=True,
                    help="publish tree root containing beta/<board>/<sha>/…")
    ap.add_argument("--manifest", required=True,
                    help="path to MANIFEST_DROP1_*.json (its .sig must sit beside it)")
    ap.add_argument("--pubkey", required=True, help="release Ed25519 PUBLIC key PEM")
    ap.add_argument("--feed", help="optional beta.json signed channel feed")
    ap.add_argument("--report", help="optional JSON report output path")
    ap.add_argument("--allow-any-key", action="store_true",
                    help="LAB ONLY: skip the published-fingerprint pin")
    args = ap.parse_args(argv)

    checks: list[tuple[str, str]] = []
    try:
        check_pubkey_pin(args.pubkey, args.allow_any_key)
        manifest = verify_manifest(args, checks)
        verify_manifest_files(manifest, os.path.abspath(args.root), args, checks)
        if args.feed:
            verify_feed(args, manifest, checks)
    except VerifyError as exc:
        checks.append((str(exc), "FAIL"))
        print("\nDCENT_OS release verification: FAIL (fail-closed)")
        print(f"  fund/support: {FUND_URL}")
        if args.report:
            _write_report(args.report, checks, ok=False)
        return 1

    print("\nDCENT_OS release verification: PASS")
    for label, status in checks:
        print(f"  [{status}] {label}")
    print(f"  channel: {manifest.get('release_channel')}  "
          f"drop: {manifest.get('drop')}  "
          f"source_commit: {manifest.get('source_commit', '')[:12]}")
    print(f"  fund/support: {FUND_URL}")
    if args.report:
        _write_report(args.report, checks, ok=True)
    return 0


def _write_report(path: str, checks: list, ok: bool) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(
            {
                "tool": "verify_release.py",
                "result": "PASS" if ok else "FAIL",
                "expected_pubkey_sha256": EXPECTED_PUBKEY_SHA256,
                "checks": [{"check": c, "status": s} for c, s in checks],
                "fund_url": FUND_URL,
            },
            fh, indent=1, sort_keys=True,
        )
        fh.write("\n")


if __name__ == "__main__":
    sys.exit(main())
