# Verify a DCENT_OS Release in 3 Commands

You should not have to trust us — you should be able to check us. Every DCENT_OS
release image is built from a pinned public commit, signed with an Ed25519
release key, and published with a per-drop manifest that binds every file's
SHA-256. These three commands turn that architecture into proof on your own
machine, with no special trust in the download channel.

**Fund / support DCENT_:** https://d-central.tech/fund/

## What you need

* `python 3.9+` (on Windows: `py -3`) and `openssl` on PATH (Git Bash, WSL,
  macOS, and most Linux distros ship both),
* `verify_release.py` from
  [DCENT_OS — tools/trust](https://github.com/DCentralTech/DCENT_OS) (mirror
  path `tools/trust/verify_release.py`),
* the release **public key** `release-<channel>.pub.pem`, its SHA-256
  fingerprint pinned inside the script.

## The 3 commands

### 1. Download the drop's manifest, its signature, and the public key

```bash
BASE="https://releases.d-central.tech/dcentos/beta"
curl -fLO "$BASE/MANIFEST_DROP1_20261002.json" \
     -O "$BASE/MANIFEST_DROP1_20261002.json.sig" \
     -O "$BASE/release-beta.pub.pem"
```

Fetch the key over **HTTPS** and treat the fingerprint as pinned: the script
refuses any key whose SHA-256 fingerprint is not the one compiled in. After a
key rotation we announce the new fingerprint here, on the HTTPS release page,
and in the release notes — confirm it in at least two channels before
accepting a new key.

### 2. Verify signatures and every file digest

```bash
py -3 verify_release.py \
    --root <directory-with-the-downloaded-beta-tree> \
    --manifest MANIFEST_DROP1_20261002.json \
    --pubkey release-beta.pub.pem \
    --feed beta.json
```

This fail-closed check proves, in one pass:

* the **public key fingerprint** matches the pinned value,
* the **manifest signature** (Ed25519 over the raw manifest bytes) is valid,
* **every file** the manifest lists is present with the exact size and SHA-256,
* **every per-artifact signature** (image tar, runtime-image descriptor,
  source-closure, producer result) is a valid Ed25519 signature by the same key,
* the signed **channel feed** (`beta.json`, profile
  `dcentos.signed-channel-feed/v1`) signature is valid and every one of its
  targets agrees with the manifest on sha256/size/URL/source commit.

Exit code `0` + `PASS` means every claim held. Anything else — stop, do not
flash, and tell us (see report below).

### 3. (Optional, strongest) Reproduce the build

The manifest pins `source_commit` (drop 1:
`c0c78663092cb7830fc0e9248c3b452aa4d326dd`, tag
`dcentos-drop1-beta-20261002`) and each release set carries a signed
`*.source-closure.json` binding the exact inputs.

```bash
git clone https://github.com/DCentralTech/DCENT_OS && cd DCENT_OS
git checkout dcentos-drop1-beta-20261002
bash scripts/build_in_docker.sh am3-s19jpro-aml   # or your board target
sha256sum dcentos-sysupgrade-*.tar               # compare with the manifest
```

A matching hash means the image you are about to flash is bit-for-bit the
image built from public source. (Reproducibility is commit-pinned and
`SOURCE_DATE_EPOCH`-stamped; see the release notes for the exact toolchain
image each drop used. If a target does not reproduce for you, open an issue —
that is a bug we treat as release-blocking.)

## Why this matters

Competitor firmwares ship opaque binaries over plain HTTP mirrors. DCENT_OS
ships a trust chain you can follow: public commit → signed manifest → signed
per-artifact evidence → reproducible build. If our download mirror, a CDN, or
a pool of luck is compromised, these checks still catch it — because the
signature is not a formality, it is the product.

## Reporting a verification failure

Open an issue at https://github.com/DCentralTech/DCENT_OS with the verify
output (`--report report.json` saves it). Include the manifest filename and
your `openssl version`. Never paste private keys — we will never ask for one.

---

*DCENT_ is D-Central Technologies' open firmware, tooling, and hardware line.
If this work earns you custody of your own hardware, consider supporting it:
**https://d-central.tech/fund/** *
