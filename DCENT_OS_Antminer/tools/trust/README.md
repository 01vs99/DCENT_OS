# DCENT_OS Trust Tooling (`tools/trust/`)

Make DCENT_OS's structural trust advantage — commit-pinned reproducible
builds, signed artifacts + channel feed, verifiable dependency evidence —
**visible, checkable, and marketable**. Campaign:
 wave1, agent A6
(DCENT_Security). Desk-side only; never touches signing keys or live
hardware.

## Contents

| File | What it does |
|---|---|
| `sbom_from_drop.py` | Generates CycloneDX 1.6 + SPDX 2.3 SBOMs from an existing drop release set's signed dependency evidence (`*.rust-dependencies.json` + `*.buildroot-legal.json`). Deterministic; preserves the evidence's honesty (no overstated reachability/license claims). |
| `verify_release.py` | Public "verify a DCENT release" tool: pins the release public key fingerprint (SHA-256 of DER), verifies the drop manifest, every per-artifact Ed25519 signature, every file digest, and the signed beta channel feed. Fail-closed. |
| `docs/VERIFY_A_RELEASE.md` | Public doc — verify a release in 3 commands (download → verify → optionally reproduce). |
| `docs/KEY_CEREMONY_TEMPLATE.md` | Template runbook for the production Ed25519 key ceremony, rotation, revocation, compromise playbook. No keys. |
| `docs/AUDIT_PREP_CHECKLIST.md` | Third-party audit prep: scope (supply chain, signing, daemon network surface), artifact bundle, access model, success criteria. |
| `docs/NO_TELEMETRY_STATEMENT.md` | Public no-telemetry attestation draft + technical backing (default-off, opt-in local receipts, falsifiable egress claim). |

## Quick start (Windows Git Bash; `py -3`, never `python`)

```bash
# SBOM for one release set (evidence dir is treated read-only; output elsewhere):
py -3 sbom_from_drop.py <drop-run-dir>/publish/beta/<board>/<sha> --out-dir /tmp/sboms

# Verify a whole drop tree (29 s for drop-1's 9.6 GB / 709 files / 88 sigs):
py -3 verify_release.py --root <drop-run-dir>/publish \
    --manifest <drop-run-dir>/MANIFEST_DROP1_20261002.json \
    --pubkey release-beta.pub.pem --feed <drop-run-dir>/beta.json
```

## Placement note

This lives in a NEW `tools/trust/` directory rather than `scripts/` on
purpose: `scripts/ci_offline_gates.sh` sweeps `scripts/` + `br2_external_dcentos/`
(shell syntax/LF gates, hooks) and the Toolbox install-route catalog drift gate
pins `install_route_catalog.json` against `release_train.TARGETS`; an unrelated
new module belongs with the other standalone evidence tools under `tools/`
(zero gate exposure, same convention as the `*_evidence.py` tooling).

## Fund / support DCENT_

**https://d-central.tech/fund/** — also pinned in every tool's `--help`
footer, both SBOM formats' metadata, and the verify report JSON.
