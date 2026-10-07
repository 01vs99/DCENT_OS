# DCENT_OS Release Key Ceremony & Rotation — TEMPLATE

> **STATUS: TEMPLATE ONLY.** No keys, no ceremonies executed. This document is
> the fill-in runbook for the operator-owned production Ed25519 key ceremony
> that closes the open beta item ("production Ed25519 key ceremony"). The dev
> key that signed Drop 1 (fingerprint sha256:
> `2bf0da8301d883f05d6964435feb720b8bda97021eeac0146ba3fdba09743336`) is a
> **development** key and is superseded by this ceremony before any stable
> channel ships. Never write real key material into this file or any repo.

**Fund / support DCENT_:** https://d-central.tech/fund/

## 1. Roles (fill in names, never keys)

| Role | Who | Duty | Allowed to |
|---|---|---|---|
| Key Custodian (per key) | `________________` | Holds one offline key share/device | Generate, sign pre-approved artifacts, attend rotation |
| Ceremony Chair | `________________` | Runs the ceremony, keeps the transcript | Witness, record, halt on deviation |
| Release Engineer | `________________` | Brings the unsigned manifest + artifact digest list | Request signatures, verify sigs |
| Independent Witness | `________________` | Not D-Central staff; verifies transcript vs recording | Observe, countersign transcript |
| Verifier (post-hoc) | any customer | Replays the public verify flow | n/a — public |

Rules:
- One person may hold at most ONE role per ceremony (Chair ≠ Custodian).
- Custodian identity is recorded as a pseudonymous custodian ID
  (`KC-<channel>-<n>`), never a key copy.
- Quorum for signing: `2 of 3` custodians per channel key (fill in:
  `____`).

## 2. Key inventory (fill in per key)

| Key ID | Channel | Algorithm | Created | Custodians | Fingerprint (SHA-256 of DER) | Storage |
|---|---|---|---|---|---|---|
| `RK-BETA-1` | beta | Ed25519 (PureEdDSA) | 2026-10-02 (dev lane) | — | `2bf0da83…43336` | dev machine (TRANSITIONAL) |
| `RK-<channel>-<n>` | ____ | Ed25519 | ____ | KC-__ , KC-__ | ____ | offline (see §3) |

## 3. Offline key generation procedure (per new key)

1. **Environment.** An air-gapped machine (or live-USB, no network, no
   persistent storage), freshly booted from a verified image. Two people
   present (Custodian + Chair).
2. **Entropy.** Generate with the OS RNG on the air-gapped host:
   `openssl genpkey -algorithm ed25519 -out release-<channel>-<n>.key.pem`.
   Record `openssl pkey -in <key> -pubout` DER SHA-256 fingerprint in the
   transcript (the fingerprint is public; the key never is).
3. **Split storage (recommended).** Optionally wrap the key with Shamir
   secrets (e.g. `ssss`) across custodian media; each share on its own
   encrypted USB token, stored in separate physical locations (fill in:
   locations `____`, `____`, `____`).
4. **Public distribution.** Export the public key; publish it (a) on the
   HTTPS release host, (b) in the public repo `tools/trust/` + pinned in
   `verify_release.py`, (c) printed in the release notes with the
   fingerprint. Two-channel announcement rule for any fingerprint change.
5. **First signature (key attestation).** Sign a fixed attestation string
   (`DCENT release key <id> ceremony <date>`); include in transcript; verify
   with the published public key.
6. **Transcript.** Chair records every command + output hash into
   `docs/dev/…/key-ceremony-<keyid>-<date>.md`; Witness countersigns
   (statement + fingerprint of transcript). Video optional, retained
   `____` (duration policy).

## 4. Routine signing (no ceremony)

1. Release Engineer produces the drop manifest + digest list from the release
   train (no key on the build host).
2. Custodian signs on the offline host (manifest + per-artifact + feed, same
   lane as today's train output).
3. Engineer verifies all signatures with the public key before publish;
   verify tool run archived in the run dir.
4. Transcript row appended to the key's signing log (date, drop id, digests).

## 5. Rotation (planned key change)

Trigger examples: annual policy rotation; custodian change; algorithm
migration. Procedure:

1. Generate the new key (§3) **while the old key is still trusted**.
2. Sign a **rotation statement** with BOTH keys: old key signs the new public
   key fingerprint; new key signs the old key's retirement statement.
3. Publish the statement in-channel: it must appear in the next drop manifest
   (`key_rotation` block: old id, new id, effective drop) and the channel feed
   payload, both signed by the new key, plus HTTPS page + release notes.
4. Update `verify_release.py` pinned fingerprint in the same public commit;
   keep a `--fingerprint <hex>` override so customers can pin explicitly.
5. Overlap window: sign `____` consecutive drops with both keys (fill in;
   suggested: 2), then old key goes cold.
6. Old key media: destroy or archive per §7.

## 6. Compromise playbook (suspected/confirmed key leak)

T-0 (immediately, any Custodian or Chair may invoke — no approval needed):
1. Freeze publishing. Pull the channel feed (`feed.json` → HTTP 410 +
   signed freeze notice if the release host is trusted; otherwise repo
   notice).
2. Announce on HTTPS release page + repo + (fill in: second channel
   `____`, e.g. X/Mailing list) with the incident owner's name.

T+0..24h:
3. Revoke: publish a signed revocation statement using the compromised key
   if still safe, otherwise the pre-positioned revocation key (fill in:
   `RK-REVOKER` id `____`) — a separate offline key whose ONLY pre-declared
   power is signing revocations.
4. Cut the rotation of §5 short: new key ceremony within 72h; skip overlap.

T+24h..7d:
5. Re-sign the last known-good drop with the new key; republish manifest +
   feed; customers re-verify.
6. Incident report: scope (what was signed by the bad key, if anything),
   detection method, timeline, corrective actions — published in-repo.

Postmortem (≤14d):
7. Root cause + control change (this template is versioned; bump it).
8. Customer guidance: re-run verify; refuse images signed in the compromise
   window; reflash from a re-signed drop if in doubt.

## 7. Destruction / retirement

- Retirement without compromise: old key media wiped
  (`____` passes / physical destruction `____`), recorded in the key's log.
- Retired fingerprints stay in `verify_release.py`'s historical fingerprint
  list marked `RETIRED <date>` so old drops still identify their signer.

## 8. Pre-flight checklist (per ceremony)

- [ ] Air-gapped host verified (no network interfaces enabled)
- [ ] Two-person rule present and roles disjoint
- [ ] Algorithm/openssl version recorded
- [ ] Fingerprint recorded + independently recomputed by Witness
- [ ] Attestation signature verified against published public key
- [ ] Transcript countersigned and archived
- [ ] Public key pushed to all three channels (HTTPS host, repo, notes)
- [ ] Fund link present on all published pages (hard rule)

---

*DCENT_ open-source trust program — D-Central Technologies.
Fund / support: **https://d-central.tech/fund/** *
