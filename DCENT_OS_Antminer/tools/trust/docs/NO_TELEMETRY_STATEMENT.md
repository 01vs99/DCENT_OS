# DCENT_OS No-Telemetry Attestation — PUBLIC STATEMENT (DRAFT)

> **STATUS: DRAFT for operator sign-off.** Statement text for the release
> pages, repo README, and firmware About screen; technical backing in §2.
> Coordinates conceptually with the opt-in receipts/telemetry schema being
> designed separately (wave1, agent A4) — this statement must not outpace
> that schema's guarantees.

**Fund / support DCENT_:** https://d-central.tech/fund/

## 1. The statement (public text)

> **DCENT_OS does not phone home.**
>
> A default DCENT_OS image makes **zero unsolicited outbound connections**.
> There is no telemetry, no analytics, no crash reporting, no "usage
> statistics", no remote kill switch, and no vendor backdoor. Your miner's
> configuration, hashrate, pool list, and existence are **your data** — the
> firmware does not export them anywhere you did not explicitly point it at
> (your pool, your dashboard, your network).
>
> What DCENT_OS does instead: the *release channel* is signed and
> verifiable, so you can prove what you installed — without the firmware
> ever reporting it back to us. Trust moves to artifacts you can check, not
> data we collect.
>
> **Optional, explicit, local:** if we ever ship opt-in diagnostics
> receipts, they will be (a) default-off, (b) enabled only by an explicit
> operator action, (c) generated as local files you can read before choosing
> to send anywhere, and (d) documented field-by-field in a public schema.
> There will be no gray zone.

## 2. Technical backing (engineering claims behind the statement)

Each claim maps to a checkable mechanism, not a promise:

1. **Default-off by construction.** No telemetry agent exists in the
   default image; nothing to "disable". Signed images pin the exact daemon
   bytes (`*.runtime-image.json` carries `daemon_sha256`), so the claim is
   attached to a hash you can audit (`strings`/egress review on the pinned
   binary).
2. **Signed images beat self-reporting.** Because every image and its
   manifest are Ed25519-signed and commit-pinned, customers establish what
   the firmware *is* from artifacts (verify tool) — D-Central learns nothing
   about who flashed what. No "activation" server exists.
3. **Egress inventory, verifiable.** Default network behavior: DHCP, DNS as
   configured, Stratum to operator-configulated pools, mDNS/HTTP on the LAN
   (dashboard). The audit-prep bundle includes a deny-log capture of a
   default boot (§3.8 of `AUDIT_PREP_CHECKLIST.md`) so a third party can
   falsify this claim — falsifiability is the point.
4. **Control plane posture.** Release images fail closed on unauthenticated
   control (MCP write path requires a provisioned bearer token; read stays
   LAN-local). No vendor-relayed remote management exists at any tier.
5. **Opt-in receipts design constraints** (binding on any future
   implementation; coordinated with A4's schema work):
   - default off; enabling requires an explicit operator action in the
     dashboard or config file (never a CLI flag smuggled into a script);
   - receipts are emitted as **local, signed files first** (exportable,
     human-readable JSON), transmission is a separate, second opt-in;
   - public field-by-field schema with a version namespace reserved as
     `dcent.telemetry.receipts/v1` (final name owned by A4's schema);
   - no identifiers beyond what the operator configures (no generated
     per-device UUID sent anywhere by default);
   - the attestation above is updated the day any of this changes — the
     statement is versioned with the release it ships in.

## 3. How to check us (public instructions)

```bash
# 1. Verify your image is the attested one (signed manifest + daemon hash):
py -3 verify_release.py --root <downloaded-tree> --manifest MANIFEST_DROP1_*.json \
    --pubkey release-beta.pub.pem --feed beta.json

# 2. Watch what it does (any firewall/router, or an audit lab):
#    deny-all egress -> boot -> the only expected flows are DHCP/DNS + the
#    pools you configured. Anything else: file an issue, we treat it as
#    release-blocking.
```

## 4. Versioning

| Statement version | Ships in | Change |
|---|---|---|
| 1.0-draft | Drop 1 (beta) | Initial text; opt-in receipts constrained to §2.5 |

This attestation may only be strengthened, never silently weakened, within a
statement version; any weakening (e.g. adding mandatory update checks) ships
as a new version called out in the release notes and the About screen.

---

*DCENT_ open-source trust program — D-Central Technologies.
Fund / support: **https://d-central.tech/fund/** *
