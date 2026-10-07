#!/usr/bin/env python3
"""Generate CycloneDX 1.6 + SPDX 2.3 SBOMs from an EXISTING DCENT_OS drop-1
release set's dependency evidence — no rebuild, no live hardware.

Campaign:  wave1, agent A6
(trust & security productization). Prototype for the SBOM program.

Inputs (already produced by the release train, READ-ONLY for this tool):
  * ``<artifact>.rust-dependencies.json``  — schema
    ``org.dcentral.dcentos.rust-dependency-inventory.v1`` (flat Cargo-resolved
    component inventory: name/version/license_declared/features/source).
  * ``<artifact>.buildroot-legal.json``    — schema
    ``org.dcentral.dcentos.buildroot-legal-inventory.v1`` (per-file digests of
    Buildroot ``make legal-info`` output for target + host packages).
  * ``<artifact>.runtime-image.json``      — optional, for board/version metadata.

The source inventories are HONEST about what they do not claim (reachability,
license auditing, vulnerability analysis). This generator preserves that honesty
as CycloneDX/SPDX properties instead of silently upgrading the claims — an SBOM
that overstates its evidence is a trust liability, not a trust asset.

Determinism: same evidence in -> byte-identical SBOM out (uuid5 serial numbers,
sorted components, timestamps taken from evidence ``created_at_utc``), so a CI
gate can regenerate-and-diff as the validation step.

This tool NEVER writes into the evidence directory: output goes to ``--out`` /
``--out-dir`` or stdout. It does not touch signing keys; signing is a separate
operator step (same Ed25519 lane as the other release artifacts).

Usage (Windows Git Bash, ``py -3`` never ``python``):

    py -3 sbom_from_drop.py <release-set-dir> [--artifact NAME] \
        [--format cyclonedx|spdx|both] [--out PATH | --out-dir DIR] [--validate-only]

Run from anywhere; paths resolve via arguments. Exit 0 on success, nonzero on
any validation failure.

Fund / support DCENT_: https://d-central.tech/fund/
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import sys
import uuid

TOOL_NAME = "dcent-trust-sbomgen"
TOOL_VERSION = "0.1.0"
ORG = "D-Central Technologies"
FUND_URL = "https://d-central.tech/fund/"
CDX_SPEC = "1.6"
SPDX_SPEC = "SPDX-2.3"
# uuid5 namespace for DCENT SBOM serials (fixed constant, not a secret).
DCENT_UUID_NAMESPACE = uuid.UUID("6f1d2c34-9a5e-4f7b-8d21-0c4e5b7a9d10")

RUST_SCHEMA = "org.dcentral.dcentos.rust-dependency-inventory.v1"
BR_SCHEMA = "org.dcentral.dcentos.buildroot-legal-inventory.v1"


class EvidenceError(Exception):
    pass


def _fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(2)


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_evidence(set_dir: str, artifact_hint: str | None):
    """Locate and load the dependency evidence pair for one release set."""
    rust = br = None
    for name in sorted(os.listdir(set_dir)):
        if name.endswith(".rust-dependencies.json"):
            if artifact_hint and not name.startswith(artifact_hint):
                continue
            if rust is not None:
                raise EvidenceError(
                    f"multiple *rust-dependencies.json in {set_dir}; pass --artifact"
                )
            rust = os.path.join(set_dir, name)
        if name.endswith(".buildroot-legal.json"):
            if artifact_hint and not name.startswith(artifact_hint):
                continue
            if br is not None:
                raise EvidenceError(
                    f"multiple *buildroot-legal.json in {set_dir}; pass --artifact"
                )
            br = os.path.join(set_dir, name)
    if not rust or not br:
        raise EvidenceError(
            f"release set {set_dir} lacks rust-dependencies/buildroot-legal evidence"
        )
    with open(rust, "r", encoding="utf-8") as fh:
        rust_doc = json.load(fh)
    with open(br, "r", encoding="utf-8") as fh:
        br_doc = json.load(fh)
    if rust_doc.get("schema") != RUST_SCHEMA:
        raise EvidenceError(f"unexpected rust inventory schema {rust_doc.get('schema')!r}")
    if br_doc.get("schema") != BR_SCHEMA:
        raise EvidenceError(f"unexpected buildroot inventory schema {br_doc.get('schema')!r}")
    art_sha = rust_doc.get("artifact", {}).get("sha256", "")
    if br_doc.get("artifact", {}).get("sha256", "") != art_sha or not art_sha:
        raise EvidenceError("evidence artifacts disagree on the bound artifact sha256")

    runtime = None
    rt_path = os.path.join(set_dir, art_name(rust_doc) + ".runtime-image.json")
    if os.path.isfile(rt_path):
        with open(rt_path, "r", encoding="utf-8") as fh:
            runtime = json.load(fh)

    return {
        "rust_path": rust,
        "br_path": br,
        "rust": rust_doc,
        "br": br_doc,
        "runtime": runtime,
        "artifact_name": art_name(rust_doc),
        "artifact_sha256": art_sha,
        "artifact_size": rust_doc.get("artifact", {}).get("size"),
        "rust_sha256": _sha256_file(rust),
        "br_sha256": _sha256_file(br),
    }


def art_name(rust_doc: dict) -> str:
    return rust_doc.get("artifact", {}).get("path", "").rsplit("/", 1)[-1]


# --------------------------------------------------------------------------- #
# Buildroot package parsing: `licenses/<name>-<version>/...` and
# `host-licenses/<name>-<version>/...` members of make legal-info output.
# --------------------------------------------------------------------------- #
_VERSION_TAIL = re.compile(r"^(?P<name>.+?)-(?P<ver>[0-9][0-9A-Za-z.+_~*-]*)$")


def parse_buildroot_packages(br_doc: dict) -> dict:
    """Return {bom_ref: component_dict} for target + host legal-info packages."""
    packages: dict[str, dict] = {}
    for entry in br_doc.get("legal_info", {}).get("files", []):
        path = entry.get("path", "")
        parts = path.split("/")
        if len(parts) < 3 or parts[0] not in ("licenses", "host-licenses"):
            continue
        phase = "target" if parts[0] == "licenses" else "host-tool"
        seg = parts[1]
        m = _VERSION_TAIL.match(seg)
        name, version = (m.group("name"), m.group("ver")) if m else (seg, "")
        ref = f"urn:dcent:buildroot:{phase}:{name}@{version}" if version else \
            f"urn:dcent:buildroot:{phase}:{name}"
        comp = packages.setdefault(
            ref,
            {
                "bom-ref": ref,
                "type": "library",
                "name": name,
                "version": version or "UNKNOWN",
                "scope": "required" if phase == "target" else "optional",
                "properties": [
                    {"name": "dcent:build-phase", "value": phase},
                    {
                        "name": "dcent:license-evidence",
                        "value": "buildroot make legal-info file digests; "
                        "license IDs not parsed or audited",
                    },
                ],
                "_evidence_files": [],
            },
        )
        comp["_evidence_files"].append(
            {"path": path, "sha256": entry.get("sha256", ""), "size": entry.get("size")}
        )
    return packages


# --------------------------------------------------------------------------- #
# CycloneDX 1.6
# --------------------------------------------------------------------------- #
def build_cyclonedx(ev: dict) -> dict:
    rust, br, runtime = ev["rust"], ev["br"], ev["runtime"]
    created = rust.get("created_at_utc") or br.get("created_at_utc")
    version = (runtime or {}).get("version") or (rust.get("source_date_epoch") and
              str(rust["source_date_epoch"])) or "unknown"
    board = (runtime or {}).get("board_target") or br.get("build", {}).get("target", "")
    main_ref = f"urn:dcent:image:{ev['artifact_sha256']}"
    serial = uuid.uuid5(DCENT_UUID_NAMESPACE, f"dcentos-sbom:{ev['artifact_sha256']}")

    # source_commit lives in the sibling release.txt lane, not in the evidence
    # pair itself; main() injects it into ev when found. Only emit what is
    # truly evidenced — never guess.
    props = [
        {"name": "dcent:product", "value": "DCENT_OS"},
        {"name": "dcent:board-target", "value": board},
        {"name": "dcent:channel", "value": (runtime or {}).get("channel", "beta")},
        {"name": "dcent:buildroot-commit",
         "value": br.get("build", {}).get("buildroot_commit", "")},
        {"name": "dcent:build-arch", "value": br.get("build", {}).get("arch", "")},
        {"name": "dcent:fund-url", "value": FUND_URL},
    ]
    if ev.get("source_commit"):
        props.append({"name": "dcent:source-commit", "value": ev["source_commit"]})
    main_component = {
        "bom-ref": main_ref,
        "type": "firmware",
        "name": ev["artifact_name"],
        "version": version,
        "hashes": [{"alg": "SHA-256", "content": ev["artifact_sha256"]}],
        "scope": "required",
        "properties": props,
    }

    components = []
    seen_refs = {main_ref}

    # --- Rust crates -------------------------------------------------------
    for crate in rust.get("graph", {}).get("components", []):
        name = crate.get("name", "")
        ver = crate.get("version", "")
        source = crate.get("source", "")
        if source.startswith("registry+"):
            purl = f"pkg:cargo/{name.lower()}@{ver}"
            ref = purl
        else:
            purl = None
            ref = f"urn:dcent:cargo-local:{name}@{ver}"
        if ref in seen_refs:
            continue  # dedupe identical purl; inventory is flat, not multi-edge
        seen_refs.add(ref)
        comp = {
            "bom-ref": ref,
            "type": "library",
            "name": name,
            "version": ver,
            "scope": "required",
            "licenses": [{"expression": crate.get("license_declared", "NOASSERTION")}]
            if crate.get("license_declared") else [],
            "properties": [
                {"name": "dcent:source", "value": source},
                {"name": "dcent:features-enabled", "value":
                 ",".join(sorted(crate.get("features_enabled", [])))},
                {"name": "dcent:manifest-path", "value": crate.get("manifest_path", "")},
                {"name": "dcent:license-evidence", "value":
                 "Cargo package declaration only; not independently validated"},
            ],
        }
        if purl:
            comp["purl"] = purl
        components.append(comp)

    # --- Buildroot target + host packages ----------------------------------
    for ref, comp in parse_buildroot_packages(br).items():
        if ref in seen_refs:
            continue
        seen_refs.add(ref)
        evidence = comp.pop("_evidence_files")
        comp["properties"].append({
            "name": "dcent:license-evidence-files",
            "value": json.dumps(evidence, sort_keys=True, separators=(",", ":")),
        })
        components.append(comp)

    scope = rust.get("scope", {})
    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_SPEC,
        "serialNumber": f"urn:uuid:{serial}",
        "version": 1,
        "metadata": {
            "timestamp": created,
            "tools": {
                "components": [{
                    "type": "application",
                    "group": "tech.d-central",
                    "name": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "publisher": ORG,
                }]
            },
            "authors": [{"name": ORG}],
            "component": main_component,
            "properties": [
                {"name": "dcent:evidence:rust-dependencies-sha256",
                 "value": ev["rust_sha256"]},
                {"name": "dcent:evidence:buildroot-legal-sha256",
                 "value": ev["br_sha256"]},
                {"name": "dcent:inventory-format", "value":
                 f"{RUST_SCHEMA} + {BR_SCHEMA}"},
                {"name": "dcent:reachability", "value": "not-claimed"},
                {"name": "dcent:vulnerability-analysis", "value":
                 scope.get("vulnerability_analysis", "not_performed")},
                {"name": "dcent:dependency-edges", "value":
                 "not-retained-by-inventory; flat component list"},
                {"name": "dcent:fund-url", "value": FUND_URL},
            ],
        },
        "components": sorted(components, key=lambda c: (c["bom-ref"])),
    }
    return bom


# --------------------------------------------------------------------------- #
# SPDX 2.3 (JSON)
# --------------------------------------------------------------------------- #
_SPDX_ID_SANITIZE = re.compile(r"[^A-Za-z0-9.-]")


def build_spdx(ev: dict) -> dict:
    rust, br, runtime = ev["rust"], ev["br"], ev["runtime"]
    created = rust.get("created_at_utc") or br.get("created_at_utc")
    version = (runtime or {}).get("version") or "unknown"
    board = (runtime or {}).get("board_target") or br.get("build", {}).get("target", "")
    doc_uuid = uuid.uuid5(DCENT_UUID_NAMESPACE, f"dcentos-spdx:{ev['artifact_sha256']}")
    ns = f"https://d-central.tech/spdx/dcentos/{board}/{ev['artifact_sha256']}/{doc_uuid}"

    def sid(prefix: str, n: int) -> str:
        return f"SPDXRef-{prefix}-{n:05d}"

    packages = []
    relationships = []
    n = 0
    n += 1
    image_pkg = sid("Package", n)
    packages.append({
        "name": ev["artifact_name"],
        "SPDXID": image_pkg,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
        "comment": "DCENT_OS firmware image; see CycloneDX companion for hashes "
                   f"and evidence bindings. Fund: {FUND_URL}",
    })
    relationships.append({
        "spdxElementId": "SPDXRef-DOCUMENT",
        "relationshipType": "DESCRIBES",
        "relatedSpdxElement": image_pkg,
    })

    for crate in rust.get("graph", {}).get("components", []):
        n += 1
        lic = crate.get("license_declared") or "NOASSERTION"
        pkg = {
            "name": crate.get("name", ""),
            "SPDXID": sid("Package", n),
            "versionInfo": crate.get("version", ""),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": lic,
            "copyrightText": "NOASSERTION",
            "comment": "Cargo-declared license; not independently validated",
        }
        if crate.get("source", "").startswith("registry+"):
            pkg["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator":
                    f"pkg:cargo/{crate['name'].lower()}@{crate.get('version','')}",
            }]
        packages.append(pkg)

    for ref, comp in parse_buildroot_packages(br).items():
        n += 1
        packages.append({
            "name": comp["name"],
            "SPDXID": sid("Package", n),
            "versionInfo": comp.get("version", "UNKNOWN"),
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": "NOASSERTION",
            "copyrightText": "NOASSERTION",
            "comment": f"Buildroot {comp['properties'][0]['value']}; license "
                       "evidence = legal-info file digests (not parsed)",
        })

    return {
        "spdxVersion": SPDX_SPEC,
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"DCENT_OS-{board}-{ev['artifact_name']}",
        "documentNamespace": ns,
        "creationInfo": {
            "created": created,
            "creators": [f"Tool: {TOOL_NAME}-{TOOL_VERSION}", f"Organization: {ORG}"],
        },
        "packages": packages,
        "relationships": relationships,
    }


# --------------------------------------------------------------------------- #
# Structural validation (no network, no external deps — the offline half of
# the designed validation step; the online half is cyclonedx-cli/py validation).
# --------------------------------------------------------------------------- #
_SHA_RE = re.compile(r"^[0-9a-f]{64}$")
_PURL_RE = re.compile(r"^pkg:cargo/[a-z0-9._-]+@[0-9A-Za-z.+~_-]+$")


def validate_cyclonedx(bom: dict) -> list[str]:
    errs = []
    if bom.get("bomFormat") != "CycloneDX":
        errs.append("bomFormat must be 'CycloneDX'")
    if bom.get("specVersion") != CDX_SPEC:
        errs.append(f"specVersion must be '{CDX_SPEC}'")
    if not str(bom.get("serialNumber", "")).startswith("urn:uuid:"):
        errs.append("serialNumber must be a urn:uuid:")
    main = bom.get("metadata", {}).get("component", {})
    if main.get("type") != "firmware" or not main.get("name"):
        errs.append("metadata.component must be a named firmware component")
    if not _SHA_RE.match((main.get("hashes") or [{}])[0].get("content", "")):
        errs.append("metadata.component needs a SHA-256 hash")
    refs = [main.get("bom-ref")]
    for comp in bom.get("components", []):
        ref = comp.get("bom-ref")
        if not ref or ref in refs:
            errs.append(f"missing/duplicate bom-ref: {ref!r}")
        refs.append(ref)
        if not comp.get("name") or not comp.get("version"):
            errs.append(f"component lacks name/version: {ref!r}")
        if "purl" in comp and not _PURL_RE.match(comp["purl"]):
            errs.append(f"malformed cargo purl: {comp['purl']!r}")
        for lic in comp.get("licenses", []):
            if "expression" not in lic and "license" not in lic:
                errs.append(f"license entry without expression/license: {ref!r}")
    if not bom.get("components"):
        errs.append("no components generated")
    return errs


def validate_spdx(doc: dict) -> list[str]:
    errs = []
    if doc.get("spdxVersion") != SPDX_SPEC:
        errs.append("spdxVersion must be SPDX-2.3")
    if doc.get("dataLicense") != "CC0-1.0":
        errs.append("dataLicense must be CC0-1.0")
    if not doc.get("documentNamespace", "").startswith("https://"):
        errs.append("documentNamespace must be an https URI")
    if not doc.get("creationInfo", {}).get("created"):
        errs.append("creationInfo.created missing")
    ids = [doc["SPDXID"]]
    for pkg in doc.get("packages", []):
        pid = pkg.get("SPDXID", "")
        if not pid.startswith("SPDXRef-") or pid in ids:
            errs.append(f"missing/duplicate SPDXID: {pid!r}")
        ids.append(pid)
    if not any(r.get("relationshipType") == "DESCRIBES" for r in doc.get("relationships", [])):
        errs.append("document must DESCRIBES at least one package")
    return errs


# --------------------------------------------------------------------------- #
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Generate CycloneDX 1.6 + SPDX 2.3 SBOMs from an existing "
                    "DCENT_OS drop-1 release set's signed dependency evidence "
                    "(no rebuild).",
        epilog=f"DCENT_ open-source trust tooling — {ORG}. "
               f"Fund / support: {FUND_URL}",
    )
    ap.add_argument("release_set_dir", help="directory holding <artifact>."
                    ".rust-dependencies.json and <artifact>.buildroot-legal.json")
    ap.add_argument("--artifact", help="artifact filename prefix when the dir "
                    "holds more than one set")
    ap.add_argument("--format", choices=["cyclonedx", "spdx", "both"], default="both")
    ap.add_argument("--out", help="output path for a single --format; "
                    "never written inside the evidence dir by default")
    ap.add_argument("--out-dir", help="directory for <artifact>.sbom.cyclonedx.json "
                    "and <artifact>.sbom.spdx.json (format=both)")
    ap.add_argument("--validate-only", action="store_true",
                    help="generate in memory, validate, write nothing")
    ap.add_argument("--indent", type=int, default=1)
    args = ap.parse_args(argv)

    set_dir = os.path.abspath(args.release_set_dir)
    if not os.path.isdir(set_dir):
        _fail(f"not a directory: {set_dir}")
    try:
        ev = load_evidence(set_dir, args.artifact)
    except (EvidenceError, json.JSONDecodeError) as exc:
        _fail(str(exc))

    # Pull source_commit from the sibling release metadata when present.
    for cand in os.listdir(set_dir):
        if cand.endswith(".release.txt"):
            for line in open(os.path.join(set_dir, cand), "r", encoding="utf-8",
                             errors="replace"):
                if line.startswith("source_commit="):
                    ev["source_commit"] = line.split("=", 1)[1].strip()
                    break
            break

    outputs = {}
    if args.format in ("cyclonedx", "both"):
        outputs["cyclonedx"] = build_cyclonedx(ev)
    if args.format in ("spdx", "both"):
        outputs["spdx"] = build_spdx(ev)

    failed = False
    for fmt, doc in outputs.items():
        errs = (validate_cyclonedx if fmt == "cyclonedx" else validate_spdx)(doc)
        n_comp = len(doc.get("components", doc.get("packages", [])))
        if errs:
            failed = True
            print(f"[{fmt}] INVALID ({len(errs)} errors):")
            for e in errs:
                print(f"  - {e}")
        else:
            print(f"[{fmt}] VALID — {n_comp} components, "
                  f"artifact {ev['artifact_name']} "
                  f"sha256:{ev['artifact_sha256'][:16]}…")

    if failed:
        return 1
    if args.validate_only:
        return 0

    if args.out and len(outputs) == 1:
        path = os.path.abspath(args.out)
        if os.path.dirname(os.path.abspath(path)) == os.path.abspath(set_dir):
            _fail("refusing to write inside the read-only evidence directory")
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(next(iter(outputs.values())), fh, indent=args.indent,
                      sort_keys=True)
            fh.write("\n")
        print(f"wrote {path}")
    elif args.out_dir:
        os.makedirs(args.out_dir, exist_ok=True)
        for fmt, doc in outputs.items():
            ext = "cyclonedx" if fmt == "cyclonedx" else "spdx"
            path = os.path.join(args.out_dir, f"{ev['artifact_name']}.sbom.{ext}.json")
            if os.path.abspath(os.path.dirname(path)) == os.path.abspath(set_dir) \
                    and os.path.abspath(args.out_dir) == os.path.abspath(set_dir):
                _fail("refusing to write inside the read-only evidence directory")
            with open(path, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(doc, fh, indent=args.indent, sort_keys=True)
                fh.write("\n")
            print(f"wrote {path}")
    else:
        for doc in outputs.values():
            json.dump(doc, sys.stdout, indent=args.indent, sort_keys=True)
            print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
