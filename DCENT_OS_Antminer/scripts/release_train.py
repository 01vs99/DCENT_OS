#!/usr/bin/env python3
"""Release train: exact registry channels joined to declared build/media routes.

BoardDesc ReleaseChannel is authoritative for Beta/Stable publication eligibility.
First-install, self-update and external-media capabilities remain independent.
Every current Beta engine row has a declared producer. Architecture cohorts
share authenticated Cargo/dashboard output and retain post-cleanup source audits.
Buildability is not a claim of physical validation or a new installer.

Every public artifact requires a trusted signature. Runtime metadata is generated
from the final executable and enclosed by the signed outer image/package.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DCENTOS_DIR = os.path.dirname(SCRIPT_DIR)

# ---------------------------------------------------------------------------
# Target table
# ---------------------------------------------------------------------------

ROUTE_FIRST_INSTALL = "first_install_and_self_update"
ROUTE_SELF_UPDATE = "self_update_only"
ROUTE_SD_TRIAL = "sd_trial_boot_only"
ROUTE_OPERATOR_STAGED = "operator_staged"
ROUTE_PENDING = "pending_adjudication"

CHANNEL_BETA = "beta"
# Compatibility name consumed by the generated route catalog. SD trial is a
# media capability; its signed release channel is Beta like other engine rows.
CHANNEL_EXPBETA = CHANNEL_BETA

FUND_URL = "https://d-central.tech/fund/"


@dataclass(frozen=True)
class TrainTarget:
    """One train slot.  Every field is checkable without building."""

    name: str
    drops: Tuple[int, ...]
    board_target: str  # canonical board_desc.rs registry key (admission source)
    policy_target: Optional[str]  # release_capsule_target_policy key or None
    lane_kind: str
    lane_command: Tuple[str, ...]  # argv, cwd=DCENTOS_DIR; {date} expanded
    expected_artifact: str  # display/legacy catalog only; execution reads strict results
    install_route: str
    reproducible: bool
    blocked_reason: str = ""
    notes: str = ""
    producer: Optional[str] = None


def _producer_targets() -> List[TrainTarget]:
    from release_producer import list_producers, MISSING_PRODUCERS
    # Presentation names retain Toolbox guide compatibility. All build facts
    # and exact board identities come from the canonical producer table.
    names = {"am2-s17p": "s17-s17pro", "am2-s17plus": "s17plus",
             "am2-t17": "t17", "am2-t17plus": "t17plus"}
    names.update({"am1-" + model: model for model in ("s9i", "s9j", "s9se", "s9k", "s15", "t15")})
    def _producer_notes(row) -> str:
        if row.install_route == ROUTE_OPERATOR_STAGED:
            return ("Signed runtime package only; no supported persistent or media installation route.")
        # AM1-A Drop-1 route scoping (owner adjudication
        #
        # Option A, ratified 2026-09-15): the producer row keeps its declared
        # route (a fitting rootfs restores the dual-route artifact from the
        # same row); a build whose am1-s9 rootfs exceeds the live-sysupgrade
        # window is packaged FIRST-INSTALL-ONLY through the signed manifest
        # contract (toolbox.install_mode=first_install_only), not a new
        # route value here. The self-update artifact is deferred to Drop-2.
        if row.producer == "s9":
            return ("Signed exact producer result; Drop-1 scoping: an over-window "
                    "am1-s9 rootfs packages first-install-only via the manifest "
                    "route contract (self-update deferred to Drop-2 per "
                    "adjudication AM1_S9 Option A); physical qualification pending.")
        return ("Signed exact producer result; storage/media policy remains independent; physical qualification pending.")
    targets = [TrainTarget(
        name=names.get(row.producer, row.producer), drops=(1,),
        board_target=row.board_target,
        policy_target=row.producer if row.producer in ("s9", "am2-s19jpro") else None,
        lane_kind="release_producer", producer=row.producer,
        lane_command=("bash", "scripts/build_release_capsule.sh", "--producer", row.producer, "--channel", "beta"),
        expected_artifact=row.primary_artifact, install_route=row.install_route,
        reproducible=row.reproducible,
        notes=_producer_notes(row),
    ) for row in list_producers()]
    targets.extend(TrainTarget(
        name=board, drops=(1,), board_target=board, policy_target=None,
        lane_kind="missing_producer", lane_command=(), expected_artifact="",
        install_route=ROUTE_PENDING, reproducible=False, blocked_reason=reason,
    ) for board, reason in MISSING_PRODUCERS.items())
    # Retain the distinct historical row for catalog compatibility. It is
    # explicitly excluded from Beta drops and cannot mint a producer result.
    targets.append(TrainTarget(
        name="am3-s19kpro", drops=(), board_target="am3-s19kpro",
        policy_target="am3-s19kpro", lane_kind="unsupported", lane_command=(),
        expected_artifact="", install_route=ROUTE_OPERATOR_STAGED, reproducible=False,
        blocked_reason="registered board is Unsupported and has no admitted work engine.",
    ))
    return targets


TARGETS: List[TrainTarget] = _producer_targets()

# ---------------------------------------------------------------------------
# Admission reader (board_desc.rs is the ring source of truth)
# ---------------------------------------------------------------------------

BOARD_DESC_RELPATH = os.path.join(
    "dcentrald", "dcentrald-common", "src", "board_desc.rs"
)

_CONSTRUCTOR_RE = re.compile(
    r"pub const fn (\w+)\(\) -> Self \{\s*Self \{(.*?)\n        \}\n    \}", re.S
)
_BOARD_TARGET_RE = re.compile(r'board_target:\s*"([^"]+)"')
_ADMISSION_RE = re.compile(r"release_channel:\s*ReleaseChannel::(\w+)")
_ALIASES_RE = re.compile(r"BOARD_TARGET_ALIASES[^=]*=\s*&\[(.*?)\];", re.S)
_ALIAS_PAIR_RE = re.compile(r'\("([^"]+)",\s*"([^"]+)"\)')

PUBLISHABLE_RINGS = ("Beta", "Stable")


class TrainError(RuntimeError):
    """Hard train-contract violation (plan or run)."""


def parse_install_admissions(source: str) -> Dict[str, str]:
    """Extract exact registered ReleaseChannel rows (legacy API name for exporter)."""
    table: Dict[str, str] = {}
    for match in _CONSTRUCTOR_RE.finditer(source):
        body = match.group(2)
        board = _BOARD_TARGET_RE.search(body)
        admission = _ADMISSION_RE.search(body)
        if board:
            if not admission or admission.group(1) not in ("Beta", "Stable", "Unsupported"):
                raise TrainError(f"missing or unknown release channel for {board.group(1)}")
            if board.group(1) in table:
                raise TrainError(f"duplicate board target {board.group(1)}")
            table[board.group(1)] = admission.group(1)
    if not table:
        raise TrainError("no BoardDesc constructors parsed from board_desc.rs")
    return table


def parse_board_target_aliases(source: str) -> Dict[str, str]:
    """Extract the BOARD_TARGET_ALIASES canonicalization map from board_desc.rs."""
    match = _ALIASES_RE.search(source)
    if not match:
        return {}
    return dict(_ALIAS_PAIR_RE.findall(match.group(1)))


def canonical_board_target(spelling: str, aliases: Dict[str, str]) -> str:
    return aliases.get(spelling, spelling)


def load_admissions(dcentos_dir: str = DCENTOS_DIR) -> Dict[str, str]:
    path = os.path.join(dcentos_dir, BOARD_DESC_RELPATH)
    with open(path, "r", encoding="utf-8") as handle:
        return parse_install_admissions(handle.read())


def load_aliases(dcentos_dir: str = DCENTOS_DIR) -> Dict[str, str]:
    path = os.path.join(dcentos_dir, BOARD_DESC_RELPATH)
    with open(path, "r", encoding="utf-8") as handle:
        return parse_board_target_aliases(handle.read())


def first_install_supported(board_target: str) -> bool:
    with open(os.path.join(DCENTOS_DIR, BOARD_DESC_RELPATH), encoding="utf-8") as handle:
        for constructor in _CONSTRUCTOR_RE.finditer(handle.read()):
            body = constructor.group(2)
            board = _BOARD_TARGET_RE.search(body)
            if board and board.group(1) == board_target:
                return bool(re.search(r"first_install_supported:\s*true\b", body))
    return False


def workspace_version() -> str:
    with open(os.path.join(DCENTOS_DIR, "dcentrald/Cargo.toml"), encoding="utf-8") as handle:
        match = re.search(r'(?ms)^\[workspace\.package\]\s*(.*?)(?=^\[|\Z)', handle.read())
    version = re.search(r'^version\s*=\s*"([^"\r\n]+)"', match.group(1), re.M) if match else None
    if not version:
        raise TrainError("cannot read exact workspace build version")
    return version.group(1)


# ---------------------------------------------------------------------------
# Historical capsule naming (current build facts are in release_producer.py)
# ---------------------------------------------------------------------------

sys.path.insert(0, SCRIPT_DIR)
import release_capsule_target_policy as capsule_policy  # noqa: E402


def stem_for(policy_target: Optional[str]) -> Optional[str]:
    if not policy_target:
        return None
    return capsule_policy.policy_for(policy_target).release_stem


def expected_artifact_glob(target: TrainTarget, date: str) -> str:
    if "{stem}" in target.expected_artifact:
        stem = stem_for(target.policy_target)
        if not stem:
            raise TrainError(f"target {target.name} has a stem placeholder but no policy")
        return target.expected_artifact.replace("{stem}", stem).replace("{date}", date)
    return target.expected_artifact.replace("{date}", date)


def validate_capsule_name(policy_target: str, date: str) -> str:
    """Build the canonical capsule name and validate via the frozen policy."""
    record = capsule_policy.policy_for(policy_target)
    name = f"{record.release_stem}_beta{date}"
    return capsule_policy.validate_output_name(record, name)


# ---------------------------------------------------------------------------
# Planning
# ---------------------------------------------------------------------------


@dataclass
class PlannedTarget:
    target: TrainTarget
    ring: str
    executable: bool
    issues: List[str] = field(default_factory=list)

    @property
    def hard_violation(self) -> bool:
        return bool(self.issues)


def plan_target(target: TrainTarget, admissions: Dict[str, str]) -> PlannedTarget:
    ring = admissions.get(target.board_target)
    issues: List[str] = []
    if ring is None:
        issues.append(
            f"board target {target.board_target!r} not found in board_desc.rs registry"
        )
        ring = "Unknown"

    if target.install_route in (ROUTE_FIRST_INSTALL, ROUTE_SD_TRIAL, ROUTE_SELF_UPDATE):
        if ring not in PUBLISHABLE_RINGS:
            issues.append(f"publish route requires Beta/Stable release channel, found {ring}")
        if target.install_route == ROUTE_FIRST_INSTALL and not first_install_supported(target.board_target):
            issues.append("first-install route requires BoardDesc.first_install_supported")
    elif target.install_route == ROUTE_OPERATOR_STAGED:
        if ring not in ("Unsupported", "Beta", "Stable"):
            issues.append(f"operator-staged route has nonsensical ring {ring}")
    elif target.install_route == ROUTE_PENDING:
        # A placeholder slot for a lane that has not adjudicated its route
        # yet.  It is only legal while the target carries a blocked_reason;
        # an unblocked pending target is a hard violation (it would run a
        # lane whose publish posture nobody has decided).
        if not target.blocked_reason:
            issues.append("pending_adjudication route requires a blocked_reason")
    else:
        issues.append(f"unknown install route {target.install_route!r}")

    if target.policy_target:
        try:
            record = capsule_policy.policy_for(target.policy_target)
        except capsule_policy.TargetPolicyError as error:
            issues.append(f"policy lookup failed: {error}")
        else:
            aliases = load_aliases()
            canonical_package_board = canonical_board_target(
                record.package_board, aliases
            )
            if canonical_package_board != target.board_target:
                issues.append(
                    f"policy package_board {record.package_board!r} (canonical "
                    f"{canonical_package_board!r}) != train board_target "
                    f"{target.board_target!r}"
                )

    executable = bool(target.lane_command)
    if executable:
        for program in target.lane_command:
            if not program.startswith("scripts/") and program != target.lane_command[0]:
                continue
            if "/" not in program and os.sep not in program:
                continue
            script = os.path.join(DCENTOS_DIR, *program.split("/"))
            if not os.path.isfile(script):
                issues.append(f"lane script missing: {program}")
    return PlannedTarget(target=target, ring=ring, executable=executable, issues=issues)


def drop_targets(drop: int) -> List[TrainTarget]:
    return [t for t in TARGETS if any(first_drop <= drop for first_drop in t.drops)]


def resolve_targets(drop: Optional[int], names: Optional[List[str]]) -> List[TrainTarget]:
    if names:
        by_name = {t.name: t for t in TARGETS}
        unknown = [n for n in names if n not in by_name]
        if unknown:
            raise TrainError(f"unknown train target(s): {', '.join(unknown)}")
        return [by_name[n] for n in names]
    if drop is None:
        raise TrainError("one of --drop or --target is required")
    return drop_targets(drop)


# ---------------------------------------------------------------------------
# Running
# ---------------------------------------------------------------------------


def sha256_file(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_fund_link(artifact_path: str, *, include_sidecars: bool = True) -> Tuple[bool, str]:
    """True iff the artifact (or its text sidecars) carries the fund URL."""
    sidecars = (
        "TESTER_README.txt",
        "BUILD_INFO.txt",
        "README.md",
        "SHA256SUMS",
    )
    base = artifact_path
    for sidecar in sidecars if include_sidecars else ():
        candidate = os.path.join(os.path.dirname(base), sidecar)
        if os.path.isfile(candidate):
            try:
                with open(candidate, "r", encoding="utf-8", errors="replace") as handle:
                    if FUND_URL in handle.read():
                        return True, f"sidecar {sidecar}"
            except OSError:
                pass
    if tarfile.is_tarfile(artifact_path):
        try:
            with tarfile.open(artifact_path, "r:*") as tar:
                for member in tar:
                    if not member.isfile() or member.size > 2_000_000:
                        continue
                    if not member.name.lower().endswith(
                        (".txt", ".md", ".json", ".html", ".sh")
                    ):
                        continue
                    extracted = tar.extractfile(member)
                    if extracted is None:
                        continue
                    data = extracted.read(2_000_000)
                    if FUND_URL.encode("utf-8") in data:
                        return True, f"tar member {member.name}"
        except (tarfile.TarError, OSError):
            return False, "unreadable tar"
    return False, "not found"


def validate_native_media_candidate(artifact: str, producer, version: str,
                                    channel: str, key: str, recipe: str) -> Dict:
    """Train-side media gate for the BM1391 lanes, delegated to the capsule's
    own per-board native-media reader so the gate and the sealed artifact
    share one contract. The previous hand-rolled bm1391_sd_media reader
    demanded a 2026-09-10 manifest schema and stale reviewed pins that the
    standardized native media (native-release-media/v1) never carries
    (drop1-20260922 latent: am1-s15/am1-t15 unqualified after full build
    cost)."""
    from release_producer import verify_native_media
    return verify_native_media(Path(artifact), producer, version, channel,
                               Path(key), hardware_recipe=recipe)


def _execute_lane(
    target: TrainTarget, date: str, scratch: str, log_name: str, extra_args: Tuple[str, ...] = ()
) -> Tuple[int, Optional[str]]:
    """Run once, retaining at most 5 MB of recent diagnostic output."""
    command = [part.replace("{date}", date) for part in target.lane_command]
    command.extend(extra_args)
    if command[0] == "bash":
        # Windows CreateProcess searches system directories before PATH for a
        # bare executable name, selecting the WSL launcher even inside Git
        # Bash. Resolve explicitly so the lane keeps its host paths and the
        # inherited signing/toolchain environment.
        shell = shutil.which("bash")
        if shell is None or (os.name == "nt" and Path(shell).parent.name.lower() in {"system32", "sysnative"}):
            raise TrainError("release lanes require Git Bash on Windows; start the train from Git Bash")
        command[0] = shell
    log_path = os.path.join(scratch, log_name)
    limit = 5_000_000
    with open(log_path, "w+b") as log:
        with subprocess.Popen(command, cwd=DCENTOS_DIR, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT) as process:
            assert process.stdout is not None
            # read1 returns as soon as any output is available; a plain read
            # would block until a full 64 KiB chunk or EOF, hiding silent
            # compile/link phases from the live log and making a healthy lane
            # look hung (drop1-20260922 lane s9: 44 minutes of quiet cargo
            # linking read as a frozen producer).
            for chunk in iter(lambda: process.stdout.read1(64 * 1024), b""):
                if log.tell() + len(chunk) > limit:
                    log.seek(-(limit // 2), os.SEEK_END)
                    retained = log.read()
                    log.seek(0)
                    log.truncate()
                    log.write(retained)
                log.write(chunk)
                log.flush()
            returncode = process.wait()
    return returncode, os.path.abspath(log_path)


def run_lane(
    planned: PlannedTarget,
    date: str,
    scratch_root: str,
    skip: set,
    with_repro: bool = False,
    prebuilt: Optional[Dict] = None,
    comparison: Optional[Dict] = None,
) -> Dict:
    """Execute one lane (or record why it was skipped) and verify artifacts."""
    target = planned.target
    result: Dict = {
        "name": target.name,
        "board_target": target.board_target,
        "ring": planned.ring,
        "install_route": target.install_route,
        "channel": planned.ring.lower(),
        "version": workspace_version(),
        "blocked_reason": target.blocked_reason,
        "status": None,
        "lane_command": list(target.lane_command) or None,
        "lane_log": None,
        "artifact": None,
        "reproducibility": None,
        "publish": None,
        "fund_link": None,
        "notes": target.notes,
    }
    scratch = os.path.join(scratch_root, target.name)
    os.makedirs(scratch, exist_ok=True)

    if target.name in skip:
        result["status"] = "skipped"
        return result
    if target.blocked_reason:
        result["status"] = "blocked"
        return result
    if not planned.executable:
        result["status"] = "no-lane"
        return result

    from release_producer import get_producer, load_result, verify_result, verify_cohort
    row = get_producer(target.producer)
    output_root = os.path.join(scratch, "capsule")
    result_path = os.path.join(scratch, "producer-result.json")
    expected_commit = prebuilt["source_commit"] if prebuilt else _git_head()
    extra = ("--date", date, "--output-root", output_root, "--result-json", result_path)
    if prebuilt is None:
        rc, rel_log = _execute_lane(target, date, scratch, "lane.log", extra_args=extra)
    else:
        rc, rel_log = prebuilt.get("rc", 0), prebuilt.get("log")
        output_root = prebuilt["root"]
        if prebuilt["status"] != "built":
            result.update(status=prebuilt["status"], validation_error=prebuilt.get("error", "cohort failed"), lane_log=rel_log)
            return result
    result["lane_log"] = rel_log
    if rc != 0:
        result.update(status="lane-failed", lane_rc=rc)
        return result
    try:
        key = os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
        if not key:
            raise TrainError("trusted release public key is required")
        recipe = os.environ.get("DCENT_RELEASE_HARDWARE_RECIPE", row.hardware_recipe)
        if prebuilt is None:
            group = load_result(Path(result_path))
            verify_cohort(group, Path(output_root), [row.producer], expected_commit,
                          result["version"], result["channel"], Path(key), recipe)
            document = group["results"][0]
        else:
            document = prebuilt["document"]
        verify_result(document, Path(output_root), row, expected_commit,
                      result["version"], result["channel"], Path(key), recipe)
        primary = document["files"]["primary"]
        artifact = os.path.join(output_root, *primary["path"].split("/"))
        result.update(producer_result=document, producer_output_root=output_root,
                      source_commit=expected_commit, hardware_recipe=recipe)
        result["artifact"] = {"path": os.path.relpath(artifact, DCENTOS_DIR),
                              "sha256": primary["sha256"], "bytes": primary["size"]}
        # The set mirrors the BM1391 lanes that owe an explicit train-side
        # evidence record; every native-sd producer is additionally verified
        # by verify_result regardless of this set.
        if target.board_target in {"am1-s15", "am1-t15"}:
            result["native_media_validation"] = validate_native_media_candidate(
                artifact, row, result["version"], result["channel"], key, recipe)
    except (ValueError, OSError, TrainError) as error:
        result.update(status="artifact-unqualified", validation_error=str(error))
        return result

    if target.reproducible:
        if with_repro:
            identical = False
            rel_log2 = comparison.get("log") if comparison else None
            if prebuilt is None:
                repro_scratch = os.path.join(scratch, "repro-pass2")
                os.makedirs(repro_scratch, exist_ok=True)
                second_root = os.path.join(repro_scratch, "capsule")
                second_json = os.path.join(repro_scratch, "producer-result.json")
                rc2, rel_log2 = _execute_lane(target, date, repro_scratch, "lane.log",
                    extra_args=("--date", date, "--output-root", second_root, "--result-json", second_json))
                if rc2 == 0:
                    try:
                        group = load_result(Path(second_json))
                        verify_cohort(group, Path(second_root), [row.producer], expected_commit,
                                      result["version"], result["channel"], Path(key), recipe)
                        comparison = {"status": "built", "document": group["results"][0], "root": second_root}
                    except (ValueError, OSError):
                        pass
            pass2_evidence: Optional[Dict] = None
            if comparison and comparison["status"] == "built":
                try:
                    second = comparison["document"]
                    verify_result(second, Path(comparison["root"]), row, expected_commit,
                                  result["version"], result["channel"], Path(key), recipe)
                    identical = all(document["files"][role]["sha256"] == second["files"][role]["sha256"]
                                    for role in document["files"])
                    # Bind the pass-2 claim to the SIGNED pass-2 result: a
                    # resumed run re-runs verify_result over this document and
                    # its bytes in the repro cohort tree, so a forged
                    # identical-claim needs fabricated, signed build output —
                    # a JSON edit alone proves nothing.
                    pass2_evidence = {"pass2_root": comparison["root"],
                                      "pass2_document": second,
                                      "pass2_primary": dict(path=second["files"]["primary"]["path"],
                                                            sha256=second["files"]["primary"]["sha256"])}
                except (ValueError, OSError):
                    pass
            reproducibility = {"compared": True, "identical": identical, "pass2_log": rel_log2}
            if identical and pass2_evidence:
                reproducibility.update(pass2_evidence)
            result["reproducibility"] = reproducibility
        else:
            result["reproducibility"] = {"compared": False, "reason": "debug subset omitted comparison"}
    fund_ok, fund_where = scan_result_fund_link(document, output_root)
    result["fund_link"] = {"ok": fund_ok, "where": fund_where}
    result["status"] = "built"
    if not fund_ok:
        result["status"] = "fund-link-failed"
    if with_repro and target.reproducible and not result["reproducibility"]["identical"]:
        result["status"] = "repro-mismatch"
    return result


def _execute_cohort(planned: List[PlannedTarget], date: str, scratch: str,
                    channel_base_url: Optional[str] = None, session: Optional[str] = None,
                    protect: Optional[set] = None) -> Dict[str, Dict]:
    from release_producer import get_producer, load_result, verify_cohort
    os.makedirs(scratch, exist_ok=True)
    rows = [get_producer(item.target.producer) for item in planned]
    command = ["bash", "scripts/build_release_capsule.sh", "--channel", "beta"]
    if channel_base_url:
        command.extend(("--feed-base-url", channel_base_url))
    for row in rows:
        command.extend(("--producer", row.producer))
    target = planned[0].target
    from dataclasses import replace
    target = replace(target, lane_command=tuple(command))
    # Segmented invocations share the cohort directory across sessions, so
    # the invocation-scoped result JSON and log must not collide with (or
    # truncate) a previous session's evidence.
    suffix = f"-{session}" if session else ""
    output_root = os.path.join(scratch, "capsule")
    result_json = os.path.join(scratch, f"cohort-result{suffix}.json")
    if session and os.path.lexists(result_json) \
            and os.path.realpath(result_json) not in (protect or set()):
        # A previous attempt at this session number died after the capsule
        # wrote its result but before the train sealed the lanes (crash
        # window). The invocation-scoped JSON is output, not evidence — the
        # capsule builder refuses to run against a stale one (exit 2), and
        # the lanes about to rebuild were by definition never sealed. An
        # ADOPTED invocation file is the on-disk recovery evidence for lanes
        # already in memory but not yet sealed; it is never stale.
        os.unlink(result_json)
    source_commit, version = _git_head(), workspace_version()
    rc, log = _execute_lane(target, date, scratch, f"cohort{suffix}.log",
        extra_args=("--date", date, "--output-root", output_root, "--result-json", result_json))
    base = {"source_commit": source_commit, "root": output_root, "log": log, "rc": rc}
    if rc:
        return {row.producer: {**base, "status": "lane-failed"} for row in rows}
    try:
        key = os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
        if not key:
            raise TrainError("trusted release public key is required")
        document = load_result(Path(result_json))
        verify_cohort(document, Path(output_root), [row.producer for row in rows], source_commit,
                      version, "beta", Path(key), os.environ.get("DCENT_RELEASE_HARDWARE_RECIPE", "board-default"))
        from release_producer_evidence import verify_cohort_evidence
        verify_cohort_evidence(document, Path(output_root), [row.producer for row in rows], source_commit,
                              version, "beta", Path(key), Path(DCENTOS_DIR).parents[1],
                              os.environ.get("DCENT_RELEASE_HARDWARE_RECIPE", "board-default"), channel_base_url)
        return {row.producer: {**base, "status": "built", "document": result}
                for row, result in zip(rows, document["results"])}
    except (ValueError, OSError, TrainError) as error:
        return {row.producer: {**base, "status": "artifact-unqualified", "error": str(error)} for row in rows}


def run_selected_cohorts(planned: List[PlannedTarget], date: str, scratch: str,
                         skip: set, with_repro: bool, channel_base_url: Optional[str] = None,
                         session: Optional[str] = None, on_result=None,
                         recovered: Optional[Dict[str, Dict]] = None,
                         recovered_comparison: Optional[Dict[str, Dict]] = None,
                         protect: Optional[set] = None) -> List[Dict]:
    from release_producer import get_producer
    groups: Dict[str, List[PlannedTarget]] = {}
    for item in planned:
        if item.target.name not in skip:
            groups.setdefault(get_producer(item.target.producer).cargo_variant, []).append(item)
    first, second = {}, {}
    feed_args = {"channel_base_url": channel_base_url} if channel_base_url else {}
    for variant, members in groups.items():
        prebuilt = recovered or {}
        build_members = [member for member in members if member.target.producer not in prebuilt]
        if build_members:
            first.update(_execute_cohort(build_members, date, os.path.join(scratch, "cohort-" + variant),
                                         session=session, protect=protect, **feed_args))
        for member in members:
            if member.target.producer in prebuilt:
                # A completed-but-unprocessed capsule invocation from a
                # crashed session: already re-verified, no rebuild owed.
                first[member.target.producer] = prebuilt[member.target.producer]
        reproducible = [member for member in members if member.target.reproducible]
        if with_repro and reproducible and all(first[member.target.producer]["status"] == "built" for member in reproducible):
            comparison = recovered_comparison or {}
            repro_build = [member for member in reproducible if member.target.producer not in comparison]
            if repro_build:
                second.update(_execute_cohort(repro_build, date,
                                              os.path.join(scratch, "cohort-" + variant + "-repro"),
                                              session=session, protect=protect, **feed_args))
            for member in reproducible:
                if member.target.producer in comparison:
                    # A completed-but-unprocessed repro invocation: the
                    # byte-identity comparison proceeds without a rebuild.
                    second[member.target.producer] = comparison[member.target.producer]
    results: List[Dict] = []
    for item in planned:
        outcome = run_lane(item, date, scratch, skip, with_repro,
                           prebuilt=first.get(item.target.producer), comparison=second.get(item.target.producer))
        results.append(outcome)
        if on_result is not None:
            # Per-lane hand-off (segment sealing): a crash later in the
            # segment keeps every lane whose verification already completed.
            on_result(outcome)
    return results


SEGMENTS_SUBDIR = "segments"
SEGMENT_SCHEMA = "dcentos.train-segments.v1"


def _segment_state_path(scratch_root: str) -> str:
    return os.path.join(scratch_root, SEGMENTS_SUBDIR, "state.json")


def _segment_results_dir(scratch_root: str) -> str:
    return os.path.join(scratch_root, SEGMENTS_SUBDIR, "results")


def write_segment_state(scratch_root: str, state: Dict) -> None:
    """Persist segment state atomically; the run directory outlives crashes."""
    path = _segment_state_path(scratch_root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(state, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, path)


def load_segment_state(scratch_root: str) -> Dict:
    path = _segment_state_path(scratch_root)
    if not os.path.isfile(path):
        raise TrainError("run directory has no segment state; nothing to resume")
    with open(path, encoding="utf-8") as handle:
        state = json.load(handle)
    if not isinstance(state, dict) or state.get("schema") != SEGMENT_SCHEMA:
        raise TrainError("run directory carries an unknown segment state schema")
    return state


def persist_segment_result(scratch_root: str, result: Dict) -> None:
    """Seal one built lane: the full verified result record, atomically."""
    directory = _segment_results_dir(scratch_root)
    os.makedirs(directory, exist_ok=True)
    stem = "".join(ch if (ch.isalnum() or ch in "-_.") else "_" for ch in result["name"])
    tmp = os.path.join(directory, stem + ".json.tmp")
    final = os.path.join(directory, stem + ".json")
    with open(tmp, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(result, handle, indent=2, sort_keys=True)
        handle.write("\n")
    os.replace(tmp, final)


def load_segment_results(scratch_root: str) -> Dict[str, Dict]:
    directory = _segment_results_dir(scratch_root)
    sealed: Dict[str, Dict] = {}
    if not os.path.isdir(directory):
        return sealed
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".json"):
            continue
        with open(os.path.join(directory, name), encoding="utf-8") as handle:
            result = json.load(handle)
        if not isinstance(result, dict) or not result.get("name"):
            raise TrainError(f"sealed result file {name} is not a result record")
        sealed[result["name"]] = result
    return sealed


def _verify_sealed_lane_bytes(result: Dict, run_root: str) -> Tuple:
    """Per-lane disk proofs: a built record whose capsule output lives inside
    this run directory, a signed publication that still verifies against the
    bytes on disk, and the fund link."""
    name = result.get("name", "<unnamed>")
    if result.get("status") != "built" or not result.get("artifact"):
        raise TrainError(f"sealed result {name} is not a built record")
    document = result.get("producer_result")
    if not isinstance(document, dict) or not document.get("producer"):
        raise TrainError(f"sealed result {name} carries no producer result document")
    output_root = str(result.get("producer_output_root"))
    if not os.path.isdir(output_root):
        raise TrainError(f"sealed result {name} lost its capsule output root")
    sealed_root = os.path.realpath(output_root)
    if os.path.commonpath([sealed_root, run_root]) != run_root:
        raise TrainError(f"sealed result {name} points at capsule output outside this run directory")
    source = os.path.join(DCENTOS_DIR, result["artifact"]["path"])
    if not os.path.isfile(source):
        raise TrainError(f"sealed artifact for {name} is missing on disk")
    # verify_publication re-runs the signed-result verification (member
    # hashes, signatures, producer row, source commit) against the bytes
    # still on disk before any new lane is built.
    verify_publication(result, source)
    fund_ok, _where = scan_result_fund_link(document, output_root)
    if not fund_ok:
        raise TrainError(f"sealed result {name} no longer carries the fund link")
    from release_producer import get_producer
    return get_producer(document["producer"]), document, output_root, sealed_root


def _verify_sealed_reproducibility(result: Dict, row, document: Dict,
                                   output_root: str, run_root: str, key: str) -> None:
    """A claimed identical pass-2 rebuild must still be provable as a SIGNED
    second result living in the repro cohort tree: JSON-only edits (a
    forged identical-claim, or aliasing the pass-1 output as pass-2) fail
    either the structural confinement or the signature re-verification."""
    name = result.get("name", "<unnamed>")
    reproducibility = result.get("reproducibility") or {}
    if reproducibility.get("compared") and reproducibility.get("identical"):
        pass2_root = str(reproducibility.get("pass2_root") or "")
        pass2_document = reproducibility.get("pass2_document")
        pass2_primary = reproducibility.get("pass2_primary") or {}
        if not pass2_root or not isinstance(pass2_document, dict) or "path" not in pass2_primary \
                or "sha256" not in pass2_primary:
            raise TrainError(f"sealed result {name} claims reproducibility without signed pass-2 evidence")
        real_pass2 = os.path.realpath(pass2_root)
        real_pass1 = os.path.realpath(output_root)
        if os.path.commonpath([real_pass2, run_root]) != run_root:
            raise TrainError(f"sealed result {name} pass-2 evidence lives outside this run directory")
        if real_pass2 == real_pass1 or os.path.commonpath([real_pass2, real_pass1]) == real_pass1:
            raise TrainError(f"sealed result {name} pass-2 evidence aliases the pass-1 capsule output")
        repro_tree = os.sep + "cohort-" + row.cargo_variant + "-repro" + os.sep
        if repro_tree not in real_pass2 + os.sep:
            raise TrainError(f"sealed result {name} pass-2 evidence is not in the repro cohort tree")
        from release_producer import verify_result
        verify_result(pass2_document, Path(real_pass2), row,
                      result["source_commit"], result["version"], result["channel"],
                      Path(key), result["hardware_recipe"])
        if pass2_primary["sha256"] != pass2_document["files"]["primary"]["sha256"] \
                or pass2_primary["sha256"] != document["files"]["primary"]["sha256"]:
            raise TrainError(f"sealed result {name} pass-2 digest does not match its signed pass-1 artifact")


def verify_sealed_invocation(members: List[Dict], scratch_root: str,
                             channel_base_url: Optional[str] = None) -> None:
    """Verify one capsule invocation's sealed members as the cohort group the
    invocation actually was.

    The evidence verifier derives the expected cohort owner from rows[0] of
    the producer list it is handed, and the live invocation stamped EVERY
    member's release-invocation descriptor with the build target of its
    FIRST member as that owner (release_producer_evidence.verify_audit_contents).
    Re-verifying a member against any other member list computes a different
    owner and refuses honest evidence — the refusal that blocked the first
    live resume (Oct 1 2026). Members must therefore be re-verified together
    and in their original invocation order, exactly as the cohort runner
    first proved them.
    """
    if not members:
        raise TrainError("sealed invocation carries no members")
    run_root = os.path.realpath(scratch_root)
    key = os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
    if not key:
        raise TrainError("trusted release public key is required")
    verified = [_verify_sealed_lane_bytes(member, run_root) for member in members]
    for member in members[1:]:
        for field in ("source_commit", "version", "channel"):
            if member.get(field) != members[0].get(field):
                raise TrainError(f"sealed invocation members disagree on {field}: {member.get('name')}")
    from release_producer import COHORT_PROFILE, verify_cohort
    from release_producer_evidence import verify_cohort_evidence
    rows = [entry[0] for entry in verified]
    documents = [entry[1] for entry in verified]
    first_root = verified[0][3]
    group = {"manifest_profile": COHORT_PROFILE, "cargo_variant": rows[0].cargo_variant,
             "source_commit": members[0]["source_commit"], "version": members[0]["version"],
             "channel": members[0]["channel"], "results": documents}
    producers = [row.producer for row in rows]
    # The cohort-evidence chain (exact member set, source closure, installed
    # daemon, compiled update-feed base) runs for every lane in a fresh drop;
    # a resumed invocation owes the same proof — this is what refuses a debug
    # or foreign capsule grafted in at the same commit.
    verify_cohort(group, Path(first_root), producers,
                  members[0]["source_commit"], members[0]["version"], members[0]["channel"],
                  Path(key), members[0]["hardware_recipe"])
    verify_cohort_evidence(group, Path(first_root), producers,
                           members[0]["source_commit"], members[0]["version"], members[0]["channel"],
                           Path(key), Path(DCENTOS_DIR).parents[1],
                           members[0]["hardware_recipe"], channel_base_url)
    for member, (row, document, output_root, _sealed) in zip(members, verified):
        _verify_sealed_reproducibility(member, row, document, output_root, run_root, key)


def verify_sealed_segment_result(result: Dict, scratch_root: str,
                                 channel_base_url: Optional[str] = None) -> None:
    """A sealed lane re-enters a resumed drop only if it re-verifies from disk.

    Everything the single-process design proved in-process for a lane must be
    re-derivable from bytes on disk: the signed result (verify_publication),
    the fund link, the full cohort-evidence chain (exact capsule member set,
    source closure, installed daemon, compiled feed base), the pass-2
    reproducibility artifact, and containment inside this run directory —
    a sealed record may not point at capsule output belonging to any other
    run, debug subset, or commit. Single-member invocation convenience; a
    multi-member invocation must re-verify through
    verify_sealed_segment_results so the cohort owner matches the owner its
    evidence stamped.
    """
    verify_sealed_invocation([result], scratch_root, channel_base_url)


def next_segment_session(scratch_root: str, state: Dict) -> str:
    """The next session suffix, skipping numbers whose invocation artifacts
    already exist on disk.

    Session suffixes name this session's invocation artifacts
    (cohort-<variant>/cohort-segN.log, cohort-result-segN.json). The segment
    record is appended only after a whole cohort run, so a crash between the
    first per-lane seals and the record write makes the naive counter
    (len(segments)+1) REUSE the dead session's number: the rebuilt
    invocation would then share the dead one's log path, and sealed lanes
    from both invocations would merge into one invocation group on resume
    (critic W, Oct 2026). Skipping occupied numbers keeps every invocation's
    log path unique.
    """
    import glob
    recorded = {segment.get("session") for segment in state.get("segments", [])}
    session_number = len(recorded) + 1
    while f"seg{session_number}" in recorded \
            or glob.glob(os.path.join(scratch_root, "cohort-*", f"*seg{session_number}.*")):
        session_number += 1
    return f"seg{session_number}"


def verify_sealed_segment_results(sealed: Dict[str, Dict], scratch_root: str,
                                  channel_base_url: Optional[str],
                                  planned_names: List[str]) -> None:
    """Re-verify every sealed lane grouped into the invocations that built them.

    Members of one capsule invocation share one cohort log path in their
    sealed records (run_lane merges the invocation's log into each member's
    ``lane_log``), so that log is the invocation fingerprint. Within an
    invocation the original member order is the planned order restricted to
    that invocation (the cohort runner walks the planned list), which makes
    rows[0] reproduce the owner stamped into every member's
    release-invocation descriptor. A crash between per-member seal writes
    can leave one variant split across two invocations with different
    owners; grouping by invocation handles both that and the single
    full-variant invocation.
    """
    order = {name: index for index, name in enumerate(planned_names)}
    invocations: Dict[str, List[Dict]] = {}
    for name in sorted(sealed):
        if name not in order:
            raise TrainError(f"sealed lane {name} is not part of the planned drop")
        log = sealed[name].get("lane_log")
        if not log:
            # Without the invocation log the lane cannot be attributed to the
            # invocation whose owner its evidence stamps; a silent singleton
            # fallback would reproduce the owner refusal with a misleading
            # error (critic X MINOR-4).
            raise TrainError(f"sealed lane {name} carries no lane_log; cannot attribute its invocation")
        invocations.setdefault(str(log), []).append(sealed[name])
    for _log, members in sorted(invocations.items(),
                                 key=lambda item: min(order[member["name"]] for member in item[1])):
        members.sort(key=lambda member: order[member["name"]])
        verify_sealed_invocation(members, scratch_root, channel_base_url)


def bootstrap_orphaned_segment_state(scratch_root: str, drop, debug: bool) -> Dict:
    """Session one died before any state was written (crash between capsule
    completion and the first seal): recover the pinning fields from the run
    directory itself so its completed capsule invocations can be processed
    instead of rebuilt."""
    heads = set()
    dated = set()
    for entry in os.listdir(scratch_root):
        cohort = os.path.join(scratch_root, entry)
        if not entry.startswith("cohort-") or not os.path.isdir(cohort):
            continue
        releases = os.path.join(cohort, "capsule", "releases")
        if os.path.isdir(releases):
            for published in os.listdir(releases):
                stamp = re.search(r"_beta(\d{8})$", published)
                if stamp:
                    dated.add(stamp.group(1))
        for name in os.listdir(cohort):
            if not name.startswith("cohort-result") or not name.endswith(".json"):
                continue
            try:
                with open(os.path.join(cohort, name), encoding="utf-8") as handle:
                    document = json.load(handle)
                if not isinstance(document, dict):
                    continue  # torn write from the crash; it can pin nothing
                heads.add(document.get("source_commit"))
            except (ValueError, OSError):
                continue  # torn write from the crash; it can pin nothing
    if len(heads) != 1 or not next(iter(heads or [None])):
        raise TrainError("orphaned run directory carries no single consistent capsule source commit")
    head = next(iter(heads))
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", head):
        raise TrainError(f"orphaned run directory pins a non-commit source id: {head}")
    match = re.match(r"drop(\d+)-(\d{8})-", os.path.basename(os.path.normpath(scratch_root)))
    if not match:
        raise TrainError("orphaned run directory name carries no drop date")
    if int(match.group(1)) != int(drop):
        raise TrainError("orphaned run directory name does not match the resumed drop number")
    drop_date = match.group(2)
    try:
        dt.datetime.strptime(drop_date, "%Y%m%d")
    except ValueError:
        raise TrainError(f"orphaned run directory name carries a non-calendar drop date: {drop_date}")
    if dated and dated != {drop_date}:
        raise TrainError("orphaned run directory date disagrees with its published capsule sets")
    state = {"schema": SEGMENT_SCHEMA, "drop": drop, "debug": debug,
             "git_head": head, "drop_date": drop_date,
             "created": dt.datetime.now(dt.timezone.utc).isoformat(),
             "segments": [], "orphan_adopted": True}
    write_segment_state(scratch_root, state)
    return state


def recover_completed_invocations(scratch_root: str, members: List[PlannedTarget],
                                  channel_base_url: Optional[str] = None,
                                  tree_suffix: str = "",
                                  expected_commit: Optional[str] = None) -> Tuple[Dict[str, Dict], set]:
    """Map producers to verified prebuilt results from capsule invocations
    that completed before a train crash processed them.

    An invocation qualifies only when its result JSON parses, its producer
    set is entirely among the lanes still missing, and the full verification
    chain (cohort signatures, evidence, feed base) re-verifies against the
    capsule bytes still on disk — the same proof a live invocation owes.
    Anything less leaves the lane on the normal rebuild path. Returns the
    recovered prebuilts and the invocation files they were adopted from
    (those stay load-bearing evidence until their lanes seal).
    """
    from release_producer import get_producer, load_result, verify_cohort
    from release_producer_evidence import verify_cohort_evidence
    key = os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
    if not key:
        raise TrainError("trusted release public key is required")
    recipe = os.environ.get("DCENT_RELEASE_HARDWARE_RECIPE", "board-default")
    version = workspace_version()
    wanted = {item.target.producer for item in members}
    recovered: Dict[str, Dict] = {}
    adopted: set = set()
    groups: Dict[str, List[PlannedTarget]] = {}
    for item in members:
        variant = get_producer(item.target.producer).cargo_variant
        groups.setdefault(variant, []).append(item)
    run_root = os.path.realpath(scratch_root)
    for variant, _items in groups.items():
        cohort = os.path.join(scratch_root, "cohort-" + variant + tree_suffix)
        if not os.path.isdir(cohort):
            continue
        capsule = os.path.realpath(os.path.join(cohort, "capsule"))
        if os.path.commonpath([capsule, run_root]) != run_root:
            continue  # capsule tree grafted outside the run directory
        for name in sorted(os.listdir(cohort)):
            if not name.startswith("cohort-result") or not name.endswith(".json"):
                continue
            try:
                document = load_result(Path(os.path.join(cohort, name)))
                producers = [result["producer"] for result in document["results"]]
            except (ValueError, KeyError, OSError):
                continue  # torn write from the crash; these lanes rebuild
            if not producers or not set(producers) <= wanted:
                continue
            if document["channel"] != "beta" or document["source_commit"] != (expected_commit or document["source_commit"]):
                continue  # self-declared pins never override the resume's pins
            try:
                verify_cohort(document, Path(capsule), producers,
                              document["source_commit"], version, document["channel"],
                              Path(key), recipe)
                verify_cohort_evidence(document, Path(capsule), producers,
                                       document["source_commit"], version, document["channel"],
                                       Path(key), Path(DCENTOS_DIR).parents[1], recipe,
                                       channel_base_url)
            except (ValueError, OSError, TrainError):
                continue  # evidence no longer verifies; these lanes rebuild
            stem = name[len("cohort-result"):-len(".json")]
            log = os.path.join(cohort, f"cohort{stem}.log")
            for producer, result in zip(producers, document["results"]):
                recovered[producer] = {"source_commit": document["source_commit"],
                                       "root": os.path.join(cohort, "capsule"), "log": log,
                                       "rc": 0, "status": "built", "document": result}
            adopted.add(os.path.realpath(os.path.join(cohort, name)))
    return recovered, adopted


def require_clean_worktree(context: str) -> None:
    """Segment sessions must all read the same tree the drop was pinned at.

    The commit pin alone accepts a dirty tree; every train-side verifier
    (this file, producer table, admissions) is read from the working tree,
    so two sessions of one drop must see the same clean tree. A git failure
    is loud but non-fatal (the commit pin still applies).
    """
    dirty = subprocess.run(["git", "status", "--porcelain"], cwd=DCENTOS_DIR,
                           capture_output=True, text=True)
    if dirty.returncode != 0:
        print(f"WARNING: {context}: git status failed (rc={dirty.returncode}); "
              "the clean-tree gate could not run", file=sys.stderr)
        return
    if dirty.stdout.strip():
        raise TrainError(f"{context} refuses a dirty working tree: clean or stash first")


def canonical_release_name(build_target: str, date: str, channel: str = "beta") -> Optional[str]:
    """The capsule's canonical publication directory name for one lane."""
    script = os.path.join(SCRIPT_DIR, "firmware_release_name.sh")
    shell = shutil.which("bash") or "sh"
    try:
        completed = subprocess.run([shell, script, build_target, channel, date],
                                   cwd=DCENTOS_DIR, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0 or not completed.stdout.strip():
        return None
    name = completed.stdout.strip().splitlines()[-1].strip()
    if not name or name in (".", "..") or "/" in name or "\\" in name:
        return None
    return name


def clear_stale_release_output(scratch_root: str, rebuilding: List[PlannedTarget], date: str,
                               trees: Tuple[str, ...] = ("", "-repro")) -> None:
    """Remove dead-attempt release-set outputs for lanes about to rebuild.

    A previous attempt may have died after the capsule published a lane's
    release set but before the train sealed the lane. That output belongs to
    no sealed result (lanes being rebuilt are unsealed by definition), and
    release_set_publication refuses to publish over an existing output —
    without this cleanup a crash in that window wedges the lane's retries.
    """
    from release_producer import get_producer
    for item in rebuilding:
        row = get_producer(item.target.producer)
        name = canonical_release_name(row.build_target, date)
        if not name:
            # Without the canonical name a stale published set from a dead
            # attempt cannot be cleared and the retry will fail loudly at
            # "release-set output already exists" — surface it now.
            print(f"WARNING: no canonical release name for {item.target.name}; "
                  "stale release-set cleanup skipped for this lane", file=sys.stderr)
            continue
        for suffix in trees:
            releases = os.path.join(scratch_root, "cohort-" + row.cargo_variant + suffix,
                                    "capsule", "releases")
            if os.path.isdir(releases):
                stale = os.path.join(releases, name)
                if os.path.isdir(stale):
                    shutil.rmtree(stale)


def scan_result_fund_link(document: Dict, root: str) -> Tuple[bool, str]:
    """Only authenticated result members can satisfy the fund-link check."""
    primary = os.path.join(root, *document["files"]["primary"]["path"].split("/"))
    ok, where = scan_fund_link(primary, include_sidecars=False)
    if ok:
        return ok, where
    for record in document["ancillary"]:
        if record["size"] > 2_000_000 or not record["path"].lower().endswith((".txt", ".md", ".html")):
            continue
        with open(os.path.join(root, *record["path"].split("/")), "rb") as stream:
            if FUND_URL.encode() in stream.read(2_000_000):
                return True, "result ancillary " + record["path"]
    return False, "not found in authenticated result members"


def stage_publish(result: Dict, publish_root: str, staging_root: str) -> Dict:
    """Stage verified bytes under an immutable content-addressed directory."""
    del staging_root
    if result["status"] != "built" or not result.get("artifact"):
        return {"staged": False, "reason": result["status"]}
    source = os.path.join(DCENTOS_DIR, result["artifact"]["path"])
    try:
        verify_publication(result, source)
        # BM1391 evidence-gate lanes: run_lane recorded the full native-media
        # validation for this same in-process result, and every native lane is
        # independently re-verified by verify_result/verify_publication — so
        # reuse the record here instead of another full 269 MB image parse.
        if result["board_target"] in {"am1-s15", "am1-t15"} \
                and "native_media_validation" not in result:
            from release_producer import get_producer
            key = os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
            if not key:
                raise TrainError("trusted release public key is required")
            result["native_media_validation"] = validate_native_media_candidate(
                source, get_producer(result["producer_result"]["producer"]),
                result["version"], result["channel"], key, result["hardware_recipe"])
        document = result["producer_result"]
        fund_ok, _ = scan_result_fund_link(document, result["producer_output_root"])
        if not fund_ok:
            raise TrainError("fund-link gate failed")
        members = sorted(({"name": Path(record["path"]).name, "size": record["size"], "sha256": record["sha256"]}
                          for record in [*document["files"].values(), *document["ancillary"]]), key=lambda record: record["name"])
        set_digest = hashlib.sha256(json.dumps(members, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        destination = Path(publish_root) / result["channel"] / result["board_target"] / set_digest
        destination.parent.mkdir(parents=True, exist_ok=True)
        records = [*document["files"].values(), *document["ancillary"]]
        copied_names = set()
        for record in records:
            name = Path(record["path"]).name
            if name.casefold() in copied_names:
                raise TrainError("publication basename collision")
            copied_names.add(name.casefold())
        if destination.is_dir():
            # A previous segment (or an interrupted endgame or staging copy)
            # already staged this content address. The address is derived
            # from the verified member set, so a complete directory is
            # re-verified in place and reused; anything else (partial copy
            # from a crash, tampered or unexpected members) is discarded and
            # regenerated from the still-verified capsule originals — the
            # staged tree is derived output, never evidence.
            def _staged_bytes_match() -> bool:
                staged_names = {entry for entry in os.listdir(destination)}
                if staged_names != {Path(record["path"]).name for record in records}:
                    return False
                return all((destination / Path(record["path"]).name).is_file()
                           and (destination / Path(record["path"]).name).stat().st_size == record["size"]
                           and sha256_file(str(destination / Path(record["path"]).name)) == record["sha256"]
                           for record in records)
            if not _staged_bytes_match():
                shutil.rmtree(destination)
        if not destination.exists():
            destination.mkdir()  # no replacement of a verified content address
            for record in records:
                name = Path(record["path"]).name
                original = Path(result["producer_output_root"]).joinpath(*record["path"].split("/"))
                copied = destination / name
                with original.open("rb") as incoming, copied.open("xb") as outgoing:
                    shutil.copyfileobj(incoming, outgoing, 1024**2)
                if copied.stat().st_size != record["size"] or sha256_file(str(copied)) != record["sha256"]:
                    raise TrainError("publication copy differs from verified result")
        primary = destination / Path(source).name
        return {"staged": True, "path": os.path.relpath(primary, DCENTOS_DIR),
                "files": [{**record, "path": os.path.relpath(destination / Path(record["path"]).name, publish_root).replace(os.sep, "/")}
                          for record in records]}
    except (ValueError, OSError, TrainError) as error:
        return {"staged": False, "reason": "signed publication gate: " + str(error)}


def verify_publication(result: Dict, source: str) -> None:
    from release_producer import get_producer, verify_result
    document = result.get("producer_result")
    if not isinstance(document, dict):
        raise ValueError("verified canonical producer result required")
    row = get_producer(document.get("producer"))
    if (result["board_target"], result["install_route"]) != (row.board_target, row.install_route):
        raise ValueError("publication board/route does not match producer")
    key = os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
    if not key:
        raise ValueError("trusted release public key is required")
    verify_result(document, Path(result["producer_output_root"]), row,
                  result["source_commit"], result["version"], result["channel"],
                  Path(key), result["hardware_recipe"])
    primary = document["files"]["primary"]
    expected_path = Path(result["producer_output_root"]).joinpath(*primary["path"].split("/"))
    if os.path.abspath(source) != os.path.abspath(expected_path) or result["artifact"] != {
            "path": os.path.relpath(expected_path, DCENTOS_DIR), "sha256": primary["sha256"], "bytes": primary["size"]}:
        raise ValueError("publication artifact differs from canonical result")


def load_toolbox_policy(matrix_path: Optional[str] = None) -> Dict:
    """Read the canonical Rust export without inventing route-derived policy.

    Release route, channel, artifact digest and build status belong in the
    drop manifest. Toolbox's strict schema-4 capability rows have a different
    purpose and cannot contain those extra fields.
    """
    path = matrix_path or os.path.join(
        DCENTOS_DIR, "docs", "architecture", "hardware_enablement_matrix.json"
    )

    def unique_object(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise TrainError(f"duplicate enablement key {key!r}")
            result[key] = value
        return result

    try:
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle, object_pairs_hook=unique_object)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise TrainError(f"cannot read canonical Toolbox policy {path}: {error}") from error
    if (not isinstance(document, dict) or set(document) != {"schema", "targets"}
            or type(document["schema"]) is not int or document["schema"] != 4
            or not isinstance(document["targets"], list) or not document["targets"]):
        raise TrainError("canonical Toolbox policy must be a nonempty schema-4 matrix")
    rows = {}
    for row in document["targets"]:
        if not isinstance(row, dict):
            raise TrainError("canonical Toolbox policy row is not an object")
        target = row.get("board_target")
        if not isinstance(target, str) or not target or target != target.strip():
            raise TrainError("canonical Toolbox policy row lacks exact board_target")
        if target in rows:
            raise TrainError(f"duplicate canonical Toolbox target {target}")
        rows[target] = row
    return rows


def emit_toolbox_row(result: Dict, policy_rows: Optional[Dict] = None) -> Dict:
    """Return the complete canonical capability row, never a build-status row."""
    rows = load_toolbox_policy() if policy_rows is None else policy_rows
    target = result["board_target"]
    if target not in rows:
        raise TrainError(f"release target {target!r} has no canonical Toolbox policy row")
    return dict(rows[target])


def emit_toolbox_matrix(results: List[Dict], policy_rows: Optional[Dict] = None) -> Dict:
    """Make a directly loadable document, deduplicating multiple release routes."""
    if not results:
        raise TrainError("cannot emit an empty Toolbox matrix")
    policy = load_toolbox_policy() if policy_rows is None else policy_rows
    selected = {result["board_target"]: emit_toolbox_row(result, policy) for result in results}
    return {"schema": 4, "targets": [selected[target] for target in sorted(selected)]}


def complete_selected_beta(targets: List[TrainTarget], results: List[Dict], *, require_repro: bool = True) -> bool:
    """Every selected Beta row must yield one qualified, publishable result."""
    if not targets or len(results) != len(targets):
        return False
    by_name = {result.get("name"): result for result in results}
    if len(by_name) != len(results) or set(by_name) != {target.name for target in targets}:
        return False
    for target in targets:
        result = by_name[target.name]
        if (result.get("board_target") != target.board_target or result.get("channel") != "beta"
                or result.get("status") != "built" or (result.get("publish") or {}).get("staged") is not True
                or (result.get("fund_link") or {}).get("ok") is not True):
            return False
        if require_repro and target.reproducible:
            repro = result.get("reproducibility") or {}
            if repro.get("compared") is not True or repro.get("identical") is not True:
                return False
    return True


def write_manifest(manifest_path: str, drop: int, results: List[Dict], git_head: str,
                   *, targets: List[TrainTarget], base_url: str, publish_root: str) -> str:
    from urllib.parse import urlsplit, quote
    import runtime_image_manifest as runtime
    from release_producer import file_record
    if not complete_selected_beta(targets, results):
        raise TrainError("cannot sign an incomplete selected Beta drop")
    expected_beta = {board for board, channel in load_admissions().items() if channel == "Beta"}
    if drop not in (1, 2, 3) or {target.board_target for target in targets} != expected_beta:
        raise TrainError("signed cumulative drop must include every registered Beta row")
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", git_head):
        raise TrainError("drop requires one full source commit")
    url = urlsplit(base_url)
    if (url.scheme != "https" or not url.hostname or url.username or url.password
            or url.query or url.fragment or any(piece in (".", "..") for piece in url.path.split("/"))):
        raise TrainError("explicit HTTPS release base URL without credentials/query/traversal required")
    key = os.environ.get("DCENT_RELEASE_SIGNING_KEY")
    pubkey = os.environ.get("DCENT_RELEASE_PUBKEY_FILE")
    if not key or not pubkey:
        raise TrainError("drop signing requires the release Ed25519 key and trusted public key")
    rows = []
    for result in results:
        if result["source_commit"] != git_head:
            raise TrainError("drop results do not share the selected source commit")
        verify_publication(result, os.path.join(DCENTOS_DIR, result["artifact"]["path"]))
        files = []
        for record in result["publish"]["files"]:
            if file_record(Path(publish_root), record["path"]) != record:
                raise TrainError("staged file changed before drop signing")
            files.append({**record, "url": base_url.rstrip("/") + "/" + quote(record["path"], safe="/")})
        rows.append({"producer": result["producer_result"]["producer"],
                     "board_target": result["board_target"], "release_channel": result["channel"],
                     "version": result["version"], "source_commit": result["source_commit"],
                     "hardware_recipe": result["hardware_recipe"], "install_route": result["install_route"],
                     "reproducibility": result["reproducibility"], "files": files})
    manifest = {"manifest_profile": "dcentos-release-train-drop-manifest/v2",
                "drop": drop, "source_commit": git_head, "release_channel": "beta",
                "complete_selected_beta": True, "fund_url": FUND_URL, "targets": rows}
    # The manifest is a derived endgame artifact regenerated from verified
    # results; an interrupted endgame may leave a partial file that the
    # completing invocation legitimately overwrites.
    with open(manifest_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    subprocess.run([sys.executable, os.path.join(SCRIPT_DIR, "sign_release_artifact.py"), manifest_path,
                    "--key", key, "--pubkey", pubkey], check=True, capture_output=True)
    runtime.verify_signature(Path(manifest_path), Path(manifest_path + ".sig"), Path(pubkey))
    return manifest_path


def _git_head() -> str:
    from release_source_git import read_source
    try:
        return read_source(Path(DCENTOS_DIR).parents[1], "commit")
    except (RuntimeError, ValueError, OSError, subprocess.SubprocessError):
        return "unknown"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _today() -> str:
    return dt.date.today().strftime("%Y%m%d")


def cmd_plan(args: argparse.Namespace) -> int:
    admissions = load_admissions()
    targets = resolve_targets(args.drop, args.target)
    print(f"drop={args.drop or '-'} targets={len(targets)} date={_today()}")
    hard = 0
    blocked = 0
    for target in targets:
        planned = plan_target(target, admissions)
        state = "OK"
        if planned.hard_violation:
            state = "VIOLATION"
            hard += 1
        elif target.blocked_reason or not planned.executable:
            state = "BLOCKED"
            blocked += 1
        print(
            f"  [{state:9s}] {target.name:14s} ring={planned.ring:18s} "
            f"route={target.install_route:28s} lane={target.lane_kind}"
        )
        for issue in planned.issues:
            print(f"      !! {issue}")
        if target.blocked_reason:
            print(f"      blocked: {target.blocked_reason}")
        if target.policy_target:
            try:
                canonical = validate_capsule_name(target.policy_target, _today())
                print(f"      capsule name: {canonical}")
            except capsule_policy.TargetPolicyError as error:
                print(f"      !! capsule name invalid: {error}")
                hard += 1
    eligible = [target for target in targets if admissions.get(target.board_target) in PUBLISHABLE_RINGS]
    producers = [target for target in eligible if target.lane_command and not target.blocked_reason]
    print(f"plan: {len(targets)} targets, {blocked} blocked, {hard} hard violations; "
          f"{len(eligible)} publishable channel rows, {len(producers)} declared producers")
    return 1 if hard else 0


def cmd_run(args: argparse.Namespace) -> int:
    import tempfile
    from release_host_tools import prepare_openssl_environment
    admissions = load_admissions()
    debug = getattr(args, "debug_subset", False)
    resume_name = getattr(args, "resume", None)
    stop_after = getattr(args, "stop_after_lanes", None)
    if (resume_name or stop_after is not None) and debug:
        raise TrainError("segment execution belongs to drop runs; --debug-subset stays single-shot")
    if stop_after is not None and stop_after < 1:
        raise TrainError("--stop-after-lanes must be a positive lane count")
    minimum_version = getattr(args, "minimum_version", None)
    if not debug:
        if not minimum_version:
            raise TrainError("--minimum-version is required for a cumulative signed channel feed")
        from release_channel_feed import feed
        feed.version(minimum_version)
    channel_base_url = getattr(args, "channel_base_url", None)
    if not debug and not channel_base_url:
        raise TrainError("--channel-base-url is required for a cumulative release's compiled update channel")
    if channel_base_url:
        from release_channel_feed import feed
        feed.https_url(channel_base_url)
    if args.target and not debug:
        raise TrainError("--target execution requires --debug-subset; a release drop selects every cumulative Beta row")
    if args.skip and not debug:
        raise TrainError("a Beta drop cannot skip selected targets")
    if debug and args.drop:
        raise TrainError("--debug-subset cannot claim a numbered Beta drop")
    if os.environ.get("DCENT_ALLOW_UNSIGNED_SYSUPGRADE", "0") != "0" or os.environ.get("DCENT_DEV_IMAGE", "0") != "0":
        raise TrainError("Beta train refuses unsigned/lab image overrides")
    targets = resolve_targets(args.drop, args.target)
    if not debug:
        expected_beta = {board for board, channel in admissions.items() if channel == "Beta"}
        if {target.board_target for target in targets} != expected_beta:
            raise TrainError("cumulative drop is missing a registered Beta row or selects a non-Beta row")
    planned_targets = [plan_target(target, admissions) for target in targets]
    invalid = [planned for planned in planned_targets if planned.hard_violation or planned.ring != "Beta"
               or planned.target.blocked_reason or not planned.executable]
    if invalid:
        for planned in invalid:
            print(f"INCOMPLETE {planned.target.name}: " + (planned.target.blocked_reason or "; ".join(planned.issues) or "no Beta producer"), file=sys.stderr)
        return 1
    base_url = getattr(args, "base_url", None) or os.environ.get("DCENT_RELEASE_BASE_URL", "")
    if not debug and not base_url:
        raise TrainError("DCENT_RELEASE_BASE_URL or --base-url is required for immutable drop URLs")
    for name in ("DCENT_RELEASE_SIGNING_KEY", "DCENT_RELEASE_PUBKEY_FILE"):
        if not os.environ.get(name):
            raise TrainError(f"{name} is required; Beta has no unsigned fallback")
    prepare_openssl_environment()
    date = _today()
    work_parent = os.path.join(DCENTOS_DIR, "output", ".release-train")
    os.makedirs(work_parent, exist_ok=True)
    sealed: Dict[str, Dict] = {}
    if resume_name:
        resume_root = resume_name if os.path.isabs(resume_name) else os.path.join(work_parent, resume_name)
        if not os.path.isdir(resume_root):
            raise TrainError(f"--resume run directory not found: {resume_name}")
        if os.path.isfile(_segment_state_path(resume_root)):
            state = load_segment_state(resume_root)
        else:
            # Session one died before writing state: adopt the run directory
            # if its completed capsule invocations pin one consistent commit.
            state = bootstrap_orphaned_segment_state(resume_root, args.drop, debug)
        if state.get("drop") != args.drop:
            raise TrainError("resume drop number does not match the segment state")
        if state.get("debug"):
            raise TrainError("segment state belongs to a debug run; drops cannot resume it")
        if state.get("completed"):
            raise TrainError("this drop already completed its endgame; the run directory is final")
        if state.get("git_head") != _git_head():
            raise TrainError("resume refuses HEAD drift: the drop stays frozen at its recorded source commit")
        require_clean_worktree("resume")
        if not re.fullmatch(r"[0-9]{8}", str(state.get("drop_date") or "")):
            raise TrainError("segment state carries an invalid pinned drop date; refusing to resume")
        date = state["drop_date"]
        scratch_root = resume_root
        sealed = load_segment_results(scratch_root)
        # Every sealed lane must re-verify from the bytes still on disk
        # before a single new lane is built — grouped into the invocations
        # that built them so each cohort owner matches its stamped evidence.
        if sealed:
            verify_sealed_segment_results(sealed, scratch_root, channel_base_url,
                                          [item.target.name for item in planned_targets])
    else:
        if stop_after is not None and not debug:
            # A segmented drop starts as clean as it must continue: every
            # later resume is held to the same tree.
            require_clean_worktree("segment start")
        scratch_root = tempfile.mkdtemp(prefix=f"drop{args.drop or 'debug'}-{date}-", dir=work_parent)
        state = {"schema": SEGMENT_SCHEMA, "drop": args.drop, "debug": debug,
                 "git_head": _git_head(), "drop_date": date,
                 "created": dt.datetime.now(dt.timezone.utc).isoformat(), "segments": []}
    publish_root = os.path.join(scratch_root, "publish")
    os.makedirs(publish_root, exist_ok=True)
    skip = {name.strip() for name in (args.skip or "").split(",") if name.strip()}
    if not skip <= {target.name for target in targets}:
        raise TrainError("--skip names must belong to the selected debug subset")
    toolbox_policy = load_toolbox_policy()
    emit_toolbox_matrix([{"board_target": target.board_target} for target in targets], toolbox_policy)
    planned_names = [item.target.name for item in planned_targets]
    missing = [item for item in planned_targets if item.target.name not in sealed]
    budget_cut = False
    newly: List[Dict] = []
    if missing:
        session = next_segment_session(scratch_root, state)
        recovered: Dict[str, Dict] = {}
        recovered_comparison: Dict[str, Dict] = {}
        adopted: set = set()
        if resume_name:
            # A previous session's capsule invocation may have completed
            # before the train died processing it: its results re-verify and
            # seal without a rebuild. Recovery runs over the FULL missing
            # set, before any budget cut — an adopted invocation is zero
            # build work and must never be forfeited by a lane budget.
            recovered, adopted = recover_completed_invocations(
                scratch_root, missing, channel_base_url, expected_commit=state.get("git_head"))
            from release_producer import get_producer
            reproducible_missing = [item for item in missing
                                    if item.target.reproducible
                                    and item.target.producer in recovered]
            recovered_comparison, adopted_repro = recover_completed_invocations(
                scratch_root, reproducible_missing, channel_base_url, tree_suffix="-repro",
                expected_commit=state.get("git_head"))
            adopted |= adopted_repro
        build_candidates = [item for item in missing if item.target.producer not in recovered]
        if stop_after is not None and len(build_candidates) > stop_after:
            # The budget bounds LANES BUILT this session; adopted lanes are
            # verification-only and always process.
            build_only_names = {item.target.name for item in build_candidates[:stop_after]}
            missing = [item for item in missing
                       if item.target.name in build_only_names or item.target.producer in recovered]
            budget_cut = True
        rebuild_only = [item for item in missing if item.target.producer not in recovered]
        clear_stale_release_output(scratch_root, rebuild_only, date)
        # Lanes whose first pass was adopted but whose repro invocation did
        # not complete owe a repro REBUILD: their stale -repro release sets
        # from the dead attempt must go or the rebuild wedges on publish.
        repro_rebuild = [item for item in missing if item.target.reproducible
                         and item.target.producer in recovered
                         and item.target.producer not in recovered_comparison]
        if repro_rebuild:
            clear_stale_release_output(scratch_root, repro_rebuild, date, trees=("-repro",))

        def _seal(result: Dict) -> None:
            # Sealed lane-by-lane: a crash later in the segment keeps every
            # lane whose verification already completed here.
            if result.get("status") == "built":
                persist_segment_result(scratch_root, result)
                sealed[result["name"]] = result

        newly = run_selected_cohorts(missing, date, scratch_root, skip, with_repro=(args.repro or not debug),
                                     channel_base_url=channel_base_url, session=session, on_result=_seal,
                                     recovered=recovered, recovered_comparison=recovered_comparison,
                                     protect=adopted)
        state.setdefault("segments", []).append({
            "session": session, "date": date, "budget_cut": budget_cut,
            "recovered": sorted(recovered),
            "built": sorted(result["name"] for result in newly if result.get("status") == "built"),
            "outcomes": {result["name"]: result.get("status") for result in newly}})
        write_segment_state(scratch_root, state)
    outcomes: Dict[str, Dict] = dict(sealed)
    for result in newly:
        outcomes.setdefault(result["name"], result)
    results = [outcomes[name] for name in planned_names if name in outcomes]
    deferred = [name for name in planned_names if name not in outcomes]
    for result in results:
        result["publish"] = stage_publish(result, publish_root, scratch_root)
        print(f"{result['name']}: status={result['status']} publish={result['publish'].get('staged', False)}")
    complete = complete_selected_beta(targets, results, require_repro=not debug or args.repro)
    # Diagnostic state is never presented or signed as a successful MANIFEST.
    with open(os.path.join(scratch_root, "RUN_STATUS.json"), "w", encoding="utf-8", newline="\n") as handle:
        json.dump({"complete_selected_beta": complete, "debug_subset": debug, "targets": results,
                   "deferred": deferred}, handle, indent=2, sort_keys=True)
        handle.write("\n")
    if not complete:
        unbuilt = [name for name in planned_names if name not in outcomes]
        failed = [result["name"] for result in newly if result.get("status") != "built"]
        if not failed and unbuilt:
            # Segment boundary: every attempted lane sealed, the remainder
            # deliberately deferred. The transport window is open; the next
            # invocation resumes with --resume <run dir>.
            message = (f"SEGMENT_COMPLETE run={os.path.basename(scratch_root)} "
                       f"sealed={len(sealed)}/{len(planned_names)} remaining={len(unbuilt)} next={unbuilt[0]}")
            print(message)
            # Durable completion marker: the console now lands in the
            # workspace train-console.log (producer_drop1_inner.sh), not the
            # systemd journal, so pause/resume tooling must not depend on
            # journal greps. The marker file is the transport-window signal.
            os.makedirs(_segment_results_dir(scratch_root), exist_ok=True)
            with open(os.path.join(scratch_root, SEGMENTS_SUBDIR, "segment-complete.log"),
                      "a", encoding="utf-8", newline="\n") as marker:
                marker.write(dt.datetime.now(dt.timezone.utc).isoformat() + " " + message + "\n")
            return 0
        unstaged = [f"{result['name']}: {(result.get('publish') or {}).get('reason', '?')}"
                    for result in results
                    if result.get("status") == "built" and not (result.get("publish") or {}).get("staged")]
        if unstaged:
            print("ENDGAME_GATE_INCOMPLETE staged-failed: " + "; ".join(unstaged), file=sys.stderr)
        return 1
    if not debug:
        manifest_path = os.path.join(scratch_root, f"MANIFEST_DROP{args.drop}_{date}.json")
        write_manifest(manifest_path, args.drop, results, _git_head(), targets=targets,
                       base_url=base_url, publish_root=publish_root)
        # Derived endgame artifacts are regenerated, never treated as
        # append-only: an interrupted endgame leaves partials that the
        # completing invocation overwrites from verified results.
        with open(os.path.join(scratch_root, "hardware_enablement_matrix.json"), "w", encoding="utf-8", newline="\n") as handle:
            json.dump(emit_toolbox_matrix(results, toolbox_policy), handle, indent=2, sort_keys=True)
            handle.write("\n")
        from pathlib import Path
        from release_channel_feed import emit
        channel_path = Path(scratch_root) / "beta.json"
        for stale_feed in (channel_path, Path(str(channel_path) + ".sig")):
            if stale_feed.exists():
                stale_feed.unlink()
        emit(Path(manifest_path), channel_path,
             Path(os.environ["DCENT_RELEASE_SIGNING_KEY"]),
             Path(os.environ["DCENT_RELEASE_PUBKEY_FILE"]), minimum_version)
        # Finality is declared only after the signed feed exists; a crash
        # anywhere above leaves the endgame re-runnable via --resume.
        state["completed"] = True
        write_segment_state(scratch_root, state)
        print(f"signed manifest: {manifest_path}")
        print(f"signed channel feed: {channel_path}")
    return 0


def cmd_admission(_args: argparse.Namespace) -> int:
    for board, ring in sorted(load_admissions().items()):
        print(f"{board:20s} {ring}")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true", help="validate composition, build nothing")
    mode.add_argument("--run", action="store_true", help="execute the drop")
    mode.add_argument("--admission", action="store_true", help="dump parsed rings")
    parser.add_argument("--drop", type=int, choices=(1, 2, 3), default=None)
    parser.add_argument("--target", action="append", default=None)
    parser.add_argument("--skip", default="", help="comma-separated names to skip")
    parser.add_argument(
        "--repro",
        action="store_true",
        help="run reproducible lanes twice and compare artifact sha256",
    )
    parser.add_argument("--keep-scratch", action="store_true")
    parser.add_argument("--debug-subset", action="store_true", help="explicit non-drop selected-producer diagnostic run")
    parser.add_argument("--resume", metavar="RUN_DIR", default=None,
                        help="resume a segmented drop inside this output/.release-train run directory")
    parser.add_argument("--stop-after-lanes", type=int, default=None, metavar="N",
                        help="cleanly stop after BUILDING N lanes this invocation; adopted "
                        "recovery lanes are verification-only and never count against it")
    parser.add_argument("--base-url", help="HTTPS immutable release file base URL; defaults to DCENT_RELEASE_BASE_URL")
    parser.add_argument("--minimum-version", help="explicit oldest installed version eligible for this signed cumulative feed")
    parser.add_argument("--channel-base-url", help="explicit HTTPS base to compile for beta.json/stable.json; no ambient fallback")
    args = parser.parse_args(argv)
    try:
        if args.plan:
            return cmd_plan(args)
        if args.run:
            return cmd_run(args)
        return cmd_admission(args)
    except (TrainError, ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: release train: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
