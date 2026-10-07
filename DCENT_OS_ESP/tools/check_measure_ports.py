#!/usr/bin/env python3
"""check_measure_ports.py - prove the two measurement-station ports agree.

`tools/measure_image.sh` and `tools/measure_image.ps1` are two ports of one
station. Round 1 of lane `P1-I3` gave each its own JSON writer and they drifted:
`xtensa_check` was a list from one port and a bare string (or `null`) from the
other, and the `boards` container had already been silently coerced into a string
array once. A blind critic handed two lanes measured on two different machines
would have been diffing two schemas without being told.

This check enforces the fix at two levels, and it FAILS CLOSED at both.

  1. STATIC (always runs, no interpreters needed beyond this one).
     Neither port may format the document itself; both must delegate to
     `tools/measure_assemble.py`. A port that grows its own `json.dump` /
     `ConvertTo-Json` fails here even on a machine that cannot run it.

  2. DYNAMIC (runs when the other interpreter exists).
     Both ports are executed with `--skip-build --skip-host-gate` (fast: no
     cargo, no espflash) into separate output files, and the resulting documents
     are compared structurally. Fields that legitimately differ between two runs
     - none today, but `lane` is passed differently by design - are normalised
     before the diff, and everything else must match exactly.

Usage:  python tools/check_measure_ports.py [--static-only] [-v]
Exit:   0 = the ports agree (and, when only one interpreter exists, that is
            reported explicitly rather than silently passing as a full check);
        1 = divergence, a port that writes its own JSON, or a port that failed.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

TOOLS = os.path.dirname(os.path.abspath(__file__))
ESP_ROOT = os.path.dirname(TOOLS)

SH = os.path.join(TOOLS, "measure_image.sh")
PS1 = os.path.join(TOOLS, "measure_image.ps1")
ASSEMBLER = os.path.join(TOOLS, "measure_assemble.py")

# A port that contains any of these is formatting the document itself again.
# Lead fix at merge (blind critic P1-I6, must-fix 1): the CR refusal existed in
# the shell port only, so a Windows-only station run measured a CRLF tree without
# complaint. Every needle here must appear in BOTH ports; that is what stops the
# two from drifting again.
REQUIRED_IN_PORTS = [
    "measure_cr_check.py",
    "embedded-asset CR check",
]

FORBIDDEN_IN_PORTS = [
    "json.dump",
    "ConvertTo-Json",
    '"xtensa_check"',
    "xtensa_check =",
]


def fail(msg: str) -> int:
    print("FAIL: " + msg, file=sys.stderr)
    return 1


def strip_script_comments(text: str) -> str:
    """Blank comments in a POSIX-shell or PowerShell script.

    Needed because the ports legitimately DOCUMENT the defect this check
    enforces against ("round 1 hand-built the document here with
    ConvertTo-Json"), and a naive substring scan would match that prose - the
    same self-match trap that bites `include_str!` source contracts. Only code
    is scanned.

    `#` starts a comment only at the start of a line or after whitespace, so a
    `#` inside a string literal (`-split "#", 2`) survives.
    """
    # PowerShell block comments first.
    out = []
    i = 0
    while i < len(text):
        if text.startswith("<#", i):
            end = text.find("#>", i + 2)
            end = len(text) if end == -1 else end + 2
            out.append("".join(c if c == "\n" else " " for c in text[i:end]))
            i = end
            continue
        out.append(text[i])
        i += 1
    text = "".join(out)

    lines = []
    for line in text.split("\n"):
        cut = None
        for idx, ch in enumerate(line):
            if ch == "#" and (idx == 0 or line[idx - 1] in " \t"):
                cut = idx
                break
        lines.append(line if cut is None else line[:cut])
    return "\n".join(lines)


def static_check(verbose: bool) -> int:
    problems = []
    for path in (SH, PS1, ASSEMBLER):
        if not os.path.exists(path):
            problems.append(f"missing {os.path.relpath(path, ESP_ROOT)}")
    if problems:
        return fail("; ".join(problems))

    for port in (SH, PS1):
        with open(port, encoding="utf-8") as fh:
            raw = fh.read()
        text = strip_script_comments(raw)
        rel = os.path.relpath(port, ESP_ROOT).replace("\\", "/")
        if "measure_assemble.py" not in text:
            problems.append(
                f"{rel} does not call tools/measure_assemble.py - the two ports "
                f"must share ONE writer or their schemas drift"
            )
        for needle in REQUIRED_IN_PORTS:
            if needle not in text:
                return fail(
                    f"{rel} does not contain `{needle}`: both station ports must "
                    "run the embedded-asset CR refusal as step 0, before any build "
                    "(P1-I6 merge fix). A port without it silently measures a CRLF "
                    "tree, which inflates the image one byte per embedded line."
                )
        for needle in FORBIDDEN_IN_PORTS:
            if needle in text:
                problems.append(
                    f"{rel} contains `{needle}`: a port must not format "
                    f"measure.json itself, it must hand its inputs to "
                    f"tools/measure_assemble.py"
                )
        if verbose:
            print(f"  static: {rel} delegates to measure_assemble.py")

    if problems:
        for p in problems:
            print("FAIL: " + p, file=sys.stderr)
        return 1
    print("static: both ports delegate to tools/measure_assemble.py  OK")
    return 0


def normalise(doc: dict) -> dict:
    """Strip the fields two runs may legitimately differ on."""
    out = json.loads(json.dumps(doc))
    # The lane id is an input, not a measurement.
    out.pop("lane", None)
    return out


def run_port(cmd, out_path, cwd, verbose):
    env = dict(os.environ)
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    if verbose or proc.returncode != 0:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
    if proc.returncode != 0:
        return None, f"{cmd[0]} exited {proc.returncode}"
    if not os.path.exists(out_path):
        return None, f"{cmd[0]} did not write {out_path}"
    with open(out_path, encoding="utf-8") as fh:
        return json.load(fh), None


def dynamic_check(verbose: bool) -> int:
    sh_exe = shutil.which("sh") or shutil.which("bash")
    ps_exe = shutil.which("powershell") or shutil.which("pwsh")

    if not sh_exe and not ps_exe:
        return fail("neither a POSIX shell nor PowerShell is available - "
                    "cannot run either port")
    if not sh_exe or not ps_exe:
        have = "PowerShell" if ps_exe else "a POSIX shell"
        missing = "a POSIX shell" if ps_exe else "PowerShell"
        print(f"dynamic: SKIPPED - this machine has {have} but not {missing}; "
              f"only the static contract was proven here. Run this check on a "
              f"machine with both before trusting cross-port evidence.")
        return 0

    tmp = tempfile.mkdtemp(prefix="axe-port-check-")
    try:
        sh_out = os.path.join(tmp, "sh.json")
        ps_out = os.path.join(tmp, "ps.json")
        common = ["--skip-build", "--skip-host-gate"]

        doc_sh, err = run_port(
            [sh_exe, SH, "--lane", "port-check-sh", "--out", sh_out] + common,
            sh_out, ESP_ROOT, verbose)
        if err:
            return fail("measure_image.sh: " + err)

        doc_ps, err = run_port(
            [ps_exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", PS1,
             "-Lane", "port-check-ps", "-Out", ps_out,
             "-SkipBuild", "-SkipHostGate"],
            ps_out, ESP_ROOT, verbose)
        if err:
            return fail("measure_image.ps1: " + err)

        a, b = normalise(doc_sh), normalise(doc_ps)
        if a != b:
            diffs = []
            for key in sorted(set(a) | set(b)):
                if a.get(key) != b.get(key):
                    diffs.append(
                        f"  {key}:\n"
                        f"    sh  = {json.dumps(a.get(key))[:400]}\n"
                        f"    ps1 = {json.dumps(b.get(key))[:400]}"
                    )
            return fail(
                "the two measurement-station ports produced DIFFERENT documents. "
                "They must be byte-identical apart from the lane id, because a "
                "critic compares evidence measured on different machines:\n"
                + "\n".join(diffs)
            )

        print(f"dynamic: measure_image.sh and measure_image.ps1 agree "
              f"(schema_version {doc_sh.get('schema_version')}, "
              f"{len(json.dumps(a))} bytes)  OK")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--static-only", action="store_true",
                    help="skip running the ports (contract check only)")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    rc = static_check(args.verbose)
    if rc:
        return rc
    if args.static_only:
        print("dynamic: SKIPPED (--static-only)")
        return 0
    return dynamic_check(args.verbose)


if __name__ == "__main__":
    sys.exit(main())
