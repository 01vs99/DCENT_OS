#!/usr/bin/env python3
"""Select Git Bash's long-path-capable OpenSSL for Windows release work."""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess


def prepare_openssl_environment() -> str | None:
    """Keep Linux unchanged; use the active Git installation's MSYS tools.

    The native mingw OpenSSL cannot open the descriptor-derived capsule paths
    when NTFS short names are unavailable. The MSYS build opens those same
    files without copying keys or weakening their ownership checks.
    """
    if os.name != "nt":
        return None
    cygpath = shutil.which("cygpath")
    if not cygpath:
        # Native Windows Python may start from PowerShell. Resolve the same
        # installed Git selected by PATH, never a guessed global executable.
        git = shutil.which("git")
        if git:
            for parent in Path(git).resolve().parents:
                candidate = parent / "usr/bin/cygpath.exe"
                if candidate.is_file():
                    cygpath = str(candidate)
                    break
    if not cygpath:
        raise ValueError("Windows release builds require Git Bash with cygpath")
    directory = Path(subprocess.check_output(
        [cygpath, "-w", "/usr/bin"], text=True, timeout=10
    ).strip())
    executable = directory / "openssl.exe"
    if not executable.is_file():
        raise ValueError("active Git Bash installation lacks its MSYS OpenSSL")
    platform = subprocess.check_output(
        [str(executable), "version", "-p"], text=True, timeout=10
    ).strip()
    if not platform.startswith("platform: Msys-"):
        raise ValueError("Git Bash release OpenSSL must report the MSYS platform")
    os.environ["PATH"] = str(directory) + os.pathsep + os.environ.get("PATH", "")
    return str(directory)


if __name__ == "__main__":
    try:
        selected = prepare_openssl_environment()
        if selected:
            print(selected)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(f"ERROR: release host tools: {error}")
