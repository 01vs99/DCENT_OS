#!/usr/bin/env python3
"""Private process fixtures for the real Cargo capsule driver acceptance test.

Docker and npm are bounded process substitutes; production source, key, ELF,
dashboard, native preflight and lineage validators execute unchanged.
"""
from __future__ import annotations

import argparse
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

SCRIPTS = Path(__file__).resolve().parent
WORKSPACE = SCRIPTS.parents[2]
TOOLBOX = WORKSPACE / "projects/dcent-toolbox/src"
VERSION = "0.9.0"
TRIPLES = ("armv7-unknown-linux-musleabihf", "aarch64-unknown-linux-musl")


def copy_inputs(destination: Path) -> None:
    # Load exactly the production preflight entry points and their imported
    # closure. No fixture module replaces a validator in the source snapshot.
    for module in ("release_build_identity", "release_dashboard", "release_native_sd",
                   "s19k_native_build_verify"):
        importlib.import_module(module)
    importlib.import_module("dcent_toolbox.core.current_native_release")
    from native_zynq_sd import assets
    from native_zynq_sd.profiles import TARGETS

    files = set()
    for board in TARGETS:
        files.update(WORKSPACE / asset.source for asset in
                     assets.source_assets(WORKSPACE, board).values() if asset.source)
    for module in tuple(sys.modules.values()):
        filename = getattr(module, "__file__", None)
        if filename is None:
            continue
        path = Path(filename).resolve()
        if path.suffix == ".py" and (path.is_relative_to(SCRIPTS) or path.is_relative_to(TOOLBOX)):
            if path != Path(__file__).resolve():
                files.add(path)
    files.add(SCRIPTS.parent / "dcentrald/dcentrald/src/build_identity.rs")
    if not 20 <= len(files) <= 150:
        raise ValueError("unexpected capsule preflight fixture source closure size")
    for source in sorted(files):
        target = destination / source.relative_to(WORKSPACE)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    version = destination / "DCENT_OS_Antminer/br2_external_dcentos/board/zynq/rootfs-overlay/etc/dcentos-version"
    version.parent.mkdir(parents=True, exist_ok=True)
    version.write_bytes((VERSION + "\n").encode())
    dashboard = destination / "DCENT_OS_Antminer/dashboard"
    dashboard.mkdir()
    (dashboard / "package.json").write_bytes(b'{"name":"capsule-dashboard-fixture","version":"0.9.0"}\n')
    (dashboard / "package-lock.json").write_bytes(b'{"name":"capsule-dashboard-fixture","lockfileVersion":3}\n')
    (dashboard / "source.html").write_bytes(b'<html><script src="/static/diagnostic-banner.js"></script></html>\n')


def compile_identities(source_repo: Path, directory: Path) -> None:
    # Same stripped cross-ELF technique as test_runtime_image_manifest.fixture,
    # with this driver's real release version and one shared throwaway key.
    import runtime_image_manifest as runtime
    directory.mkdir()
    key, pubkey = directory / "test-key.pem", directory / "test-pub.pem"
    runtime.openssl("genpkey", "-algorithm", "ED25519", "-out", key)
    runtime.openssl("pkey", "-in", key, "-pubout", "-out", pubkey)
    public = runtime.public_key_bytes(pubkey).hex()
    (directory / "ota-key.hex").write_bytes((public + "\n").encode())
    source = directory / "identity_fixture.rs"
    identity = source_repo / "DCENT_OS_Antminer/dcentrald/dcentrald/src/build_identity.rs"
    source.write_text('extern crate self as dcentrald_common;\n'
                      'pub mod lab_env { pub const fn compiled() -> bool { false } }\n'
                      '#[path = ' + json.dumps(str(identity)) + '] mod build_identity;\n'
                      'fn main() { build_identity::retain(); }\n', encoding="utf-8")
    rustc = subprocess.check_output(["rustup", "which", "--toolchain", "1.90.0", "rustc"], text=True).strip()
    linker = Path(rustc).parent.parent / "lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld"
    for triple in TRIPLES:
        output = directory / triple
        command = [rustc, "--edition", "2021", str(source), "--target", triple,
                   "-C", "opt-level=2", "-C", "lto=yes", "-C", "strip=symbols",
                   "-C", "linker=" + str(linker), "-o", str(output)]
        run = subprocess.run(command, env=dict(os.environ, CARGO_PKG_VERSION=VERSION,
                             DCENT_OTA_PUBLIC_KEY_HEX=public), capture_output=True, text=True, timeout=180)
        if run.returncode:
            raise RuntimeError("cross ELF fixture failed: " + run.stdout + run.stderr)
        observed = runtime.build_identity(output.read_bytes())
        assert observed["version"] == VERSION and observed["public_key"].hex() == public


def process_fixtures(directory: Path) -> None:
    node = directory / "node"
    node.write_bytes(b'#!/bin/sh\n[ "$#" = 1 ] && [ "$1" = --version ] || exit 91\nprintf "fixture-node-1\\n"\n')
    npm = directory / "npm"
    npm.write_text('''#!/usr/bin/env python3
import gzip, hashlib, os
from pathlib import Path
import sys
if sys.argv[1:] == ["--version"]:
    print("fixture-npm-1")
    raise SystemExit(0)
assert "dashboard-build-" in str(Path.cwd()), "npm must use its private source copy"
assert os.environ["CI"] == "1" and os.environ["CYPRESS_INSTALL_BINARY"] == "0"
assert Path("package.json").is_file() and Path("package-lock.json").is_file()
if sys.argv[1:] == ["ci", "--no-audit", "--no-fund"]:
    Path("node_modules").mkdir()
elif sys.argv[1:] == ["run", "build"]:
    assert Path("node_modules").is_dir()
    raw = Path("source.html").read_bytes()
    Path("dist").mkdir()
    Path("dist/index.html").write_bytes(raw)
    Path("dist/index.html.gz").write_bytes(gzip.compress(raw, mtime=0))
    digest = hashlib.sha256(raw).hexdigest() + "\\n"
    if os.environ.get("FAKE_NPM_BAD_ASSETS") == "1":
        digest = "0" * 64 + "\\n"
    Path("dist/index.html.sha256").write_text(digest)
else:
    raise AssertionError("unexpected npm process arguments: " + repr(sys.argv))
''', encoding="utf-8")
    for path in (node, npm):
        path.chmod(0o755)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repo", type=Path, required=True)
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--fake-bin", type=Path, required=True)
    args = parser.parse_args()
    copy_inputs(args.source_repo)
    compile_identities(args.source_repo, args.fixtures)
    process_fixtures(args.fake_bin)


if __name__ == "__main__":
    main()
