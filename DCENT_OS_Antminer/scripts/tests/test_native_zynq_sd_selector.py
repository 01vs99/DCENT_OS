"""Only source-extracted shell path selection; no daemon or service execution."""

from pathlib import Path
import importlib
import os
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "DCENT_OS_Antminer/scripts"))
assets = importlib.import_module("native_zynq_sd.assets")
TARGETS = importlib.import_module("native_zynq_sd.profiles").TARGETS
pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="actual POSIX selector execution"
)


@pytest.mark.parametrize("target", TARGETS)
@pytest.mark.parametrize(
    "case", ["fresh", "retained_config", "retained_executable_and_config"]
)
def test_image_daemon_remains_selected_with_preserved_data(tmp_path, target, case):
    text = assets.render_supervisor(ROOT, target).content.decode()
    start = text.index("select_dcentrald_paths() {")
    end = text.index("\n}\n", start) + 3
    function = text[start:end]
    # Native operands are fixed no-space /data and /etc paths. The host rebase
    # must preserve those shell lexical properties; the v1 spaced fixture and
    # all21 actual failed scripts are retained separately.
    fixture = tmp_path / "operator_data"
    for name in ("data", "etc", "usr/local/bin"):
        (fixture / name).mkdir(parents=True)
    if case != "fresh":
        (fixture / "data/dcentrald.toml").write_bytes(b"inert operator configuration\n")
    if case == "retained_executable_and_config":
        old = fixture / "data/dcentrald"
        old.write_bytes(b"inert old daemon; never executed\n")
        old.chmod(0o755)
    for name in ("data", "etc", "usr/local/bin"):
        function = function.replace("/" + name + "/", str(fixture / name) + "/")
    source = fixture / "selector.sh"
    source.write_text(
        function + '\nselect_dcentrald_paths\nprintf "%s\\n%s\\n" "$DAEMON" "$CONFIG"\n'
    )
    process = subprocess.run(
        ["/bin/sh", str(source)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
    )
    assert process.returncode == 0 and process.stderr == b""
    daemon, config = process.stdout.decode().splitlines()
    assert daemon == str(fixture / "usr/local/bin/dcentrald")
    assert config == str(
        fixture / ("etc/dcentrald.toml" if case == "fresh" else "data/dcentrald.toml")
    )
