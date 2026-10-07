"""Actual private directory-bind SSH namespace tests; never device/media mounts."""

import importlib.util
import os
from pathlib import Path
import stat
import subprocess

import pytest

SOURCE = (
    Path(__file__).resolve().parents[2]
    / "br2_external_dcentos/board/zynq/native-sd/rootfs-overlay/usr/libexec/dcentos/native-zynq-sd-ssh.py"
)
spec = importlib.util.spec_from_file_location("native_sd_ssh", SOURCE)
namespace = importlib.util.module_from_spec(spec)
spec.loader.exec_module(namespace)
pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="Linux private host-directory binds"
)


def mounted(path):
    return any(
        line.split()[4] == str(path)
        for line in Path("/proc/self/mountinfo").read_text().splitlines()
    )


@pytest.fixture
def root(tmp_path):
    if os.environ.get("DCENT_TEST_HOST_BINDS") != "1":
        pytest.skip("requires explicit isolated host-directory-bind test runner")
    assert os.readlink("/proc/self/ns/mnt") != os.readlink("/proc/1/ns/mnt")
    tree = tmp_path / "root"
    tree.mkdir(mode=0o700)
    for path in ("etc/dcentos", "data", "root", "outside", "wrong-keys"):
        (tree / path).mkdir(parents=True, mode=0o700)
    (tree / "etc/dcentos/board_target").write_bytes(b"am1-s9i\n")
    (tree / "etc/dcentos/board_target").chmod(0o644)
    (tree / "etc/shadow").write_bytes(b"root:*:1:0:99999:7:::\n")
    try:
        yield tree
    finally:
        for name in ("etc/dropbear", "data/keys/dropbear", "data/dcent"):
            path = tree / name
            assert path.is_relative_to(tree)
            if mounted(path):
                subprocess.run(["/bin/umount", str(path)], check=True, timeout=20)
            assert not mounted(path)
        assert not any(
            str(tree) in row
            for row in Path("/proc/self/mountinfo").read_text().splitlines()
        )
        assert (tree / "etc/shadow").read_bytes() == b"root:*:1:0:99999:7:::\n"


@pytest.mark.parametrize("target", sorted(namespace.TARGETS))
def test_actual_bind_and_fixed_operator_link_for_all_routes(root, target):
    (root / "etc/dcentos/board_target").write_bytes(target)
    original = (root / "etc/shadow").read_bytes()
    result = namespace.prepare(root)
    persistent, host = root / "data/keys/dropbear", root / "etc/dropbear"
    assert result["target"] == target.decode().strip()
    assert not result["ssh_started"]
    assert os.path.samestat(persistent.stat(), host.stat())
    assert mounted(host)
    assert namespace.directory_mount_id(persistent) != namespace.directory_mount_id(
        host
    )
    assert (
        os.readlink(root / "root/.ssh/authorized_keys") == "/data/dcent/authorized_keys"
    )
    assert not (root / "data/dcent/authorized_keys").exists()
    for name in (
        "data/dcent",
        "data/keys",
        "data/keys/dropbear",
        "etc/dropbear",
        "root/.ssh",
    ):
        assert stat.S_IMODE((root / name).stat().st_mode) == 0o700
    mount = namespace.directory_mount_id(host)
    assert namespace.prepare(root) == result
    assert namespace.directory_mount_id(host) == mount
    assert (root / "etc/shadow").read_bytes() == original


def test_actual_bind_retains_existing_key_file_identity(root):
    persistent = root / "data/keys/dropbear"
    persistent.mkdir(parents=True, mode=0o700)
    key = persistent / "dropbear_ed25519_host_key"
    key.write_bytes(b"inert host-key content for namespace test")
    key.chmod(0o600)
    original = key.stat(), key.read_bytes()
    namespace.prepare(root)
    observed = root / "etc/dropbear/dropbear_ed25519_host_key"
    assert observed.read_bytes() == original[1]
    assert os.path.samestat(observed.stat(), original[0])


@pytest.mark.parametrize(
    "name", ["data/dcent", "data/keys", "root/.ssh", "etc/dropbear"]
)
def test_symlinked_namespace_never_touches_outside(root, name):
    path = root / name
    path.parent.mkdir(exist_ok=True)
    path.symlink_to(root / "outside", target_is_directory=True)
    sentinel = root / "outside/sentinel"
    sentinel.write_bytes(b"retained outside file")
    before = sentinel.stat(), sentinel.read_bytes()
    with pytest.raises(ValueError, match="direct protected"):
        namespace.prepare(root)
    assert sentinel.read_bytes() == before[1]
    assert sentinel.stat().st_mode == before[0].st_mode
    assert not mounted(root / "etc/dropbear")


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "wrong-mode", "unexpected"])
def test_bad_persistent_host_key_metadata_refused_without_altering_source(root, kind):
    persistent = root / "data/keys/dropbear"
    persistent.mkdir(parents=True, mode=0o700)
    outside = root / "outside/key"
    outside.write_bytes(b"inert protected original")
    outside.chmod(0o600)
    key = persistent / "dropbear_ed25519_host_key"
    if kind == "symlink":
        key.symlink_to(outside)
    elif kind == "hardlink":
        os.link(outside, key)
    else:
        (key if kind == "wrong-mode" else persistent / "unselected-key").write_bytes(
            outside.read_bytes()
        )
    before = outside.stat(), outside.read_bytes()
    with pytest.raises(ValueError):
        namespace.prepare(root)
    assert outside.read_bytes() == before[1]
    assert outside.stat().st_mode == before[0].st_mode
    assert not mounted(root / "etc/dropbear")


@pytest.mark.parametrize("kind", ["regular", "foreign-symlink"])
def test_operator_key_path_is_never_replaced(root, kind):
    ssh = root / "root/.ssh"
    ssh.mkdir(mode=0o700)
    key = ssh / "authorized_keys"
    if kind == "regular":
        key.write_bytes(b"retained old operator key")
    else:
        key.symlink_to("/etc/shadow")
    with pytest.raises(ValueError, match="fixed persistent"):
        namespace.prepare(root)
    assert (
        key.read_bytes() == b"retained old operator key"
        if kind == "regular"
        else os.readlink(key) == "/etc/shadow"
    )
    assert not mounted(root / "etc/dropbear")


def test_dropped_bind_refuses_success(root):
    with pytest.raises(ValueError, match="bind or target readback"):
        namespace.prepare(root, bind=lambda *_: None)
    assert not mounted(root / "etc/dropbear")


def test_wrong_actual_host_directory_bind_refuses_success(root):
    def wrong_bind(_source, target):
        subprocess.run(
            ["/bin/mount", "--bind", str(root / "wrong-keys"), str(target)], check=True
        )

    with pytest.raises(ValueError, match="bind or target readback"):
        namespace.prepare(root, bind=wrong_bind)
    assert mounted(root / "etc/dropbear")


def test_foreign_application_submount_refuses_before_ssh_bind(root):
    target = root / "data/dcent"
    target.mkdir(mode=0o700)
    subprocess.run(
        ["/bin/mount", "--bind", str(root / "outside"), str(target)], check=True
    )
    with pytest.raises(ValueError, match="share admitted data mount"):
        namespace.prepare(root)
    assert not mounted(root / "etc/dropbear")


def test_dropped_mode_change_is_observed(root, monkeypatch):
    (root / "data/keys/dropbear").mkdir(parents=True, mode=0o755)
    original = Path.chmod

    def dropped(path, mode, **kwargs):
        if path != root / "data/keys/dropbear":
            original(path, mode, **kwargs)

    monkeypatch.setattr(Path, "chmod", dropped)
    with pytest.raises(ValueError, match="mode readback"):
        namespace.prepare(root)
