"""Read-only configuration composition checks; no configure/build process."""

from pathlib import Path, PurePosixPath
import importlib
import sys

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "DCENT_OS_Antminer/scripts"))
producer = importlib.import_module("native_zynq_sd.prepare_build")


def values(config):
    """Independent last-assignment reader for this defconfig text subset."""
    result = {}
    for line in config.splitlines():
        if line.startswith("BR2_") and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
        elif line.startswith("# BR2_") and line.endswith(" is not set"):
            result[line[2:-11]] = "n"
    return result


@pytest.mark.parametrize("family", ["am1", "am2"])
def test_actual_source_configs_keep_dependencies_and_replace_legacy_routes(family):
    configs = ROOT / "DCENT_OS_Antminer/br2_external_dcentos/configs"
    board = (
        "dcentos_s9_defconfig"
        if family == "am1"
        else "dcentos_am2_s17pro_zynq_defconfig"
    )
    base = "\n".join(
        (configs / name).read_text(encoding="utf-8")
        for name in ("dcentos-common.fragment", board)
    )
    job = PurePosixPath("/root/fixture-" + family)
    compiler = PurePosixPath("/root/input/compiler.tar.xz")
    rendered = producer.render_defconfig(base, family, job, compiler)
    config = values(rendered)
    assert rendered.startswith(base + "\n")
    assert config["BR2_ROOTFS_OVERLAY"] == '"' + str(job / "overlay") + '"'
    assert config["BR2_ROOTFS_POST_BUILD_SCRIPT"] == (
        '"'
        + str(job / "source/DCENT_OS_Antminer/scripts/native_zynq_sd/post_build.sh")
        + '"'
    )
    assert config["BR2_ROOTFS_POST_SCRIPT_ARGS"] == '"' + str(job / "inputs.json") + '"'
    assert (
        config["BR2_TOOLCHAIN_EXTERNAL_URL"] == '"file:///root/input/compiler.tar.xz"'
    )
    assert config["BR2_ROOTFS_POST_IMAGE_SCRIPT"] == '""'
    assert config["BR2_PACKAGE_BUSYBOX_CONFIG"] == '"$(BR2_EXTERNAL_DCENTOS_PATH)/board/zynq/native-sd/busybox.config"'
    assert config["BR2_TARGET_GENERIC_ROOT_PASSWD"] == '"*"'
    assert config["BR2_TARGET_ENABLE_ROOT_LOGIN"] == "n"
    assert config["BR2_JLEVEL"] == "2"
    assert config["BR2_REPRODUCIBLE"] == "y"
    for key in (
        "PACKAGE_DCENTOS_TOOLS",
        "PACKAGE_AM2_NAND_WINDOW",
        "PACKAGE_MTD",
        "PACKAGE_MTD_UBIFS_UTILS",
        "PACKAGE_LIBUBOOTENV",
        "PACKAGE_LIBUBOOTENV_TOOLS",
        "PACKAGE_STRACE",
        "TARGET_ROOTFS_EXT2",
        "LINUX_KERNEL",
        "TARGET_UBOOT",
    ):
        assert config["BR2_" + key] == "n", key
    for key in (
        "arm",
        "cortex_a9",
        "PACKAGE_PYTHON3",
        "PACKAGE_BASH",
        "PACKAGE_DROPBEAR",
        "PACKAGE_DCENTOS_DEPLOY_LOCK",
        "PACKAGE_DCENTOS_DEPLOY_PATH",
        "PACKAGE_SEED_ENTROPY",
        "PACKAGE_UTIL_LINUX",
        "PACKAGE_HOST_UBOOT_TOOLS",
        "TARGET_ROOTFS_SQUASHFS",
        "TARGET_ROOTFS_SQUASHFS_BS_1024K",
    ):
        assert config["BR2_" + key] == "y", key
    assert config["BR2_TARGET_ROOTFS_SQUASHFS4_GZIP"] == (
        "y" if family == "am1" else "n"
    )
    assert config["BR2_TARGET_ROOTFS_SQUASHFS4_XZ"] == ("y" if family == "am2" else "n")
    # Configuration text is an input; Kconfig and actual root readback remain
    # distinct qualifications after the root-owned build slot is available.


@pytest.mark.parametrize("family", ["am1-s9i", "am2-s19pro", "aml", "", "AM2"])
def test_foreign_build_family_refused(family):
    with pytest.raises(ValueError, match="build family"):
        producer.render_defconfig(
            "", family, PurePosixPath("/root/job"), PurePosixPath("/root/compiler")
        )


@pytest.mark.parametrize(
    "bad",
    ["relative", "/root/job\nnext", "/root/job\rnext", '/root/"job', "/root/\\job"],
)
@pytest.mark.parametrize("position", ["job", "compiler"])
def test_unrepresentable_configuration_paths_refused(bad, position):
    paths = {
        "job": PurePosixPath("/root/job"),
        "compiler": PurePosixPath("/root/compiler"),
    }
    paths[position] = PurePosixPath(bad)
    with pytest.raises(ValueError, match="build path"):
        producer.render_defconfig("", "am1", paths["job"], paths["compiler"])
