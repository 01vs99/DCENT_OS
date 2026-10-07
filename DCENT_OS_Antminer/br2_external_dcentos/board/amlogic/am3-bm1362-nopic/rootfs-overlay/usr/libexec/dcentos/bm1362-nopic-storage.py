#!/usr/bin/python3
"""Own the existing, exactly qualified A126/Plus120 AML nvdata volume at boot.

Derived independently for the exact A/Plus controller profiles from the reviewed
Classic filesystem owner. The held model-specific S03mount/kernel/DTB are byte
identical. This admits only the separately observed seven-partition S19j tuple,
not all physical A/Plus storage variants or a generic AML partition
finder. Never format, create a volume, recover a corrupt filesystem, detach a
foreign owner, or import third-party configuration. `check` is observational.
"""
import argparse
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys


MTD = (
    ("bootloader", 0x200000), ("tpl", 0x800000), ("misc", 0x200000),
    ("recovery", 0x1000000), ("boot", 0x2000000), ("config", 0x500000),
    ("nvdata", 0xB900000),
)
DT = "/sys/firmware/devicetree/base"
NAND = DT + "/mtd_nand@ffe07800"
VOLUME = "/mnt/dcentos-nvdata"
DATA_ROOT = "/dcentos/data"
READY = "/run/dcentos/nopic-bm1362-storage-ready.json"
BASELINE = "/etc/init.d/S37board_setup"


class Refused(RuntimeError):
    pass


def require(condition, message):
    if not condition:
        raise Refused(message)


class Storage:
    # `root` exists only for offline fixtures; the installed CLI always uses /.
    def __init__(self, root=Path("/"), runner=None):
        self.root = Path(root)
        self.runner = runner or self.execute
        self.controller = None

    def path(self, name):
        return self.root / name.lstrip("/")

    @staticmethod
    def execute(argv):
        subprocess.run(argv, check=True, timeout=20,
                       env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"})

    def read(self, name):
        return self.path(name).read_text(encoding="utf-8").strip()

    def secure_directory(self, name, create=False, mode=0o755):
        current = self.root
        for component in Path(name).parts[1:]:
            current /= component
            if create and not current.exists() and not current.is_symlink():
                current.mkdir(mode=mode)
            metadata = current.lstat()
            require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                    and metadata.st_gid == 0 and metadata.st_mode & 0o022 == 0,
                    "unsafe directory: " + str(current))
        return current

    def regular_descriptor(self, name, maximum=4096, mode=None):
        self.secure_directory(str(Path(name).parent))
        def admitted(metadata):
            return (stat.S_ISREG(metadata.st_mode) and metadata.st_uid == 0
                    and metadata.st_gid == 0 and metadata.st_nlink == 1
                    and metadata.st_mode & 0o022 == 0 and metadata.st_size <= maximum
                    and (mode is None or stat.S_IMODE(metadata.st_mode) == mode))
        before = self.path(name).lstat()
        # Reject FIFO/device objects before open; NONBLOCK also bounds a
        # replacement race. No special-file open may stall the early gate.
        require(admitted(before), "unsafe file: " + name)
        descriptor = os.open(self.path(name), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        try:
            metadata = os.fstat(descriptor)
            require(admitted(metadata) and (metadata.st_dev, metadata.st_ino)
                    == (before.st_dev, before.st_ino), "file identity changed: " + name)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise

    def protected_read(self, name):
        descriptor = self.regular_descriptor(name)
        try:
            return os.read(descriptor, 4097).decode("utf-8").strip()
        finally:
            os.close(descriptor)

    def controller_identity(self):
        target = self.protected_read("/etc/dcentos/board_target")
        profiles = {"am3-s19jproa": "am3-aml-s19jproa",
                    "am3-s19jproplus": "am3-aml-s19jproplus"}
        platform = profiles.get(target)
        require(platform is not None
                and self.protected_read("/etc/dcentos-platform") == platform
                and self.protected_read("/etc/dcentos/platform") == platform
                and self.protected_read("/etc/dcentos/rail_gpio") == "437",
                "exact A126 or Plus120 image identity required")
        identity = (target, platform)
        require(self.controller is None or self.controller == identity,
                "controller identity changed within the retained storage owner")
        self.controller = identity
        require(self.read("/proc/sys/kernel/osrelease") == "4.9.113",
                "only the held classic kernel4.9.113 controller contract is admitted")
        for name, expected in {
            DT + "/compatible": b"amlogic, axg\0",
            DT + "/amlogic-dt-id": b"axg_s400_v03sbr\0",
        }.items():
            require(self.path(name).read_bytes() == expected, "live DT mismatch: " + name)

    def identity(self):
        self.controller_identity()
        for name, expected in {
            NAND + "/compatible": b"amlogic, aml_mtd_nand\0",
            NAND + "/status": b"okay\0",
            NAND + "/nand_partition/nvdata/offset": b"\xff" * 8,
            NAND + "/nand_partition/nvdata/size": b"\0" * 8,
        }.items():
            require(self.path(name).read_bytes() == expected, "live DT mismatch: " + name)
        # DT sizes for fixed partitions; nvdata is explicitly the remainder,
        # so its observed physical size is separately bound below, not guessed.
        for name, size in MTD[2:6]:
            require(self.path(NAND + "/nand_partition/" + name + "/size").read_bytes()
                    == size.to_bytes(8, "big"), "live DT partition size mismatch: " + name)
        rows = self.read("/proc/mtd").splitlines()
        require(len(rows) == 8 and rows[0].split() == ["dev:", "size", "erasesize", "name"],
                "expected the exact seven-partition nvdata layout")
        for index, ((name, size), row) in enumerate(zip(MTD, rows[1:])):
            expected = f'mtd{index}: {size:08x} 00020000 "{name}"'
            require(" ".join(row.split()) == expected, "MTD layout mismatch: " + row)
            prefix = f"/sys/class/mtd/mtd{index}/"
            require(self.read(prefix + "name") == name
                    and self.read(prefix + "type") == "nand"
                    and int(self.read(prefix + "size")) == size
                    and int(self.read(prefix + "erasesize")) == 0x20000
                    and int(self.read(prefix + "writesize")) == 2048,
                    "sysfs MTD identity/geometry mismatch: " + name)

    def volume(self):
        prefix = "/sys/class/ubi/ubi0/"
        require(self.read(prefix + "mtd_num") == "6", "UBI0 has a foreign MTD owner")
        require(self.read(prefix + "volumes_count") == "1"
                and self.read(prefix + "ro_mode") == "0"
                and self.read(prefix + "min_io_size") == "2048"
                and self.read(prefix + "eraseblock_size") == "126976",
                "UBI0 is read-only or has unqualified geometry/population")
        require(sorted(p.name for p in self.path("/sys/class/ubi").glob("ubi0_*")) == ["ubi0_0"],
                "expected the existing single UBI0 volume0")
        prefix = "/sys/class/ubi/ubi0_0/"
        require(self.read(prefix + "name") == "nvdada_log"
                and self.read(prefix + "type") == "dynamic"
                and self.read(prefix + "corrupted") == "0"
                and self.read(prefix + "upd_marker") == "0"
                and self.read(prefix + "usable_eb_size") == "126976",
                "existing nvdada_log volume is absent, corrupt, updating, or unqualified")
        reserved = int(self.read(prefix + "reserved_ebs"))
        require(0 < reserved * 126976 <= MTD[6][1], "UBI volume capacity exceeds nvdata")

    def mounts(self):
        result = []
        for line in self.read("/proc/self/mountinfo").splitlines():
            before, after = line.split(" - ", 1)
            left, right = before.split(), after.split()
            require(len(left) >= 6 and len(right) == 3, "invalid mountinfo")
            result.append({"id": left[0], "device": left[2], "root": left[3],
                           "target": left[4], "options": set(left[5].split(",")),
                           "fs": right[0], "source": right[1],
                           "super_options": set(right[2].split(","))})
        return result

    def at(self, target):
        return [item for item in self.mounts() if item["target"] == target]

    def mounted(self):
        roots, data, keys = self.at(VOLUME), self.at("/data"), self.at("/etc/dropbear")
        require(len(roots) == len(data) == len(keys) == 1,
                "exact nvdata, /data and persistent SSH-key mounts are required")
        base = roots[0]
        require(base["root"] == "/" and base["fs"] == "ubifs"
                and base["source"] in ("ubi0_0", "/dev/ubi0_0", "ubi0:nvdada_log"),
                "nvdata mount has a foreign filesystem/source")
        for item, root in [(base, "/"), (data[0], DATA_ROOT),
                           (keys[0], DATA_ROOT + "/keys/dropbear")]:
            require(item["root"] == root and item["device"] == base["device"]
                    and item["fs"] == base["fs"] and item["source"] == base["source"]
                    and {"rw", "nosuid", "nodev", "noexec"} <= item["options"]
                    and "rw" in item["super_options"],
                    "persistent mount source/root/options mismatch: " + item["target"])
        for name in (VOLUME + "/dcentos", VOLUME + DATA_ROOT, "/data/dcent",
                     "/data/keys", "/data/keys/dropbear", "/etc/dropbear"):
            self.secure_directory(name)
        self.operator_keys(create=False)
        return {"volume_mount_id": base["id"], "data_mount_id": data[0]["id"],
                "keys_mount_id": keys[0]["id"], "device": base["device"]}

    def check(self):
        self.identity()
        self.volume()
        actual = self.mounted()
        proof = json.loads(self.protected_read(READY))
        require(proof == {"schema": 1, "board_target": self.controller[0], "boot_id": self.read("/proc/sys/kernel/random/boot_id"),
                          **actual}, "persistent readiness is stale or not this mount namespace")

    def character(self, name, sysfs):
        major, minor = (int(value) for value in self.read(sysfs).split(":"))
        metadata = self.path(name).lstat()
        require(stat.S_ISCHR(metadata.st_mode) and metadata.st_uid == 0
                and metadata.st_gid == 0 and metadata.st_mode & 0o022 == 0
                and metadata.st_rdev == os.makedev(major, minor),
                "device node disagrees with kernel: " + name)

    def operator_keys(self, create):
        directory = self.secure_directory("/root/.ssh", create=create, mode=0o700)
        if create:
            directory.chmod(0o700)
        require(stat.S_IMODE(directory.lstat().st_mode) == 0o700, "root SSH directory must be0700")
        target = "/data/dcent/authorized_keys"
        self.secure_directory("/data/dcent")
        key_file = self.path(target)
        # An unprovisioned target deliberately stays absent. Never generate or
        # copy an operator login credential; refuse foreign file indirection.
        if key_file.exists() or key_file.is_symlink():
            descriptor = self.regular_descriptor(target, maximum=256 * 1024, mode=0o600)
            os.close(descriptor)
        link = directory / "authorized_keys"
        if create and not link.exists() and not link.is_symlink():
            link.symlink_to(target)
        metadata = link.lstat()
        require(stat.S_ISLNK(metadata.st_mode) and metadata.st_uid == 0
                and metadata.st_gid == 0 and os.readlink(link) == target,
                "root authorized_keys must link exactly to the persistent operator keys")

    def bind(self, source, target):
        self.secure_directory(target, create=True)
        require(not self.at(target), "refusing an existing mount at " + target)
        self.runner(["/bin/mount", "--bind", source, target])
        self.runner(["/bin/mount", "-o", "remount,bind,rw,nosuid,nodev,noexec", target])

    def start_storage(self):
        self.identity()
        self.secure_directory("/run/dcentos", create=True, mode=0o700)
        # Never overwrite an earlier outcome or mount over another owner.
        require(not self.path(READY).exists() and not self.path(READY).is_symlink(),
                "persistent setup already ran; use observational check")
        require(not self.at(VOLUME) and not self.at("/data") and not self.at("/etc/dropbear"),
                "refusing pre-existing persistent mount ownership")
        if not self.path("/sys/class/ubi/ubi0").exists():
            for other in self.path("/sys/class/ubi").glob("ubi[0-9]*"):
                if (other / "mtd_num").exists():
                    require((other / "mtd_num").read_text().strip() != "6",
                            "nvdata is already attached under a different UBI owner")
            self.character("/dev/ubi_ctrl", "/sys/class/misc/ubi_ctrl/dev")
            self.character("/dev/mtd6", "/sys/class/mtd/mtd6/dev")
            self.runner(["/usr/sbin/ubiattach", "/dev/ubi_ctrl", "-d", "0", "-m", "6"])
        self.volume()
        # No existing mount of this UBI is adopted, even if it is read-only.
        require(not any(item["source"] in ("ubi0_0", "/dev/ubi0_0", "ubi0:nvdada_log")
                        for item in self.mounts()), "existing UBI volume mount has another owner")
        self.secure_directory(VOLUME, create=True)
        self.runner(["/bin/mount", "-t", "ubifs", "-o", "rw,nosuid,nodev,noexec", "ubi0_0", VOLUME])
        # Validate the real filesystem before creating our isolated namespace.
        mounted = self.at(VOLUME)
        require(len(mounted) == 1 and mounted[0]["root"] == "/"
                and mounted[0]["fs"] == "ubifs" and mounted[0]["source"] == "ubi0_0"
                and {"rw", "nosuid", "nodev", "noexec"} <= mounted[0]["options"]
                and "rw" in mounted[0]["super_options"], "UBIFS mount readback failed")
        for suffix in ("", "/dcent", "/keys/dropbear", "/config", "/logs"):
            self.secure_directory(VOLUME + DATA_ROOT + suffix, create=True, mode=0o700)
        self.bind(VOLUME + DATA_ROOT, "/data")
        self.bind("/data/keys/dropbear", "/etc/dropbear")
        self.operator_keys(create=True)
        actual = self.mounted()
        proof = {"schema": 1, "board_target": self.controller[0], "boot_id": self.read("/proc/sys/kernel/random/boot_id"), **actual}
        descriptor = os.open(self.path(READY), os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            json.dump(proof, output, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
        self.check()

    def early(self):
        # A refused nvdata volume must not strand inherited hash power: PID1
        # skips all S## services after early-init failure. Establish only the
        # volatile prerequisites for the existing checked board owner first.
        # Its exact identity/policy, GPIO437 high, cap30 fans and reset readback
        # remain authoritative; this helper adds no electrical implementation.
        self.virtual_fs(stage="baseline")
        self.controller_identity()
        descriptor = self.regular_descriptor(BASELINE, maximum=128 * 1024, mode=0o755)
        os.close(descriptor)
        self.runner([BASELINE, "start"])
        self.virtual_fs(stage="remaining")
        self.start_storage()

    def virtual_fs(self, stage="all"):
        # PID1 already mounted proc/sys. Use this exact kernel's devtmpfs so
        # UART, I2C, UBI and watchdog nodes follow real kernel device numbers.
        self.controller_identity()
        mounts = (
            ("/dev", "devtmpfs", "devtmpfs", "mode=0755,nosuid", {"rw", "nosuid"}),
            ("/run", "tmpfs", "tmpfs", "mode=0755,nosuid,nodev,size=8m", {"rw", "nosuid", "nodev"}),
            ("/tmp", "tmpfs", "tmpfs", "mode=1777,nosuid,nodev,size=64m", {"rw", "nosuid", "nodev"}),
            ("/dev/pts", "devpts", "devpts", "gid=5,mode=620,ptmxmode=666,nosuid,noexec", {"rw", "nosuid", "noexec"}),
            ("/dev/shm", "tmpfs", "tmpfs", "mode=1777,nosuid,nodev,noexec,size=8m", {"rw", "nosuid", "nodev", "noexec"}),
        )
        require(stage in ("all", "baseline", "remaining"), "invalid volatile setup stage")
        selected = mounts[:2] if stage == "baseline" else mounts[2:] if stage == "remaining" else mounts
        for target, source, filesystem, options, required_options in selected:
            if target in ("/tmp", "/dev/shm"):
                self.secure_directory(str(Path(target).parent))
                directory = self.path(target)
                if not directory.exists() and not directory.is_symlink():
                    directory.mkdir(mode=0o755)
                metadata = directory.lstat()
                require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == 0
                        and metadata.st_gid == 0 and stat.S_IMODE(metadata.st_mode) in (0o755, 0o1777),
                        "unsafe virtual directory: " + target)
            else:
                self.secure_directory(target, create=True)
            prior = self.at(target)
            if prior and len(prior) == 1 and prior[0]["fs"] == filesystem:
                self.virtual_mount(prior[0], filesystem, source, required_options)
                continue
            if prior:
                require(target == "/dev" and len(prior) == 1 and prior[0]["fs"] == "tmpfs",
                        "unexpected virtual mount at " + target)
                self.virtual_mount(prior[0], "tmpfs", "tmpfs", {"rw"})
            self.runner(["/bin/mount", "-t", filesystem, "-o", options, source, target])
            current = self.at(target)
            if prior:
                # Covered PID1 tmpfs may remain in mountinfo. Retain its exact
                # ID/metadata and admit exactly one new devtmpfs over it.
                covered = [item for item in current if item["id"] == prior[0]["id"]]
                require(covered == prior and len(current) == 2, "unexpected /dev replacement mount count")
                current = [item for item in current if item["id"] != prior[0]["id"]]
            require(len(current) == 1, "virtual mount readback count differs")
            self.virtual_mount(current[0], filesystem, source, required_options)
        if stage == "baseline":
            self.secure_directory("/run/dcentos", create=True, mode=0o700)
            return
        self.secure_directory("/run/lock", create=True)
        for name, destination in (("fd", "/proc/self/fd"), ("stdin", "fd/0"),
                                  ("stdout", "fd/1"), ("stderr", "fd/2")):
            path = self.path("/dev/" + name)
            if path.is_symlink():
                require(os.readlink(path) == destination, "unexpected /dev link: " + name)
            else:
                require(not path.exists(), "unexpected /dev object: " + name)
                path.symlink_to(destination)
        self.runner(["/sbin/ip", "link", "set", "lo", "up"])
        hostname = self.protected_read("/etc/hostname")
        require(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", hostname) is not None,
                "invalid protected hostname")
        self.runner(["/bin/hostname", hostname])

    @staticmethod
    def virtual_mount(item, filesystem, source, required_options):
        require(item["root"] == "/" and item["fs"] == filesystem and item["source"] == source
                and required_options <= item["options"] and "ro" not in item["options"]
                and "rw" in item["super_options"] and "ro" not in item["super_options"]
                and (filesystem not in ("devtmpfs", "devpts") or "nodev" not in item["options"]),
                "virtual mount source/root/options mismatch: " + item["target"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("early", "check"))
    arguments = parser.parse_args()
    require(os.geteuid() == 0, "root required")
    owner = Storage()
    if arguments.action == "early":
        owner.early()
    else:
        owner.check()
    print("A126/Plus120 AML existing nvdata: persistent namespace verified")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, Refused, subprocess.SubprocessError) as error:
        print("A126/Plus120 AML persistent storage refused: " + str(error), file=sys.stderr)
        sys.exit(1)
