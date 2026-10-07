"""Inspect a complete immutable native28 base, preserving its exact provenance.

No source path, device or executable is opened by this module. It reads the
entire SquashFS and joins the frozen build/finalizer contract. A passed base is
not a successor SSH root, final card, physical qualification or writer permit.
"""

from __future__ import annotations

from collections import deque
import hashlib
import posixpath

from dcent_toolbox.core.arm_elf_dependencies import arm_elf_dependencies
from dcent_toolbox.core.squashfs_files import SquashfsFiles


def resolve(inventory: dict, path: str) -> str:
    """Resolve an image path inside the immutable root, never the host namespace."""
    parts, done, links = deque(path.lstrip("/").split("/")), [], 0
    while parts:
        part = parts.popleft()
        if part in ("", "."):
            continue
        if part == "..":
            if not done:
                raise ValueError("image symlink leaves root")
            done.pop()
            continue
        candidate = "/".join(done + [part])
        row = inventory.get(candidate)
        if row is None:
            raise ValueError("missing image dependency: " + candidate)
        if row["kind"] == 3:
            links += 1
            if links > 40:
                raise ValueError("image dependency symlink loop")
            target = bytes.fromhex(row["target_hex"]).decode("utf-8")
            if target.startswith("/"):
                done = []
            parts.extendleft(reversed(target.split("/")))
        else:
            if parts and row["kind"] != 1:
                raise ValueError("non-directory dependency parent")
            done.append(part)
    return "/".join(done)


def runtime_dependencies(fs: SquashfsFiles, inventory: dict) -> dict:
    """Decode all ELF inputs and resolve every interpreter and DT_NEEDED edge."""
    objects, by_inode = {}, {}
    for name, row in inventory.items():
        if row["kind"] != 2:
            continue
        if row["inode"] in by_inode:
            parsed = by_inode[row["inode"]]
        else:
            raw = fs.read(name)
            parsed = arm_elf_dependencies(raw) if raw[:4] == b"\x7fELF" else None
            by_inode[row["inode"]] = parsed
        if parsed is not None:
            objects[name] = parsed
    graph = {}
    for name, parsed in objects.items():
        edges = []
        if parsed["interpreter"]:
            target = resolve(inventory, parsed["interpreter"])
            if target not in objects or not inventory[target]["mode"] & 0o111:
                raise ValueError("executable ELF interpreter absent: " + name)
            edges.append(
                {
                    "kind": "interpreter",
                    "name": parsed["interpreter"],
                    "resolved": target,
                }
            )
        directories = []
        for _tag, value in parsed["search_paths"]:
            # Buildroot clears build-tree RPATH strings in-place. A completely
            # empty tag adds no loader search directory; empty colon elements
            # in a nonempty tag remain refused below.
            if not value:
                continue
            for directory in value.split(":"):
                directory = directory.replace("${ORIGIN}", "$ORIGIN").replace(
                    "$ORIGIN", "/" + posixpath.dirname(name)
                )
                if (
                    not directory.startswith("/")
                    or "$" in directory
                    or ".." in directory.split("/")
                ):
                    raise ValueError("unsupported ELF search directory: " + name)
                directories.append(directory)
        directories += ["/lib", "/usr/lib"]
        for needed in parsed["needed"]:
            if "/" in needed or needed in (".", ".."):
                raise ValueError("plain ELF dependency basename required")
            found = None
            for directory in directories:
                candidate = directory.rstrip("/") + "/" + needed
                if candidate.lstrip("/") not in inventory:
                    continue
                found = resolve(inventory, candidate)
                if found not in objects:
                    raise ValueError("ELF dependency resolves to non-ELF")
                break
            if found is None:
                raise ValueError("ELF dependency absent: " + name + " needs " + needed)
            edges.append({"kind": "needed", "name": needed, "resolved": found})
        graph[name] = {**parsed, "resolved_dependencies": edges}
    return graph


def inspect_base(raw: bytes, manifest: dict, finalization: dict) -> dict:
    fs = SquashfsFiles(raw)
    inventory = fs.inventory()
    if (
        manifest.get("schema") != "dcentos.native_zynq_sd_build_inputs.v1"
        or manifest.get("native_checkpoint") != 28
    ):
        raise ValueError("exact frozen native28 base manifest required")
    if (
        finalization.get("schema") != "dcentos.native_zynq_sd_root_finalization.v1"
        or finalization.get("board_target") != manifest["board_target"]
    ):
        raise ValueError("matching actual base finalization required")
    if finalization["overlay"] != manifest["overlay"]:
        raise ValueError("frozen overlay/finalization differ")
    if fs.compressor != (1 if manifest["family"] == "am1" else 4):
        raise ValueError("actual base compressor differs")
    if any(row["kind"] not in (1, 2, 3) for row in inventory.values()):
        raise ValueError(
            "base contains special nodes; ordinary-file extraction not admitted"
        )
    for name, expected in manifest["overlay"].items():
        row = inventory.get(name, {})
        links = 2 if name == "usr/local/bin/dcentrald" else 1
        if (
            row.get("kind") != 2
            or row.get("mode") != expected["mode"]
            or row.get("uid") != 0
            or row.get("gid") != 0
            or row.get("nlink") != links
            or any(row.get(key) != expected[key] for key in ("bytes", "sha256"))
        ):
            raise ValueError("complete base overlay differs: " + name)
    left, right = inventory["usr/local/bin/dcentrald"], inventory["usr/bin/dcentrald"]
    if left != right or left["nlink"] != 2:
        raise ValueError("exact two daemon hard links required")
    services = {
        name.removeprefix("etc/init.d/")
        for name in inventory
        if name.startswith("etc/init.d/")
    }
    if services != set(finalization["services"]) or services != set(
        manifest["services"]
    ) | {"rcS", "rcK"}:
        raise ValueError("complete base startup service set differs")
    for name, expected in finalization["generated_startup"].items():
        row = inventory["etc/init.d/" + name]
        if (
            row["kind"] != 2
            or row["nlink"] != 1
            or row["uid"] != 0
            or row["gid"] != 0
            or any(row[key] != expected[key] for key in ("mode", "bytes", "sha256"))
        ):
            raise ValueError("actual generated startup differs")
    shadow = inventory["etc/shadow"]
    if (
        shadow["kind"] != 2
        or shadow["nlink"] != 1
        or shadow["mode"] != 0o600
        or shadow["uid"] != 0
        or shadow["gid"] != 0
        or shadow["sha256"] != finalization["root_credential_sha256"]
    ):
        raise ValueError("base root credential identity differs")
    rows = [
        row.split(b":")
        for row in fs.read("etc/shadow").splitlines()
        if row.startswith(b"root:")
    ]
    if (
        len(rows) != 1
        or len(rows[0]) != 9
        or rows[0][1] not in (b"*", b"!", b"!*", b"!!")
    ):
        raise ValueError("base root password must remain locked")
    forbidden = {
        "data/dcentrald",
        "data/dcentrald.toml",
        "data/dcentrald-experimental.toml",
        "etc/dcentos/external-media-ephemeral-root",
        "etc/dcentos/first-boot-grace",
        "usr/sbin/sysupgrade",
        "usr/sbin/fw_setenv",
        "usr/sbin/nandwrite",
    }
    if forbidden & inventory.keys() or any(
        name.startswith("data/") and row["kind"] != 1 for name, row in inventory.items()
    ):
        raise ValueError("retained data or legacy writer in base root")
    writer_names = {
        "sysupgrade",
        "fw_setenv",
        "nandwrite",
        "flash_erase",
        "flash_eraseall",
        "ubiformat",
        "ubiupdatevol",
    }
    if any(name.rsplit("/", 1)[-1] in writer_names for name in inventory):
        raise ValueError("legacy writer command present in base root")
    dependencies = runtime_dependencies(fs, inventory)
    required = (
        "bin/sh",
        "bin/mount",
        "bin/mknod",
        "bin/mkdir",
        "bin/ln",
        "bin/cp",
        "bin/chmod",
        "bin/cat",
        "bin/hostname",
        "sbin/ip",
        "usr/bin/awk",
        "usr/bin/python3",
        "usr/sbin/dropbear",
        "usr/bin/dropbearkey",
        "usr/sbin/seed-entropy",
        "usr/libexec/dcentos/dcentos-deploy-lock",
        "usr/libexec/dcentos/dcentos-deploy-path",
        "sbin/init",
        "usr/local/bin/dcentrald",
        "usr/bin/dcentos-discovery",
    )
    executables = {}
    for name in required:
        target = resolve(inventory, name)
        row = inventory[target]
        if (
            target not in dependencies
            or row["kind"] != 2
            or not row["mode"] & 0o111
            or row["mode"] & 0o022
            or row["uid"] != 0
            or row["gid"] != 0
        ):
            raise ValueError("required protected executable absent: " + name)
        executables[name] = target
    for name in ("sbin/init", "usr/local/bin/dcentrald", "usr/bin/dcentos-discovery"):
        parsed = dependencies[name]
        if parsed["dynamic"] or parsed["interpreter"] or parsed["needed"]:
            raise ValueError("native28 input must be static")
    if (
        fs.read("etc/dcentos/board_target")
        != (manifest["board_target"] + "\n").encode()
    ):
        raise ValueError("exact base target bytes required")
    return {
        "schema": "dcentos.native_zynq_sd_base_inspection.v1",
        "board_target": manifest["board_target"],
        "native_checkpoint": 28,
        "root": {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        "inventory": inventory,
        "elf_dependencies": dependencies,
        "required_executables": executables,
        "root_password_locked": True,
        "frozen_overlay_exact": True,
        "successor_ssh_composition_required": True,
        "complete_card": False,
        "physical_qualification": False,
        "execution": False,
    }
