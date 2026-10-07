#!/usr/bin/env python3
"""Test-only decoding of paused QEMU nandsim memory into raw NAND snapshots.

No hardware or debugger connection is opened here. Callers supply a memory
reader for their stopped, owned QEMU instance. Only simulated flash pages and
the bad-block table are retained; UBI/UBIFS and process memory are discarded.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import stat
import struct


class SnapshotError(ValueError):
    pass


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def span(raw: bytes, offset: int, size: int) -> bytes:
    if not 0 <= offset <= len(raw) or not 0 <= size <= len(raw) - offset:
        raise SnapshotError("binary extent is outside its retained bytes")
    return raw[offset:offset + size]


def cstring(raw: bytes, offset: int) -> str:
    if not 0 <= offset < len(raw):
        raise SnapshotError("string offset is outside its table")
    end = raw.find(b"\0", offset)
    if end < 0:
        raise SnapshotError("unterminated binary string")
    return raw[offset:end].decode("ascii")


class Elf:
    def __init__(self, raw: bytes):
        if len(raw) < 64 or raw[:7] != b"\x7fELF\x02\x01\x01" or struct.unpack_from("<H", raw, 18)[0] != 62:
            raise SnapshotError("exact x86-64 little-endian ELF required")
        offset = struct.unpack_from("<Q", raw, 40)[0]
        size, count, index = struct.unpack_from("<HHH", raw, 58)
        if size != 64 or not 0 < count <= 65535 or not 0 < index < count:
            raise SnapshotError("bounded ordinary section table required")
        table = span(raw, offset, size * count)
        self.rows = [struct.unpack_from("<IIQQQQIIQQ", table, n * size) for n in range(count)]
        names = self.rows[index]
        strings = span(raw, names[4], names[5])
        self.sections = {}
        for row in self.rows:
            name = cstring(strings, row[0])
            if name in self.sections:
                raise SnapshotError("duplicate ELF section name")
            self.sections[name] = row
        self.raw = raw

    def section(self, name: str) -> bytes:
        try:
            row = self.sections[name]
        except KeyError as error:
            raise SnapshotError("required ELF section absent: " + name) from error
        if row[1] == 8:
            raise SnapshotError("NOBITS section has no retained file bytes")
        return span(self.raw, row[4], row[5])

    def symbol(self, name: str) -> tuple[str, int]:
        row = self.sections.get(".symtab")
        if row is None or row[9] != 24 or row[5] % 24 or row[6] >= len(self.rows):
            raise SnapshotError("ordinary ELF symbol table required")
        strings_row = self.rows[row[6]]
        strings = span(self.raw, strings_row[4], strings_row[5])
        names = {self.rows.index(value): key for key, value in self.sections.items()}
        found = []
        for offset in range(row[4], row[4] + row[5], 24):
            noff, info, other, index, value, size = struct.unpack("<IBBHQQ", span(self.raw, offset, 24))
            if cstring(strings, noff) == name:
                if info & 15 != 1 or size != 8 or index not in names:
                    raise SnapshotError("nsmtd must be a pointer-sized module object")
                found.append((names[index], value))
        if len(found) != 1:
            raise SnapshotError("unique module symbol required: " + name)
        return found[0]


@dataclass(frozen=True)
class Type:
    name: str
    kind: int
    value: int
    members: tuple[tuple[str, int, int], ...] = ()
    bitfields: bool = False


class Btf:
    def __init__(self):
        self.types = {0: Type("void", 0, 0)}
        self.strings = b""

    def add(self, raw: bytes) -> None:
        header = struct.unpack("<HBB5I", span(raw, 0, 24))
        magic, version, flags, size, toff, tlen, soff, slen = header
        if magic != 0xEB9F or version != 1 or flags != 0 or size != 24 or tlen > 32 * 1024**2:
            raise SnapshotError("unsupported BTF header")
        table = span(raw, size + toff, tlen)
        self.strings += span(raw, size + soff, slen)
        cursor = 0
        while cursor < len(table):
            noff, info, value = struct.unpack("<III", span(table, cursor, 12))
            cursor += 12
            kind, count = info >> 24 & 31, info & 65535
            sizes = {1: 4, 2: 0, 3: 12, 4: count*12, 5: count*12, 6: count*8,
                     7: 0, 8: 0, 9: 0, 10: 0, 11: 0, 12: 0, 13: count*8,
                     14: 4, 15: count*12, 16: 0, 17: 4, 18: 0, 19: count*12}
            if kind not in sizes:
                raise SnapshotError("unsupported BTF kind")
            body = span(table, cursor, sizes[kind])
            members = []
            if kind in (4, 5):
                for position in range(count):
                    name, tid, bits = struct.unpack_from("<III", body, position * 12)
                    members.append((cstring(self.strings, name), tid, bits))
            self.types[len(self.types)] = Type(cstring(self.strings, noff), kind, value,
                                               tuple(members), bool(info & 0x80000000))
            cursor += len(body)
            if len(self.types) > 500000:
                raise SnapshotError("BTF type inventory exceeds bound")

    def structure(self, name: str) -> Type:
        matches = [value for value in self.types.values() if value.kind == 4 and value.name == name]
        if len(matches) != 1:
            raise SnapshotError("unique BTF structure required: " + name)
        return matches[0]

    def member(self, parent: Type, name: str) -> tuple[int, Type]:
        found = [(tid, bits) for key, tid, bits in parent.members if key == name]
        if len(found) != 1:
            raise SnapshotError("unique ordinary BTF member required: " + name)
        tid, bits = found[0]
        if parent.bitfields:
            if bits >> 24:
                raise SnapshotError("snapshot member is a bitfield rather than an ordinary object")
            bits &= 0xFFFFFF
        if bits % 8 or bits // 8 >= parent.value or tid not in self.types:
            raise SnapshotError("invalid BTF member offset/type")
        return bits // 8, self.types[tid]


@dataclass(frozen=True)
class Schema:
    btf: Btf
    kernel_sha256: str
    module_sha256: str
    base_btf_sha256: str
    module_btf_sha256: str
    symbol_section: str
    symbol_offset: int
    nsmtd_offset: int

    @classmethod
    def decode(cls, kernel_elf: bytes, module: bytes, *, kernel_sha256: str,
               expected_module_sha256: str) -> "Schema":
        # The caller verifies the compressed kernel against inputs.lock before
        # extraction; kernel_sha256 names that authority, not a new ELF pin.
        if not _digest(kernel_sha256) or sha(module) != expected_module_sha256:
            raise SnapshotError("module or original kernel binding differs")
        base, extra = Elf(kernel_elf).section(".BTF"), Elf(module).section(".BTF")
        btf = Btf()
        btf.add(base)
        btf.add(extra)
        ns = btf.structure("nandsim")
        chip_offset, chip = btf.member(ns, "chip")
        base_offset, device = btf.member(chip, "base")
        mtd_offset, mtd = btf.member(device, "mtd")
        if (chip.name, device.name, mtd.name) != ("nand_chip", "nand_device", "mtd_info"):
            raise SnapshotError("unexpected nandsim ownership structure")
        section, offset = Elf(module).symbol("nsmtd")
        return cls(btf, kernel_sha256, sha(module), sha(base), sha(extra), section, offset,
                   chip_offset + base_offset + mtd_offset)


def _digest(value) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def pointer(value: int) -> int:
    if not 0xFFFF800000000000 <= value <= 0xFFFFFFFFFFFFFFF8 or value % 8:
        raise SnapshotError("expected an aligned x86-64 guest kernel pointer")
    return value


def regular(path: Path, maximum: int) -> bytes:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > maximum:
        raise SnapshotError("bounded single-link regular snapshot file required")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        if not os.path.samestat(before, os.fstat(stream.fileno())):
            raise SnapshotError("snapshot file changed before reading")
        raw = stream.read(maximum + 1)
        after = os.fstat(stream.fileno())
        if (len(raw) != before.st_size or after.st_mtime_ns != before.st_mtime_ns
                or not os.path.samestat(after, path.lstat())):
            raise SnapshotError("snapshot file changed during reading")
    return raw


def snapshot(schema: Schema, read, *, nsmtd_address: int, output: Path, boundary: str,
             bad_blocks: tuple[int, ...] = ()) -> dict:
    """Read only a stopped simulator's pages, including OOB and allocation map."""
    if not boundary or len(boundary) > 160 or any(ord(c) < 32 for c in boundary):
        raise SnapshotError("bounded logical cut boundary required")
    if output.exists() or output.is_symlink():
        raise SnapshotError("new private snapshot directory required")
    if (any(type(value) is not int or not 0 <= value < 2048 for value in bad_blocks)
            or tuple(sorted(set(bad_blocks))) != bad_blocks):
        raise SnapshotError("ordered exact guest bad-block census required")
    def memory(address, size):
        pointer(address)
        if not 0 < size <= 2 * 1024**2:
            raise SnapshotError("guest memory read exceeds bound")
        raw = read(address, size)
        if len(raw) != size:
            raise SnapshotError("short stopped-guest memory read")
        return raw
    ns_pointer = struct.unpack("<Q", memory(nsmtd_address, 8))[0]
    try:
        ns_address = pointer(ns_pointer - schema.nsmtd_offset)
    except SnapshotError as error:
        raise SnapshotError(f"stopped guest nsmtd pointer {ns_pointer:#x} with container offset "
                            f"{schema.nsmtd_offset:#x} differs from the four-level kernel mapping") from error
    ns_type = schema.btf.structure("nandsim")
    ns = memory(ns_address, ns_type.value)
    def ns_value(name, fmt):
        offset, _ = schema.btf.member(ns_type, name)
        return struct.unpack(fmt, span(ns, offset, struct.calcsize(fmt)))[0]
    if ns_value("cfile", "<Q") != 0:
        raise SnapshotError("cache-file-backed nandsim is not admitted")
    goff, geometry = schema.btf.member(ns_type, "geom")
    def geom(name, fmt="<I"):
        offset, _ = schema.btf.member(geometry, name)
        return struct.unpack(fmt, span(ns, goff + offset, struct.calcsize(fmt)))[0]
    values = {"bytes": geom("totsz", "<Q"), "page_size": geom("pgsz"), "oob_size": geom("oobsz"),
              "page_count": geom("pgnum"), "erase_size": geom("secsz"), "raw_page_size": geom("pgszoob")}
    if values != {"bytes": 256*1024**2, "page_size": 2048, "oob_size": 64,
                  "page_count": 131072, "erase_size": 131072, "raw_page_size": 2112}:
        raise SnapshotError("exact disposable AM2 simulator geometry differs")
    pointers = memory(pointer(ns_value("pages", "<Q")), values["page_count"] * 8)
    chip_offset, chip = schema.btf.member(ns_type, "chip")
    bbt_offset, _ = schema.btf.member(chip, "bbt")
    bbt_pointer = struct.unpack("<Q", span(ns, chip_offset + bbt_offset, 8))[0]
    bbt = memory(pointer(bbt_pointer), 512) if bbt_pointer else b""
    allocation = bytearray(values["page_count"] // 8)
    output.mkdir(mode=0o700)
    page_digest, allocated, erased = hashlib.sha256(), 0, 0
    with (output / "pages.bin").open("xb") as stream:
        for number in range(values["page_count"]):
            address = struct.unpack_from("<Q", pointers, number * 8)[0]
            if not address:
                continue
            raw = memory(pointer(address), values["raw_page_size"])
            allocation[number // 8] |= 1 << (number % 8)
            allocated += 1
            erased += raw == b"\xff" * values["raw_page_size"]
            stream.write(raw)
            page_digest.update(raw)
        stream.flush()
        os.fsync(stream.fileno())
    (output / "allocation.bin").write_bytes(allocation)
    (output / "bbt.bin").write_bytes(bbt)
    meta = {"schema": "dcentos.test-nandsim-flash.v1", "boundary": boundary, "geometry": values,
            "kernel_sha256": schema.kernel_sha256, "module_sha256": schema.module_sha256,
            "base_btf_sha256": schema.base_btf_sha256, "module_btf_sha256": schema.module_btf_sha256,
            "allocated_pages": allocated, "allocated_erased_pages": erased,
            "bad_blocks": list(bad_blocks),
            "pages_sha256": page_digest.hexdigest(), "allocation_sha256": sha(allocation), "bbt_sha256": sha(bbt)}
    # Written last: an interrupted snapshot never looks complete to replay.
    (output / "snapshot.json").write_text(json.dumps(meta, sort_keys=True) + "\n", encoding="ascii")
    return meta


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SnapshotError("duplicate snapshot metadata key")
        result[key] = value
    return result


def load_snapshot(directory: Path, *, kernel_sha256: str, module_sha256: str):
    """Authenticate the complete local test snapshot before a fresh guest writes."""
    if directory.is_symlink() or not directory.is_dir() or set(p.name for p in directory.iterdir()) != {
            "snapshot.json", "allocation.bin", "pages.bin", "bbt.bin"}:
        raise SnapshotError("complete exact snapshot directory required")
    meta = json.loads(regular(directory / "snapshot.json", 16384), object_pairs_hook=_unique)
    fields = {"schema", "boundary", "geometry", "kernel_sha256", "module_sha256", "base_btf_sha256",
              "module_btf_sha256", "allocated_pages", "allocated_erased_pages", "pages_sha256",
              "allocation_sha256", "bbt_sha256", "bad_blocks"}
    if (not isinstance(meta, dict) or set(meta) != fields or meta["schema"] != "dcentos.test-nandsim-flash.v1"
            or meta["kernel_sha256"] != kernel_sha256 or meta["module_sha256"] != module_sha256
            or any(not _digest(meta[key]) for key in fields if key.endswith("sha256"))):
        raise SnapshotError("snapshot identity/field binding differs")
    boundary = meta["boundary"]
    if (not isinstance(boundary, str) or not boundary or len(boundary) > 160
            or any(ord(character) < 32 for character in boundary)):
        raise SnapshotError("snapshot logical boundary differs")
    if meta["geometry"] != {"bytes": 256*1024**2, "page_size": 2048, "oob_size": 64,
            "page_count": 131072, "erase_size": 131072, "raw_page_size": 2112}:
        raise SnapshotError("snapshot simulator geometry differs")
    bad = meta["bad_blocks"]
    if (not isinstance(bad, list) or any(type(value) is not int or not 0 <= value < 2048 for value in bad)
            or sorted(set(bad)) != bad):
        raise SnapshotError("snapshot bad-block census differs")
    allocation = regular(directory / "allocation.bin", 16384)
    if len(allocation) != 16384 or sha(allocation) != meta["allocation_sha256"]:
        raise SnapshotError("snapshot allocation map differs")
    count = sum(value.bit_count() for value in allocation)
    if type(meta["allocated_pages"]) is not int or count != meta["allocated_pages"]:
        raise SnapshotError("snapshot allocation count differs")
    pages = regular(directory / "pages.bin", 131072 * 2112)
    if len(pages) != count * 2112 or sha(pages) != meta["pages_sha256"]:
        raise SnapshotError("snapshot raw NAND/OOB differs")
    erased = sum(pages[n:n+2112] == b"\xff"*2112 for n in range(0, len(pages), 2112))
    if type(meta["allocated_erased_pages"]) is not int or erased != meta["allocated_erased_pages"]:
        raise SnapshotError("snapshot allocated-erased count differs")
    bbt = regular(directory / "bbt.bin", 512)
    if len(bbt) not in (0, 512) or sha(bbt) != meta["bbt_sha256"]:
        raise SnapshotError("snapshot bad-block table differs")
    return meta, allocation, pages, bbt


def allocated_pages(allocation: bytes, pages: bytes):
    position = 0
    for number in range(len(allocation) * 8):
        if allocation[number // 8] & (1 << (number % 8)):
            yield number, span(pages, position, 2112)
            position += 2112
    if position != len(pages):
        raise SnapshotError("orphaned raw pages outside allocation map")
