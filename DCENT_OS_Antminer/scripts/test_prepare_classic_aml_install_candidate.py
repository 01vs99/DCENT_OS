"""Producer checks against exact held Classic loader and original BETA bundle."""
import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).with_name("prepare_classic_aml_install_candidate.py")
spec = importlib.util.spec_from_file_location("classic_candidate_producer", SCRIPT)
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


@pytest.fixture(scope="module")
def donor():
    if not (producer.ROOT / producer.DONOR).exists():
        pytest.skip("held Classic donor absent from standalone export")
    return producer.codec_and_donor()


@pytest.mark.parametrize("length", [1024, 1025, 1026, 1027, 13000001])
def test_component_resize_alignment_and_exact_unrelated_bytes(donor, length):
    codec, original = donor
    ramdisk = b"x" * length
    encoded, kernel_size = producer.compose(codec, original, ramdisk)
    decoded = producer.reader().decode_container(encoded)
    nodes, positions = producer.reader().parse_fdt(decoded[0x100000:])
    assert nodes["/images/ramdisk"]["data"] == ramdisk
    assert kernel_size == 14960648
    assert decoded[0x8000:0x100000] == original[0x8000:0x100000]
    assert producer.sha(nodes["/images/kernel"]["data"]) == producer.reader().KERNEL_SHA
    assert producer.sha(nodes["/images/fdt"]["data"]) == producer.reader().DTB_SHA


def test_reserved_memory_collision_refused(donor):
    codec, original = donor
    with pytest.raises(ValueError, match="reserved secmon"):
        producer.compose(codec, original, b"x" * producer.reader().MAX_PACKAGE)


def test_wrong_source_digest_rejected_before_preparation(tmp_path):
    path = tmp_path / "source.tar"
    path.write_bytes(b"untrusted")
    with pytest.raises(ValueError, match="SHA256"):
        producer.prepare(path, "0" * 64, tmp_path / "result.tar")
    assert not (tmp_path / "result.tar").exists()


def test_existing_candidate_preserved(tmp_path):
    path = tmp_path / "retained.tar"
    path.write_bytes(b"keep")
    with pytest.raises(ValueError, match="preserve"):
        producer.prepare(tmp_path / "absent", "0" * 64, path)
    assert path.read_bytes() == b"keep"
