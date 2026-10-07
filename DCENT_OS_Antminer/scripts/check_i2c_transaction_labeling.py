#!/usr/bin/env python3
"""Reject unlabeled compatibility calls without confusing private owner methods.

The compatibility API remains allowed only in its defining HAL i2c.rs. Three
concrete owners have unrelated private methods also named transaction. Permit
only self calls inside those exact impls while their own private method exists;
continue scanning every other call in those same files. This is a source-shape
boundary, not a Rust typecheck or validation of the owners' hardware behavior.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import re

from check_no_orphan_power_backends import (
    in_spans,
    mask_rust,
    match_brace_span,
)

HAL = "dcentrald/dcentrald-hal/src/"
OWNERS = {
    HAL + "platform/am2_bm1398.rs": "Nbp1901PicService",
    HAL + "platform/amlogic/s21_psu.rs": "GpioWire",
    HAL + "platform/stock_bm1391_pic.rs": "PicApplication",
}
TEST_CHILD = HAL + "platform/stock_bm1391_pic_tests.rs"
TEST_PARENT = HAL + "platform/stock_bm1391_pic.rs"
TEST_REGISTRATION = '#[cfg(test)]\n#[path = "stock_bm1391_pic_tests.rs"]\nmod tests;'
CALL = re.compile(r"\.\s*transaction\s*\(")
IMPL_HEADERS = {
    "Nbp1901PicService": r"\bimpl\s+Nbp1901PicService\s*\{",
    "GpioWire": r"\bimpl\s+GpioWire\s*\{",
    "PicApplication": r"\bimpl\s*<\s*R\s*:\s*Registers\s*>\s*PicApplication\s*<\s*R\s*>\s*\{",
}


def private_test_child(sources: dict[str, str]) -> bool:
    parent = sources.get(TEST_PARENT, "")
    masked = mask_rust(parent)
    expected = mask_rust(TEST_REGISTRATION)
    return any(masked[m.start():m.end()] == expected
               for m in re.finditer(re.escape(TEST_REGISTRATION), parent))


def violations(sources: dict[str, str]) -> list[str]:
    failures = []
    for path, text in sorted(sources.items()):
        if path == HAL + "i2c.rs":
            continue
        if not CALL.search(text):
            continue
        if path == TEST_CHILD and private_test_child(sources):
            # This exact private child is absent from production compilation.
            continue
        masked = mask_rust(text)
        spans = []
        owner = OWNERS.get(path)
        if owner:
            inherent = [(m.start(), match_brace_span(masked, m.end() - 1))
                        for m in re.finditer(IMPL_HEADERS[owner], masked)]
            private = re.compile(r"(?m)^\s{4}(?:async\s+)?fn\s+transaction(?:<[^\n]+>)?\s*\(")
            def has_own_method(a: int, b: int) -> bool:
                opening = masked.index("{", a)
                return any(masked[opening:a + m.start()].count("{") -
                           masked[opening:a + m.start()].count("}") == 1
                           for m in private.finditer(masked[a:b]))
            if any(has_own_method(a, b) for a, b in inherent):
                spans.extend(inherent)
                if owner == "GpioWire":
                    for match in re.finditer(r"\bimpl\s+PsuWire\s+for\s+GpioWire\s*\{", masked):
                        spans.append((match.start(), match_brace_span(masked, match.end() - 1)))
        for match in CALL.finditer(masked):
            # A field/alias call (owner.i2c.transaction) can never use this
            # exception, even inside an inspected owner implementation.
            receiver = re.search(r"(?<![\w.])self\s*$", masked[:match.start()])
            if receiver and in_spans(match.start(), spans):
                continue
            line = text.count("\n", 0, match.start()) + 1
            failures.append(f"{path}:{line}: transaction call lacks typed/audit admission")
    return failures


def self_test(sources: dict[str, str]) -> None:
    assert not violations(sources), "current source must pass before controls"
    path = HAL + "platform/am2_bm1398.rs"
    original = sources[path]
    controls = {
        "raw-field-in-known-owner": (path, original.replace(
            "self.transaction(chain, label, steps, terminal_disable)",
            "self.i2c.transaction(chain, steps)", 1)),
        "no-private-owner-method": (path, original.replace(
            "async fn transaction(", "async fn renamed_transaction(", 1)),
        "foreign-impl-in-known-file": (path, original +
            "\nimpl I2cServiceHandle { fn bad(&self) { self.transaction(0, vec![]); } }\n"),
        "unknown-module": (HAL + "unreviewed.rs",
            "fn bad(bus: &I2cServiceHandle) { bus.transaction(0, vec![]); }"),
        "multiline-unknown-module": (HAL + "unreviewed.rs",
            "fn bad(bus: &I2cServiceHandle) { bus\n . transaction\n (0, vec![]); }"),
        "child-lost-test-only-registration": (TEST_PARENT,
            sources[TEST_PARENT].replace(TEST_REGISTRATION,
                '#[path = "stock_bm1391_pic_tests.rs"]\nmod tests;', 1)),
        "comment-cannot-supply-test-registration": (TEST_PARENT,
            sources[TEST_PARENT].replace(TEST_REGISTRATION,
                "/*" + TEST_REGISTRATION + "*/\n" +
                '#[path = "stock_bm1391_pic_tests.rs"]\nmod tests;', 1)),
        "foreign-generic-impl-in-known-file": (path, original +
            "\nimpl Foreign<Nbp1901PicService> { fn bad(&self) { self.transaction(0, vec![]); } }\n"),
    }
    for name, (changed_path, changed) in controls.items():
        assert changed != sources.get(changed_path), name
        candidate = dict(sources)
        candidate[changed_path] = changed
        assert violations(candidate), name
        print(f"PASS negative control: {name}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    roots = [args.project_root / "dcentrald" / crate / "src"
             for crate in ("dcentrald-hal", "dcentrald-asic", "dcentrald")]
    assert all(path.is_dir() for path in roots), "complete three-crate source roots required"
    sources = {path.relative_to(args.project_root).as_posix(): path.read_text(encoding="utf-8")
               for root in roots for path in root.rglob("*.rs")}
    errors = violations(sources)
    for error in errors:
        print(error)
    if errors:
        return 1
    if args.self_test:
        self_test(sources)
    print(f"PASS I2C transaction labeling: {len(sources)} source files, zero unadmitted calls")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
