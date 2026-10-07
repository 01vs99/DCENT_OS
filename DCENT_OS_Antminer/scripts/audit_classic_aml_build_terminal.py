#!/usr/bin/env python3
"""Classify one retained Classic AML make log for private preparation eligibility."""
import argparse
import hashlib
import json
from pathlib import Path
import re

SCHEMA = 'dcentos.classic_aml_build_terminal.v1'
PACKAGE_REFUSAL = 'ERROR: unsigned package generation requires explicit lab override DCENT_ALLOW_UNSIGNED_SYSUPGRADE=1'
MARKERS = (
    '=== DCENTos Post-Image Builder (am3-s19jpro-aml) ===',
    'Rootfs audit: access services present; telnet paths absent',
    'uImage:  uImage_rootfs.bin (',
    'Rootfs window: ',
    'Kernel:  kernel (',
)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def classify(make_exit, text):
    text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', text)
    position = 0
    for marker in MARKERS:
        found = text.find(marker, position)
        if found < 0:
            raise ValueError('this attempt did not complete required post-image stage: ' + marker)
        position = found + len(marker)
    tail = text[position:]
    if make_exit == 0 and 'Sysupgrade tarball:' in tail:
        return 'completed_standard_make', None
    if make_exit == 2 and tail.count(PACKAGE_REFUSAL) == 1:
        final = tail.split(PACKAGE_REFUSAL, 1)[1]
        lines = [line.strip() for line in final.splitlines() if line.strip()]
        if lines and all(re.fullmatch(r'make(?:\[\d+\])?: (?:\*\*\* \[[^\n]*target-post-image\] Error 1|Leaving directory .+)', line)
                         for line in lines):
            return 'final_unsigned_package_gate_refusal', PACKAGE_REFUSAL
    raise ValueError('make did not end at an eligible completed/package-refusal stage')


def audit(build_path, output):
    if output.exists():
        raise ValueError('preserve existing terminal audit')
    build = json.loads(build_path.read_text(encoding='utf-8'))
    if (build.get('step') != 'build' or build.get('sources_unchanged') is not True
            or build.get('validation_error') is not None
            or build.get('resolved_aarch64') is not True or build.get('resolved_root_locked') is not True):
        raise ValueError('build source/configuration admission failed')
    log = Path(build['log'])
    if not log.is_file() or log.is_symlink() or log.stat().st_size > 128 * 1024 * 1024:
        raise ValueError('build log must be bounded and regular')
    raw = log.read_bytes()
    payload = dict(schema=SCHEMA, build_receipt_sha256=digest(build_path),
                   log=str(log), log_sha256=hashlib.sha256(raw).hexdigest(), log_bytes=len(raw),
                   make_exit_code=build['make_exit_code'], auditor_sha256=digest(Path(__file__)),
                   eligible_for_private_preparation=False, hardware_contact=False, publication=False)
    try:
        stage, reason = classify(build['make_exit_code'], raw.decode('utf-8', errors='replace'))
        payload.update(terminal_stage=stage, reason=reason, eligible_for_private_preparation=True)
    except ValueError as error:
        payload.update(terminal_stage='ineligible_failure', reason=str(error))
    output.write_text(json.dumps(payload, indent=2) + '\n', encoding='utf-8')
    return payload


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--build-receipt', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    result = audit(args.build_receipt, args.output)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['eligible_for_private_preparation'] else 1)
