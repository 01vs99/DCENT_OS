#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-only
"""Read the held VNish model generator's voltage constants without hardware.

Linux/root, qemu-arm-static and unshare are required. The generator runs in a
temporary chroot with an empty device tree and an isolated network namespace.
Only its model-generation flags are used. No vendor miner daemon is executed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

MODELS = ('s19jpro-a', 's19jpro-plus')


def extract(held: Path, model: str) -> dict:
    if model not in MODELS:
        raise ValueError('exact A/Plus vendor model required')
    source = held / 'extractions/vnish-farm' / model / 'vnishfarm-1.2.6-rc5-aml-nand-install/rootfs'
    raw = (source / 'usr/bin/hwscan').read_bytes()
    if raw[:6] != b'\x7fELF\x01\x01' or raw[18:20] != b'\x28\x00':
        raise ValueError('held ARM32 model generator required')
    with tempfile.TemporaryDirectory(prefix='dcent-voltage-') as directory:
        root = Path(directory)
        shutil.copyfile('/usr/bin/qemu-arm-static', root / 'qemu')
        (root / 'qemu').chmod(0o700)
        (root / 'hwscan').write_bytes(raw)
        (root / 'hwscan').chmod(0o700)
        for name in ('var/run/hwscan', 'etc/factory', 'etc/zlog', 'tmp', 'var/log'):
            (root / name).mkdir(parents=True, exist_ok=True)
        (root / 'etc/zlog/hwscan.conf').write_bytes((source / 'etc/zlog/hwscan.conf').read_bytes())
        run = subprocess.run(['unshare', '--net', 'chroot', str(root), '/qemu', '/hwscan',
                              '--platform', 'aml', '--gen-model-info', model, '--gen-def-conf', model],
                             capture_output=True, timeout=30)
        if run.returncode:
            raise ValueError(f'isolated generator failed ({run.returncode}): {run.stderr[-1000:]!r}')
        info = json.loads((root / 'var/run/hwscan/miner-model.json').read_bytes())
        default = json.loads((root / 'etc/factory/cgminer.conf').read_bytes())
    if info['model'] != model or info['chip']['model'] != 'BM1362':
        raise ValueError('generated model identity differs')
    performance = info['performance']
    return {
        'model': model, 'board': info['btm_model'], 'chips': info['chain']['num_chips'],
        'per_chain_voltage_control': info['chain']['volt_ctrl'],
        'default_mv': performance['default_volt'], 'startup_mv': performance['startup_volt'],
        'default_mhz': performance['default_freq'], 'startup_mhz': performance['startup_freq'],
        'minimum_mv': info['psu']['min_volt'], 'maximum_mv': info['psu']['max_volt'],
        'factory_config_voltage': default['bitmain-voltage'],
        'presets_at_12800mv_mhz': [row['freq'] for row in performance['presets']
                                  if row['initial_volt'] == 12800],
    }


def require_exact_board(profile: dict, board: str, chips: int, per_chain_voltage_control: bool):
    """A vendor model label alone cannot supply another board's voltage law."""
    if (profile['board'], profile['chips'], profile['per_chain_voltage_control']) != (
            board, chips, per_chain_voltage_control):
        raise ValueError('vendor voltage profile does not describe this exact board/controller')
    return profile['default_mv'], profile['startup_mv']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--held-assets', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps([extract(args.held_assets, model) for model in MODELS], indent=2))


if __name__ == '__main__':
    main()
