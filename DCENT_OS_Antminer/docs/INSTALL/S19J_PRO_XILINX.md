# S19j Pro with a Xilinx/Zynq controller

Confirm the exact S19j Pro model and Xilinx/Zynq controller in Toolbox. The running board target is `am2-s19j`. The BeagleBone, Amlogic and CVitek S19j Pro controllers require different packages and procedures.

## Existing DCENT_OS installation

The signed `am2-s19jpro` sysupgrade package supports a DCENT_OS self-update. Select it in Toolbox or the dashboard update flow. Verify the selected version and target, keep the required backup and recovery preparation, and wait for the write and readback to finish.

## First install from another firmware

Use Toolbox's controller- and source-firmware-specific first-install route. A self-update tar alone does not provide the boot files, recovery preparation or stock-firmware installer needed for first install. Preview the route and use its supplied install capsule when requested. If the required route or package is absent, leave the existing firmware installed and retain the refusal reason for support.

The Install form has a separate **First install capsule** field. Provide the retained full backup directory for this exact unit, recovery image, installation configuration and pinned SSH host keys. Use the backup procedure reported for the detected source firmware; a settings-only backup is insufficient. The equivalent local preview is:

```text
dcent install MINER_IP --first-install-capsule CAPSULE.tar --artifact-dir UNIT_BACKUP --recovery-image RECOVERY.img --install-config dcentrald.toml --known-hosts known_hosts --dry-run
```

Replace every placeholder with the supplied files or your retained unit backup. This preview verifies the capsule and local backup without contacting the miner. If it succeeds, rerun the same command with `--yes` in place of `--dry-run` to authorize that transaction. Keep its session file: an interrupted transaction must use the reported resume procedure, not a fresh install command. Stock eight-partition recovery transition and dual-slot install have different completion messages; neither automatically reboots the miner.

## Reboot and first start

Some AM2 routes finish with an accepted upload or a verified inactive-slot write and request a power-cycle. Follow that message after the write has completed. An accepted upload is not proof that DCENT_OS booted. Check the dashboard version, complete the [quickstart](../BETA_QUICKSTART.md), and press Start only after reviewing board, fan and temperature status. Damaged or mismatched EEPROM/PIC identities remain refused.

## Recovery

Keep the full backup and the route's board-specific recovery media off the miner. Automatic failed-boot rollback is not guaranteed. Use the saved recovery procedure if the new slot does not boot; do not improvise raw U-Boot environment writes or use a sibling model's SD image.

## Heater requests

The 600, 900 and 1200 W S19j presets are requested targets. The current hybrid runtime does not have a watt-control owner with admitted power inputs, so it saves these requests without claiming to apply them. The dashboard reports that limitation. These values are not measured wall power, a thermostat, or guaranteed heat output.
