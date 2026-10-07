# S9 family with a Xilinx/Zynq controller

Confirm the exact variant before choosing a package. The base S9 and the S9i, S9j, S9 SE and S9k have distinct release targets. Do not rename a sibling image to make it match.

## Base S9

The base S9 signed sysupgrade package has a Toolbox first-install route as well as a DCENT_OS self-update route. Preview the source-firmware-specific method, retain the full backup and recovery preparation, and approve the exact write in [Toolbox](README.md). An existing base-S9 SD boot kit is a separate artifact; a sysupgrade tar is not a raw card image.

## S9i, S9j, S9 SE and S9k

Use the exact signed native SD image supplied for your variant. Prepare the removable card with Toolbox's SD flow, verify the write, eject it, and power off before inserting it. Follow the supplied controller-specific SD boot selection instructions. These are card-resident trials; keep the card inserted while using DCENT_OS. They do not install into NAND.

## First start and recovery

Wait for the miner's address to appear on your router, open its dashboard and follow the [quickstart](../BETA_QUICKSTART.md). Mining starts off. For a card trial, complete Stop, power off, remove the card and restore the original boot selection to return to internal firmware. For a persistent install, use your saved full backup and the controller-specific recovery instructions if boot fails.
