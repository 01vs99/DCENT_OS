# Installing DCENT_OS beta

Start with the [one-page quickstart](../BETA_QUICKSTART.md). Obtain the signed beta package and DCENT_Toolbox supplied for your exact model and control board. Beta packages are for testing; no model is described here as production-stable. You do not need to compile firmware to try a supplied package.

## Pick your family

- [S9 and S9 variants with Xilinx/Zynq controllers](S9_XILINX.md)
- [S15/T15, S17/T17 and S19 native Zynq SD trials](AM2_NATIVE.md)
- [S19j Pro with a Xilinx/Zynq controller](S19J_PRO_XILINX.md)
- [S19j Pro with a BeagleBone controller](BEAGLEBONE.md)
- [S19 and S21 families with Amlogic controllers](AMLOGIC.md)

CVitek, S11, S23, T21 and other models outside the supplied release roster need a separate supported package and procedure. Discovery of a device is not an install method. Do not select a similarly named package when the exact model or controller is missing.

## Preview with Toolbox

Launch `dcent tui` for the Toolbox interface, select one miner, and open Install. Choose the signed package and review the proposed method. For a firmware route that requests the Firmware field, the command-line preview is below; replace MINER_IP and SIGNED_PACKAGE with your own address and file path. An AM2 first-install capsule uses the separate example in the [S19j Pro guide](S19J_PRO_XILINX.md).

```text
dcent doctor MINER_IP
dcent install --list-routes --explain MINER_IP
dcent install MINER_IP -f SIGNED_PACKAGE --dry-run
```

The doctor and route-explanation commands contact the selected miner to identify it. The firmware preview can also probe it; the dedicated AM2 capsule preview checks local inputs only. None of these previews performs the install. Resolve the reported prerequisites before proceeding. For a persistent write, keep the automatic full backup, readback result and required restore preparation off the device. Then approve the exact action in Toolbox. For the firmware route just previewed, the CLI execution form is:

```text
dcent install MINER_IP -f SIGNED_PACKAGE --yes
```

This command can write internal storage. Use it only for the route you just reviewed; SD preparation has its own card-selection step. Do not add bypass flags to overcome an identity, signature, recovery or safety refusal.

## Understand completion

An accepted upload, a verified storage write, a successful reboot and accepted pool shares are separate milestones. Follow the route's final message. If it requests a power-cycle, first wait until the write has finished. Do not assume every stock firmware will reboot automatically.

## Recovery and updates

Keep the original firmware and board-specific recovery media. Failed-boot recovery depends on the controller and install method; automatic rollback is not universal. SD trials run from the card. A DCENT_OS self-update package does not automatically provide a first-install route from stock firmware. Use the signed update selected for the running board, then verify the displayed version and complete the [first-start checks](../BETA_QUICKSTART.md).
