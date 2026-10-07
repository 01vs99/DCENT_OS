# Braiins OS / OS+ 20260915 ssh-tarball policy census

```
PROVENANCE HEADER
source corpus     :  (5 ssh tarballs)
capture date      : acquired 2026-09-15; extracted (read-only copies) 2026-10-05
labels            : [BRAIINS-OS-GPL]      = Braiins Open-Source Initiative (BOSI) base, GPLv3+ scripts
                    [BRAIINS-OS+-proprietary] = bosminer/boser/plus-tuner binaries (UPX-packed) —
                    strings/layout facts only, NO code copying (GPL-quarantine fold, plan.md §11 C2)
oracle class      : ORACLE-CLASS ONLY (plan.md §11 C2-F2). Competitor policy = emulation-twin
                    oracles + sanity bounds, NEVER shipped DCENT_OS defaults.
extract method    : tar -> uImage(64B hdr) -> gzip -> cpio(newc) member walk; strings via regex over
                    member bytes; no disassembly, no mounting, originals untouched.
caveats           :
  - ssh packages carry the FIRST-STAGE initramfs; the system partition (squashfs on NAND) with the
    full /etc (bosminer.toml templates, updater/feeds config) is NOT in these tarballs. Feeds URLs
    are separately held (acquisition-20260913 Braiins feeds URL list; ).
  - am1-s9 (22.08.1) and am2-s17 (23.10.1) sysupgrade root filesystem is squashfs ("hsqs") — not
    unpacked here (desk tool limit); their facts below are from tarball-level scripts only.
  - cvitek-bm1-am2 rootfs payload uses a non-cpio container (magic 1a 85 38 02) — not unpacked;
    install-level facts only.
  - bosminer/boser in 26.08.1 are UPX-packed: config-schema strings not directly greppable.
    Tuner-behavior facts remain those of the held unpacked 0.9.0 binaries
    (extractions/s19k/live-probe-78-2026-04-29 + research/ecosystem/BOSMINER_AUTOTUNER_RE.md).
fund link         : https://d-central.tech/fund/
```

## 1. Inventory (5 platforms)

| Platform | Tarball | Version string | Rootfs access | Tuner binary |
|---|---|---|---|---|
| am3-aml | braiins-os_am3-aml_ssh_2026-08-20-0-33fea20e-26.08.1-plus.tar.gz | 2026-08-20-0-33fea20e-26.08.1-plus | uImage→gzip→cpio (1167 members) | /usr/bin/bosminer 10,819,664 B (UPX) + /usr/bin/boser 7,686,984 B (UPX) |
| am3-bbb | braiins-os_am3-bbb_ssh_2026-08-20-0-33fea20e-26.08.1-plus.tar.gz | same build 33fea20e | cpio, Nix-store layout | nix/store/...-bosminer-plus-tuner-armv7l-unknown-linux-musleabihf-**0.9.0**-with-version-upx/bin/bosminer-plus-tuner (identical 10,819,664 B) |
| cvitek-bm1-am2 | braiins-os_cvitek-bm1-am2_ssh_2026-08-20-0-33fea20e-26.08.1-plus.tar.gz | same build 33fea20e | container magic 1a853802 (not unpacked) | not reached |
| am1-s9 | braiins-os_am1-s9_ssh_2022-09-27-0-26ba61b9-22.08.1-plus.tar.gz | 22.08.1 (2022-09-27-0-26ba61b9) | tarball scripts + fit.itb/stage2.tgz/sysupgrade (squashfs inside, not unpacked) | in squashfs |
| am2-s17 | braiins-os_am2-s17_ssh_2023-11-20-0-b982cd98-23.10.1-plus.tar.gz | 23.10.1 (2023-11-20-0-b982cd98) | same as am1-s9 | in squashfs |

`www/boser/build_info.json` (am3-aml): `{"head": "33fea20ee4982531", "date": "2026-08-20_15:39:09"}`.

Key fact [BRAIINS-OS+-proprietary]: **the 26.08.1 plus stack still ships tuner family 0.9.0** (BBB
Nix path pins `bosminer-plus-tuner-...-0.9.0-with-version-upx`) — same family as the held live-probe
binaries (0.9.0-3881c51d, 2026-04-29). Our RE doc remains current.

## 2. Boot / process policy [BRAIINS-OS-GPL]

- `etc/init.d/S97bosminer-detect`: on `am3-*` and `cvitek-bm1-am2`, runs `bosminer model --detect`
  to write `/etc/bosminer_model` (hashchain model detection at boot).
- `etc/init.d/S98boser`: starts `boser` via `bos-tools run-and-watch`; **waits up to 30 s for
  boser to generate `/etc/bosminer.toml`** on first boot (from the post-install dir). boser owns
  bosminer.toml creation — config-template authority is in the proprietary boser, not a shipped
  template file in this image.
- `etc/init.d/S99bosminer`: starts bosminer via `bos-tools run-and-watch --oom-score-adj -1000` —
  OOM-shield policy for the miner process.
- `etc/init.d/S46post-install` (NAND mode): post-install tar is read from a BOS env MTD partition
  at a fixed offset, extracted to /tmp, executed once, then the length field is erased. Custom
  per-install scripting channel.
- `etc/init.d/S39set-environment`: device hwid = `md5("bitmain-serial-{serial}-mac-{mac}")` →
  12-byte base64 (with `+`/`/` mapped to `a`/`b`) → `/etc/miner_hwid`; survives reinstall
  (privacy-relevant identity scheme; DCENT_OS alternative: explicit consent-based ID).
- `usr/bin/factory_config_reset.sh`: factory reset stops bosminer/boser/dropbear, wipes /etc
  except `miner_hwid`; `--wipe-network` also clears stock network.conf. Reboots immediately.
- `etc/bos_mode` = `nand`; `etc/bos_platform`/`bos_build` = `am3-aml`;
  `etc/bos_version` = `2026-08-20-0-33fea20e-26.08.1-plus`; `etc/bos_major` pins
  `2022-09-13-0-11012d53-22.08-plus` (platform major lineage).

## 3. Board / fan / thermal-adjacent GPIO policy [BRAIINS-OS-GPL] (am3-aml S37board_setup)

- **PSU_nEN GPIO 437** exported `high` at boot (plus 476/477 I2C pinmux rescue exports) — matches
  D-Central live findings on Amlogic Bitmain boards (BOS-3528 comments).
- Chain plug detect: 439/440/441 (pull-down); chain reset: 454/455/456 (out).
- Recovery 446 / IP-button 445 (rising edge).
- LEDs: green 453, red 438.
- **Fan tach**: 447/448 (front), 449/450 (rear), falling-edge IRQs.
- **Fan PWM**: pwmchip0 channels 0 (rear FAN2/FAN4) and 1 (front FAN1/FAN3), period 100000 ns
  (10 kHz), **boot duty = 100000 ns = 100%** — boot-safe full-speed default, same philosophy as
  VNish 1.2.7 (`fan_ctrl.c` boot-to-100%) and Bitmain stock.

## 4. Tuner / config surface [BRAIINS-OS+-proprietary]

- 26.08.1 bosminer/boser are **UPX-packed** (supply-chain observation: packed Rust binaries in a
  signed-ish distribution; strings of the compressed image are not auditable without unpacking —
  contrast with DCENT_OS reproducible builds).
- Config schema / tuner behavior: not string-extractable here (packed). Authoritative held sources
  stay: `extractions/s19k/live-probe-78-2026-04-29/04-binaries/{bosminer,boser}.unpacked`
  (tuner 0.9.0: stage machine Bootstrap→S2→S3→S8→S10→S13, GDTUNER per-chip V/f fit, DPS
  power-target walk, pause taxonomy incl. SupervisorTemperatureHalfwayToDangerous) and
  `extractions/s9/{braiins_bm1387.rs,braiins_fan.rs,bosminer-template.toml}` [BRAIINS-OS-GPL]
  for the open S9 driver + fan policy + TOML template.
- BBB platform detail: rootfs is a **Nix store** build — Braiins ships reproducibly-built artifacts
  on at least one platform (interesting trust-posture contrast: reproducible base, packed
  proprietary tuner on top).

## 5. Feeds / update URLs

- No feeds URLs in the ssh-package initramfs or tarball scripts (checked install.sh, run.sh,
  common.sh, nand_env, CONTROL, stage1.sh, uboot_env.config, JSON.awk across all 5 tarballs; only
  gnu.org/github.com license/tooling links).
- Held separately: acquisition-20260913 catalog includes the Braiins feeds URL list;
  `repos/bos-build`, `repos/braiins-open`, `repos/bos-plus-api` hold the feeds/package layout.

## 6. Older-generation layout facts (am1-s9 22.08.1, am2-s17 23.10.1) [BRAIINS-OS-GPL]

- Package = topdir/firmware/{CONTROL, stage1.sh, stage2.tgz, fit.itb, boot.bin, u-boot.img,
  system.bit.gz, uboot_env.bin/.config, JSON.awk, jq.awk}.
- am1-s9 carries `system.bit.gz` — the **S9 FPGA bitstream** (BM1387 chain bridge), consistent
  with the am1-s9 FPGA-UIO-FIFO architecture recorded as a permanent twin gap (C1-F2).
- stage2.tgz contains sysupgrade.tar.gz → sysupgrade-{platform}/{root,spl,uboot,uenv,fpga,kernel,CONTROL,COMMAND};
  `root` is squashfs ("hsqs").
- miner_cfg.config (plain text, am1-s9) + miner_cfg.bin: stock-config migration inputs.

## 7. Emulation-twin consumption notes

- Use §3 GPIO/PWM/tach map as the am3-aml board-facility oracle for twin DTB/GPIO modeling.
- Use §2 process/facility behavior (boser-owns-bosminer.toml, model --detect, OOM shield) as
  behavioral oracles for parity tests — reimplementation only.
- The 0.9.0-still-current fact (§1) keeps the existing BOSMINER_AUTOTUNER_RE.md stage/GDTUNER/DPS
  contracts valid for 26.08.1-era parity targets.
- Nothing here may enter DCENT_OS defaults (C2-F2); GPL base code may only be adopted with
  GPL-3.0 obligations (our firmware is GPL-3.0 — compatible).
