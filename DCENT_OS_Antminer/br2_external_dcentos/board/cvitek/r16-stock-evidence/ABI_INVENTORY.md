# CV1835 stock kernel/device ABI inventory (R16, pinned)

L17 retirement note: this is a historical stock ABI inventory, retained with
its original pins and limitations. References below to the CV constructor,
its contract, and a built candidate describe the retired prototype. No CV
runtime or image producer exists. The current decision is in
`docs/CV1835_STATUS.md`; the stock root DTB is
`linux,dummy-virt` with no model, so the retirement guard reads exact child
compatibles instead of relying on the historical root-signature proposal.

Campaign: , lane R16 ("factory
CV1835 HAL and mining composition"), scope drop 2026-09-12.

This document is the pinned, human-readable form of the ABI inventory that
lives in
`DCENT_OS_Antminer/dcentrald/dcentrald-hal/src/platform/cvitek_stock_evidence.rs`
(`REQUIRED_ABI_INVENTORY`). A test in that module fails the build if this doc
drifts from the Rust rows (every row name and the built-candidate owner line
below are pinned by `include_str!`).

Every row is proven from held bytes only — the five stock sd2nand recovery
bundles (S19k Pro / S19 XP / S19j XP / S19 Pro / T21, SHA-256-pinned in
`projects/dcent-toolbox/src/dcent_toolbox/core/cv1835_bcb100_variant_evidence.py`)
and the held 2022-12-26 stock CVCtrl BMU extraction
. Fixtures are
byte-exact extractions in `fixtures/` (manifest:
`FIXTURES_MANIFEST.json`; extractor + log in the lane evidence dir).

**Built-candidate check owner:** Lead build slot (R16 acceptance: 'required kernel/device ABI present in built candidate' is checked against the built candidate, not at desk)

## Kernel modules (held bytes; a built candidate ships this kernel ABI)

| Module | Detail | Held proof |
|---|---|---|
| cv183x_pwm.ko | Cvitek PWM driver; alias cvitek,cvi-pwm; fan PWM out + tach capture | fixtures/cv183x_pwm.ko d3bc1599 (vermagic 4.9.38-00269-g8355fd4db SMP preempt mod_unload aarch64) |
| cv183x_base.ko | Cvitek base driver; __ioremap 0x03000000+0x10000, cvi_base misc device, chip_id/chip_version | fixtures/cv183x_base.ko be9bec65 (vermagic 4.9.38-g214084e SMP preempt mod_unload aarch64) |
| uart_trans.ko | chain UART relay chrdev + /dev/ttyS1..4 termios owner; crc_itu_t codec | fixtures/uart_trans.ko 48ebbbc3 (vermagic 4.9.38 SMP preempt mod_unload aarch64) |
| cv183x_wdt.ko | Synopsys DesignWare watchdog; alias snps,dw-wdt | fixtures/cv183x_wdt.ko f1394e57 (vermagic 4.9.38-tag- SMP preempt mod_unload aarch64) |
| configfs.ko | stock kernel infra present in mnt/system/ko | fixtures/configfs.ko 101ac45a (vermagic 4.9.38-tag- SMP preempt mod_unload aarch64) |

Kernel ABI family: **4.9.38 aarch64 SMP preempt mod_unload** — all five held
vermages. A built DCENT candidate either ships this kernel ABI or must not
load out-of-tree modules (DCENT's UIO/sysfs-first posture needs none of them
at runtime; they are listed because the stock userspace contract assumes
them).

## Device nodes

| Node | Detail | Held proof |
|---|---|---|
| /dev/ttyS0 | console UART (DTB serial@04140000, alias serial0, stdout-path, 25 MHz clock) | fdt_cv1835_miner_emmc.dtb 5b62a37d aliases+chosen |
| /dev/ttyS1 | chain 0 UART (DTB serial@04150000, alias serial1, 200 MHz clock) | uart_trans.ko literal /dev/ttyS1..4 + fdt 5b62a37d |
| /dev/ttyS2 | chain 1 UART (DTB serial@04160000, alias serial2) | uart_trans.ko literal + fdt 5b62a37d |
| /dev/ttyS3 | chain 2 UART (DTB serial@04170000, alias serial3) | uart_trans.ko literal + fdt 5b62a37d |
| /dev/ttyS4 | chain 3 UART (DTB serial@041C0000, alias serial4) | uart_trans.ko literal + fdt 5b62a37d |
| /dev/uart_trans | uart_trans.ko chrdev ('register uart_trans chrdev success'); BM1362 wire transport | fixtures/uart_trans.ko 48ebbbc3 |
| /dev/mem | busybox devmem pinmux replay path (S37/cvidaemon writes) | S37 devmem lines b09fcd17/5ef8441d + cvidaemon 8638900f |
| /dev/mmcblk0p1 | GPT kernel partition (updateporc write law) | updateporc.sh 7d71a778 blkdiscard+dd |
| /dev/mmcblk0p3 | GPT minerfs partition (updateporc write law) | updateporc.sh 7d71a778 blkdiscard+dd |
| /dev/mmcblk0p4 | GPT sig partition (updateporc write law) | updateporc.sh 7d71a778 blkdiscard+dd |
| /dev/watchdog | standard dw_wdt node (driver held as cv183x_wdt.ko; node name per snps,dw-wdt class convention — no held rootfs byte names it) | fixtures/cv183x_wdt.ko f1394e57 alias snps,dw-wdt + DTB cv-wd@0x3010000 |
| /dev/i2c-N | Designware I2C adapters (DTB i2c@04000000/04020000/04030000/04040000). NOT named in any held sd2nand byte; bus numbering (contract: bus 0 for PIC1704 0x20) comes from the dev-kit RE + L9 topol.conf corroboration — bench witness required | fdt 5b62a37d i2c nodes; no held /dev/i2c string (stop-where-bytes-end) |

## Sysfs interfaces

| Interface | Detail | Held proof |
|---|---|---|
| /sys/class/gpio/{export,unexport} | legacy GPIO sysfs (S37 exports 412/427/429/431/433/434/435/459/461) | S37 b09fcd17/5ef8441d export lines |
| /sys/class/gpio/gpioN/{direction,value} | direction=out for the exported set; value 0/1 writes per s19j_init.c convention | S37 direction lines + constructor contract |
| /sys/class/pwm/pwmchip8/pwm{0,1}/{export,period,enable,duty_cycle} | fan PWM output (period 1000000 ns; front pwm1 FAN1/3, rear pwm0 FAN2/4) | S37 pwmchip8 setup lines b09fcd17/5ef8441d |
| /sys/class/pwm/pwmchip12/pwm{0..3}/{export,period,enable} | fan tach capture channels (period 1000000 ns; capture readback is the contract's RPM path — 'capture' not named in held S37) | S37 pwmchip12 setup lines (stop-where-bytes-end for capture) |
| /proc/device-tree/model + /sys/firmware/devicetree/base/compatible | CV1835 signature detection consumed by cvitek.rs has_cv1835_signature | constructor contract (standard kernel ABI; stock DTB model/compatible held in fdt 5b62a37d) |

## Stock DTB nodes (`fdt@cv1835_miner_emmc`, byte-identical in 5/5 bundles)

| Node family | Detail | Held proof |
|---|---|---|
| serial@04140000..041C0000 (snps,dw-apb-uart) | 5 UARTs: serial0 console 25 MHz; serial1..4 chains 200 MHz; reg-shift=2 reg-io-width=4 | fdt_cv1835_miner_emmc.dtb 5b62a37d |
| pwm@03060000..03063000 (cvitek,cvi-pwm) | 4 PWM controllers, #pwm-cells=1 | fdt 5b62a37d + cv183x_pwm.ko alias cvitek,cvi-pwm |
| gpio@03020000..03023000 (snps,dw-apb-gpio) | 4 banks x 32 lines (porta..portd); sysfs base numbering is driver-assigned, S37 numbers are the held witness | fdt 5b62a37d + S37 exports |
| i2c@0400xxxx (snps,designware-i2c) | 4 I2C adapters (0x04000000/04020000/04030000/04040000) | fdt 5b62a37d |
| clock-controller@03002000 (cvitek,cv1835-clk) + reset-controller@03003000 (cvitek,reset) | clock/reset control; oscillator fixed-clock 25 MHz (0x017D7840); clk-reset-controller@03002000 | fdt 5b62a37d |
| cv-wd@0x3010000 (snps,dw-wdt) | watchdog at 0x03010000 | fdt 5b62a37d + cv183x_wdt.ko alias |
| cv-emmc@4300000 (cvitek,cv1835-emmc) + cv-sd@4310000 (cvitek,cv1835-sd) | eMMC (install target carrier) and SD controllers | fdt 5b62a37d + partition_emmc_miner.xml (shared pin 1e06d0a3) |
| pinctrl@3001000 (cvitek,pinctrl-cv1835) + top_misc_ctrl@3000000 (syscon) | pinmux block 0x03001000 (all S37 devmem writes land inside it) and top misc syscon | fdt 5b62a37d + S37 devmem b09fcd17/5ef8441d |
| thermal@030E0000 (cvitek,cv1835-thermal) | SoC thermal sensor | fdt 5b62a37d |
| cpus (2x arm,cortex-a53) + memory@0x100000000 (256 MiB) | DUAL-core A53 per the stock DTB — the constructor-contract doc's 'quad A53' wording is contradicted by the held bytes; memory 0x10000000 at 0x100000000 | fdt 5b62a37d cpus/memory nodes |

## Boot-chain components (inventory only — writes stay authority-closed)

| Component | Detail | Held proof |
|---|---|---|
| boot.emmc uImage FIT | kernel(gzip arm64) + 4 fdt images + ramdisk; configurations signed sha256,rsa2048; CIMG v1 dest LBA 8192 | 5x bundle boot.emmc (toolbox-pinned member SHAs); fdt@cv1835_miner_emmc identical 5/5 |
| fdt@cv1835_miner_emmc | the stock eMMC-miner device tree (embedded fixture) | fixtures/fdt_cv1835_miner_emmc.dtb 5b62a37d |
| ramboot.itb | bootstrap-only FIT (FDT magic d00dfed); bootstrap transport unheld (CV1835_BOOTROM_TRANSPORT unresolved) | bundle member pins (toolbox evidence module); s19kpro==t21 931307d0 |
| fip.bin | ARM Trusted Firmware + U-Boot; no self-described destination (eMMC boot partitions outside user area) — outside every write path | bundle member pins; s19pro==t21 cc2894e1 |
| gpt.img + partition_emmc_miner.xml | 7-partition topology (kernel/marker/minerfs/sig/config/miner/nvdata), 3,700,000 KiB eMMC; gpt targets LBA 0 (forbidden region) | toolbox-pinned member SHAs; I04 contract tests |

## Userspace contracts

| Contract | Detail | Held proof |
|---|---|---|
| /etc/subtype | CVCtrl_BHB42XXX (20221226 BMU + s19pro) / CVCtrl_BHB56XXX (s19kpro/s19xp/s19jxp) / CVCtrl_BHB6870X (t21); contract classifier binds BHB42XXX -> Pic1704 only | subtype fixtures 5b8d906a/3ef605ca/5a90581d |
| /etc/fw-info | JSON identity {miner, model, platform=cv, fw_version, install_type=nand} | toolbox cv1835_bcb100_variant_evidence overlay pins |
| updateporc.sh BMU law | BMU split -> openssl sha256 verify chain (/etc/bitmain[.release].pub) -> p1,p4,p3 blkdiscard+dd -> sleep 3 -> sync; no backup, no readback, no env seam | fixtures/updateporc.sh 7d71a778 (identical 20221226 + 5/5 bundles) |
| cvidaemon clock-gate unlock | devmem 0x03005D00 32 0x4D474E35 ('5NGM') + dynamic 0x03005D04 template write | fixtures/cvidaemon.bin 8638900f (identical 5/5) |
| S37bitmainer_setup + S70cgminer | pinmux/GPIO/PWM init + lsmod-guarded module loads (two S37 builds: b09fcd17, 5ef8441d; one S70 build: 617dbd58) | fixtures/s37_*.sh, fixtures/s70_cgminer_variant_617dbd58.sh |
| busybox devmem + aarch64 userspace | pinmux replay executor; /lib/ld-linux-aarch64.so.1 loader | updateporc/cvidaemon string census |
| kernel 4.9.38 aarch64 ABI family | all five held module vermages are 4.9.38 variants (SMP preempt mod_unload aarch64); a built candidate's kernel must be this ABI or the out-of-tree modules must stay absent | module fixture vermagic strings |

## Stop-where-bytes-end (evidence-blocked, not desk-closable)

1. **Chain-UART mmap base.** The accepted contract's cold-boot UART shuttle
   is documented at the W10.3 dev-kit base `0x0500_D000 + 0x1000*chain`. The
   held stock DTB declares the chain UARTs as kernel `snps,dw-apb-uart` nodes
   at `0x04150000/0x04160000/0x04170000/0x041C0000` and no held byte declares
   `0x0500_D000`. Any mmap-based chain-UART executor must treat that base as
   undefined; the stock-defined access path is the kernel ttyS nodes (and
   `/dev/uart_trans` for the BM1362 wire transport).
2. **Phase-6 "FPGA" registers (0x43C0xxxx).** Contradicted — CV1835 has no
   FPGA; no held byte defines those addresses ( Q6 + full-rootfs
   search). Refused by the executor adapter.
3. **Chain bauds beyond 115200 / 937500.** No held CV byte defines any
   fast-UART mode for this platform.
4. **PWM period/duty.** The stock law is exactly 1_000_000 ns period on
   pwmchip8/0+1 and pwmchip12/0..3; the tach `capture` readback file is the
   contract's RPM path but is not named in any held S37 build.
5. **I²C bus numbering.** `/dev/i2c-N` never appears in held sd2nand bytes;
   the contract's bus 0 for PIC1704 0x20 rests on the dev-kit RE + the L9
   topol.conf corroboration. Bench witness required.
6. **Chip-id register offset (0x8C) and SoC-version magic (0x18802001).** The
   held cv183x_base.ko proves the `cvi_base_read_chip_id`/`_chip_version`
   functions and the misc registration; the numeric constants remain
   RE-sourced (R4-1 carry-forward, bench probe required).
7. **CV1835 BootROM/USB bootstrap transport.** `ramboot.itb`'s host binding
   and `cvi_burn` stay unheld (`CV1835_BOOTROM_TRANSPORT` unresolved).
8. **Subtype families BHB56XXX / BHB6870X.** Held (s19kpro/s19xp/s19jxp and
   t21 rootfs) but unbound by the accepted constructor-contract classifier
   (only `CVCtrl_BHB42XXX` -> Pic1704). No controller profile may be
   inherited across families without new evidence.
9. **All storage writes.** updateporc.sh defines the p1->p4->p3
   blkdiscard+dd law but grants no authority; the only DCENT write path is
   I04's authority-gated EvidenceOnly transaction (matrix row denied).

## Built-candidate check (acceptance clause 2 remainder)

Owner: **Lead build slot**. The desk inventory above is what the built
candidate must satisfy; the actual check runs against the built candidate's
kernel config/DTB/rootfs in the Lead's build slot. This document and the Rust
inventory are the pinned reference for that check.
