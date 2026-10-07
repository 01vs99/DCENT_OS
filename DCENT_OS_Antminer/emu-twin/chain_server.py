"""BM1362 hashboard-chain emulator server: a chain of simulated chips behind
a TCP port that REALLY mines.

One `ChainServer` == one chain (one hashboard) on one TCP port.  It speaks
the BM13xx serial wire protocol (`protocol.py`, byte-true mirror of
`dcentrald-asic/src/protocol.rs` + the BM1362 builders), hosts N simulated
chips, registers per-chip addresses through the real admission flow
(ChainInactive -> SetAddress ladder -> GetAddress roster), accepts 88-byte
job frames, runs a REAL double-SHA256 nonce search (`nonce_engine.py`) for a
configurable subset of searching chips, and emits 11-byte BM1362 nonce
responses whose nonces genuinely meet the configured share target.

Per-chip state:
  - address (None until the SetAddress ladder assigns it; stride 2)
  - register file (ChipAddress, PLL0/1/3, TicketMask, MiscCtrl, FastUART...)
  - frequency (decoded from PLL0 writes via the BM1362 divider formula)
  - voltage-domain rail (board-level, set via set_rail / SETCONFIG hooks)
  - temperature (physics-driven: `physics.BoardThermalModel`)
  - silicon bin -> sigmoid HW-error cliff; when a chip is operating past its
    cliff, its returned nonces are corrupted with probability = error_rate
    (feeding daemon-side HW-error trackers/autotuner supervisors).

Safety invariants (G-spirit, enforced structurally):
  - The server ONLY opens listening TCP sockets on localhost (or a caller
    given host).  There is no code path that opens a device file: every
    filesystem-touching helper goes through `_guard_path()`, which refuses
    anything under /dev/ (POSIX) or a Windows device namespace.
  - No live hardware, no SSH, no non-localhost default binds.

Tier honesty: T1 sim / T2 twin evidence only; model outputs, not silicon
truth.  Reported hashrate/temperature/power are physics-model outputs — the
Python nonce-search rate is NOT a hashrate measurement.

Run (stdlib only, Python 3.9+):
    py -3 chain_server.py --chips 8 --port 40260 --difficulty 0.001

License: GPL-3.0 (DCENT_OS emu-twin).
Fund: https://d-central.tech/fund/
"""

from __future__ import annotations

import argparse
import random
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, TextIO, Tuple

import nonce_engine
import physics
import protocol as wire

# ---------------------------------------------------------------------------
# G-spirit device-path guard: no code path may open a real device
# ---------------------------------------------------------------------------

_FORBIDDEN_PATH_PREFIXES = ("/dev/", "\\\\.\\", "\\\\?\\")  # POSIX + Win32 devices


def _guard_path(path: str) -> str:
    """Refuse any path that names a device special file (G-invariant).

    Every filesystem path this module opens (the optional status log) goes
    through here first.  The chain wire itself is TCP-only.
    """
    normalized = path.replace("\\", "/").lower()
    for prefix in _FORBIDDEN_PATH_PREFIXES:
        if normalized.startswith(prefix.replace("\\", "/").lower()):
            raise PermissionError(
                f"emu-twin chain server never touches real devices: {path!r}"
            )
    return path


def open_status_log(path: Optional[str]) -> Optional[TextIO]:
    """Open (through the device guard) an append-mode status log; None when
    no log was requested."""
    if path is None:
        return None
    return open(_guard_path(path), "a", encoding="utf-8")


# ---------------------------------------------------------------------------
# Simulated chip
# ---------------------------------------------------------------------------


@dataclass
class SimChip:
    """One simulated BM1362 chip on the chain."""

    index: int                       # physical position on the board
    address: Optional[int] = None    # None until the SetAddress ladder
    bin_spec: physics.ChipBin = field(
        default_factory=lambda: physics.ChipBin(
            label="default", k_per_mhz=0.8, f_cliff25_mhz=560.0,
            derate_mhz_per_c=0.5, source="[DCENT-MODEL]",
        )
    )
    searching_core: bool = True      # whether this chip runs the real search
    registers: Dict[int, int] = field(default_factory=dict)
    hw_errors_injected: int = 0
    shares_found: int = 0

    def __post_init__(self) -> None:
        # POR register defaults (drivers/bm1362.rs: MiscCtrl POR = 0x00000001)
        self.registers.setdefault(wire.REG_CHIP_ADDRESS, 0x1362_0000)
        self.registers.setdefault(wire.REG_MISC_CONTROL, 0x0000_0001)
        self.registers.setdefault(wire.REG_PLL0, 0x40A8_0265)  # RE-018 default
        self.registers.setdefault(wire.REG_TICKET_MASK, 0x0000_00FF)

    @property
    def freq_mhz(self) -> float:
        decoded = wire.decode_pll_reg_to_freq_mhz(
            self.registers.get(wire.REG_PLL0, 0)
        )
        return float(decoded) if decoded else 0.0

    def write_register(self, reg: int, value: int) -> None:
        self.registers[reg] = value & 0xFFFFFFFF
        if reg == wire.REG_CHIP_ADDRESS:
            self.address = value & 0xFF

    def error_rate(self, die_temp_c: float) -> float:
        return physics.error_rate(self.freq_mhz, die_temp_c, self.bin_spec)


# ---------------------------------------------------------------------------
# The simulated chain
# ---------------------------------------------------------------------------


class SimChain:
    """An ordered chain of SimChips plus its physics board model."""

    def __init__(
        self,
        n_chips: int = 8,
        difficulty: float = 0.001,
        rail_v: float = 13.8,
        pwm_percent: float = 100.0,
        searching_fraction: float = 1.0,
        max_nonces_per_job: int = 1 << 20,
        bins: Optional[List[physics.ChipBin]] = None,
        power: Optional[physics.PowerParams] = None,
        thermal: Optional[physics.ThermalParams] = None,
        rng_seed: int = 0xB01362,
        hw_error_injection: bool = True,
    ) -> None:
        if n_chips <= 0:
            raise ValueError("chain needs at least one chip")
        self.n_chips = n_chips
        self.difficulty = difficulty
        self.share_target = nonce_engine.target_from_difficulty(difficulty)
        self.rail_v = rail_v
        self.max_nonces_per_job = max_nonces_per_job
        self.hw_error_injection = hw_error_injection
        self.rng = random.Random(rng_seed)
        self.chips: List[SimChip] = []
        bins = bins if bins is not None else physics.default_nameplate_bins(n_chips)
        n_search = max(1, int(round(n_chips * searching_fraction)))
        for i in range(n_chips):
            self.chips.append(
                SimChip(
                    index=i,
                    bin_spec=bins[i % len(bins)],
                    searching_core=i < n_search,
                )
            )
        self.power = power if power is not None else physics.calibrate_bm1362_s19jpro()
        self.thermal_model = physics.BoardThermalModel(
            n_chips=n_chips,
            thermal=thermal if thermal is not None
            else physics.default_s19jpro_thermal_params(),
            power=self.power,
            pwm_percent=pwm_percent,
        )
        # ring of jobs seen, for job_id echo verification
        self.jobs: Dict[int, Tuple[wire.JobFields, bytes]] = {}
        self.baud = wire.DEFAULT_BAUD  # logical only: the TCP transport is
        # baud-agnostic; the ladder models chip-side UART law timing
        self._addr_cursor = 0
        # RLock: server sessions call chain methods that also lock (the
        # search itself runs OUTSIDE the lock — see dispatch_job)
        self.lock = threading.RLock()

    # -- enumeration -------------------------------------------------------

    def chain_inactive(self) -> None:
        """ChainInactive broadcast: every chip forgets its address."""
        for chip in self.chips:
            chip.address = None
            chip.registers[wire.REG_CHIP_ADDRESS] = 0x1362_0000

    def set_chip_address(self, addr: int) -> bool:
        """First un-addressed chip claims `addr` (serialized ladder)."""
        for chip in self.chips:
            if chip.address is None:
                chip.address = addr & 0xFF
                chip.registers[wire.REG_CHIP_ADDRESS] = (
                    (wire.BM1362_CHIP_ID << 16) | addr & 0xFFFF
                )
                return True
        return False  # every chip already addressed

    def assigned_chips(self) -> List[SimChip]:
        return [c for c in self.chips if c.address is not None]

    # -- registers ---------------------------------------------------------

    def _apply_register_side_effects(self, reg: int, value: int) -> None:
        """Chip-side law: the FAST_UART_CONFIG stock value (0x00003011)
        moves the chain onto the operational rung of the baud ladder
        (logical timing only — the TCP transport relays bytes regardless)."""
        if reg == wire.REG_FAST_UART_CONFIG:
            if value == wire.FAST_UART_CONFIG_VALUE:
                self.baud = wire.OPERATIONAL_BAUD
            else:
                self.baud = wire.DEFAULT_BAUD

    def write_register(self, chip_addr: int, reg: int, value: int) -> List[SimChip]:
        """Single-chip write; returns the chips written."""
        targets = [
            c for c in self.chips
            if c.address is not None and c.address == chip_addr
        ]
        for chip in targets:
            chip.write_register(reg, value)
        if targets:
            self._apply_register_side_effects(reg, value)
        return targets

    def broadcast_write(self, reg: int, value: int) -> List[SimChip]:
        for chip in self.assigned_chips():
            chip.write_register(reg, value)
        self._apply_register_side_effects(reg, value)
        return self.assigned_chips()

    def set_rail(self, volts: float) -> None:
        """Set the chain voltage-domain rail (server-side config; the real
        chain rail is a dsPIC/PSU concern owned by the future I2C sidecar —
        no BM1362 wire register claims rail volts, so we do not invent one)."""
        if volts <= 0:
            raise ValueError("rail voltage must be positive")
        self.rail_v = volts

    def read_register(self, chip: SimChip, reg: int) -> int:
        if reg == wire.REG_CHIP_ADDRESS:
            return (
                (wire.BM1362_CHIP_ID << 16)
                | (wire.BM1362_CORE_COUNT_ENCODING << 8)
                | (chip.address or 0)
            )
        return chip.registers.get(reg, 0)

    # -- physics -----------------------------------------------------------

    def step_physics(self, dt_s: float) -> None:
        self.thermal_model.step(dt_s, self.chip_freqs(), self.rail_v)

    def chip_freqs(self) -> List[float]:
        return [c.freq_mhz for c in self.chips]

    def chip_die_temps(self) -> List[float]:
        return self.thermal_model.chip_die_temps()

    # -- mining ------------------------------------------------------------

    def dispatch_job(self, fields: wire.JobFields) -> List[bytes]:
        """Run the REAL nonce search for one job; return response frames.

        Each searching chip scans its own bounded nonce window (subsampled:
        found-share rate, not terahash).  A chip operating past its
        sigmoid error cliff corrupts its returned nonce with probability
        error_rate (HW-error injection -> daemon-side hw_err accounting).
        The search itself runs OUTSIDE the chain lock (commands and physics
        keep flowing while chips hash, like real silicon); only state
        snapshots/updates take the lock.
        """
        header_prefix = fields.header_prefix()
        with self.lock:
            self.jobs[fields.job_id] = (fields, header_prefix)
            targets = [
                (i, chip)
                for i, chip in enumerate(self.chips)
                if chip.address is not None and chip.searching_core
            ]
            dies = self.chip_die_temps()

        responses: List[bytes] = []
        for i, chip in targets:
            job = nonce_engine.MidstateJob.from_header_prefix(
                header_prefix,
                target=self.share_target,
                job_id=fields.job_id,
            )
            start = (
                fields.starting_nonce + chip.index * self.max_nonces_per_job * 2
            ) & 0xFFFFFFFF
            share = nonce_engine.search(
                job,
                start_nonce=start,
                max_nonces=self.max_nonces_per_job,
            )
            if share is None:
                continue
            nonce_out = share.nonce
            corrupted = (
                self.hw_error_injection
                and self.rng.random() < chip.error_rate(dies[i])
            )
            with self.lock:
                if corrupted:
                    # corrupt the nonce: daemon-side validation will fail
                    # (feeds hw_err_tracker / bad-chip supervisors)
                    nonce_out ^= 0x5A5A_0000
                    chip.hw_errors_injected += 1
                else:
                    chip.shares_found += 1
                responses.append(
                    wire.build_nonce_response(
                        nonce=nonce_out,
                        job_id=fields.job_id,
                        version_bits=0,
                        small_core=self.rng.randrange(16),
                    )
                )
        return responses

    # -- status ------------------------------------------------------------

    def status(self) -> Dict[str, object]:
        return {
            "n_chips": self.n_chips,
            "assigned": len(self.assigned_chips()),
            "baud": self.baud,
            "difficulty": self.difficulty,
            "rail_v": self.rail_v,
            "board_temp_c": round(self.thermal_model.board_temp_c, 2),
            "sensor_temp_c": round(self.thermal_model.sensor_temp_c, 2),
            "board_power_w": round(
                self.thermal_model.board_power_w(
                    self.chip_freqs(), self.rail_v
                ),
                2,
            ),
            "chip_freqs_mhz": [round(f, 1) for f in self.chip_freqs()],
            "die_temps_c": [round(t, 1) for t in self.chip_die_temps()],
            "error_rates": [
                round(c.error_rate(t), 4)
                for c, t in zip(self.chips, self.chip_die_temps())
            ],
            "hw_errors_injected": sum(
                c.hw_errors_injected for c in self.chips
            ),
            "shares_found": sum(c.shares_found for c in self.chips),
            "tier": "T1-sim / T2-twin evidence only; model outputs, not "
            "silicon truth",
        }


# ---------------------------------------------------------------------------
# Command routing (host frame -> chip responses)
# ---------------------------------------------------------------------------


def route_command(chain: SimChain, frame: wire.CmdFrame) -> List[bytes]:
    """Apply one decoded command frame to the chain; return response frames
    in chip order.

    Intent is routed by header byte + frame length (the BM1397+/BM1362
    family uses bare headers 0x40/0x41/0x42/0x51/0x52/0x53; the BM1387
    space composes TYPE_CMD|GROUP_ALL|opcode).  SETADDR vs WRITE shares an
    opcode and is differentiated by length (5 vs 9) per protocol.rs.
    """
    if frame.is_job:
        raise ValueError("job frames are not commands")

    header = frame.header

    # ChainInactive (0x53 BM1362 law, 0x55 BM1387) — reset addresses
    if header in (wire.HDR_BM139X_INACTIVE_BCAST, wire.HDR_CMD_BCAST_INACTIVE):
        chain.chain_inactive()
        return []

    # SetChipAddress (0x40, length 5): first un-addressed chip claims it
    if header in (wire.HDR_BM139X_SETADDR, wire.HDR_CMD_SETADDR) and frame.is_setaddr:
        chain.set_chip_address(frame.chip_addr)
        return []

    # Reads: broadcast (0x52/0x54) or single (0x42/0x44)
    if header in (
        wire.HDR_BM139X_READ_BCAST,
        wire.HDR_CMD_BCAST_READ,
    ):
        return [
            wire.build_register_response(
                chip_addr=c.address or 0,
                reg=frame.reg,
                value=chain.read_register(c, frame.reg),
            )
            for c in chain.assigned_chips()
        ]
    if header in (wire.HDR_BM139X_READ_SINGLE, wire.HDR_CMD_READ):
        targets = [
            c for c in chain.assigned_chips() if c.address == frame.chip_addr
        ]
        return [
            wire.build_register_response(
                chip_addr=c.address or 0,
                reg=frame.reg,
                value=chain.read_register(c, frame.reg),
            )
            for c in targets
        ]

    # Writes (9-byte): broadcast (0x51/0x58) or single (0x41/0x48)
    if header in (wire.HDR_BM139X_WRITE_BCAST, wire.HDR_CMD_BCAST_SETCONFIG,
                  wire.HDR_CMD_BCAST_WRITE):
        assert frame.value is not None
        chain.broadcast_write(frame.reg, frame.value)
        return []
    if header in (wire.HDR_BM139X_WRITE_SINGLE, wire.HDR_CMD_SETCONFIG,
                  wire.HDR_CMD_WRITE):
        assert frame.value is not None
        chain.write_register(frame.chip_addr, frame.reg, frame.value)
        return []

    raise wire.ProtocolError(f"unrouted header {header:#04x}")


# ---------------------------------------------------------------------------
# TCP server (one chain per port)
# ---------------------------------------------------------------------------


class ChainServer:
    """Threaded TCP front-end for one SimChain.

    The daemon (or a test client) connects, writes command/job frames, and
    reads response frames.  Frame boundaries: CMD frames by their length
    byte, JOB frames fixed at 88 bytes, responses are 11 bytes each.
    """

    TICK_S = 1.0  # physics tick

    def __init__(
        self,
        chain: SimChain,
        host: str = "127.0.0.1",
        port: int = 0,
    ) -> None:
        if host not in ("127.0.0.1", "localhost", "::1"):
            # G-spirit: default posture is loopback-only operation
            raise ValueError(
                "emu-twin chain server binds loopback only by policy; "
                f"refused {host!r}"
            )
        self.chain = chain
        self.host = host
        self.port = port
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((host, port))
        self.port = self._sock.getsockname()[1]
        self._sock.listen(4)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._physics_thread: Optional[threading.Thread] = None
        self.rx_bytes = 0
        self.tx_bytes = 0

    # -- lifecycle ---------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._serve, name=f"chain-{self.port}", daemon=True
        )
        self._thread.start()
        self._physics_thread = threading.Thread(
            target=self._physics_loop, name=f"phys-{self.port}", daemon=True
        )
        self._physics_thread.start()

    def close(self) -> None:
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def _physics_loop(self) -> None:
        while not self._stop.is_set():
            time.sleep(self.TICK_S)
            if self._stop.is_set():
                return
            try:
                with self.chain.lock:
                    self.chain.step_physics(self.TICK_S)
            except Exception:  # pragma: no cover - physics must never kill IO
                pass

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _addr = self._sock.accept()
            except OSError:
                return  # socket closed
            with conn:
                self._session(conn)

    def _session(self, conn: socket.socket) -> None:
        conn.settimeout(30.0)
        buf = bytearray()
        while not self._stop.is_set():
            try:
                chunk = conn.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            if not chunk:
                return
            self.rx_bytes += len(chunk)
            buf.extend(chunk)
            out = bytearray()
            while buf:
                if buf[:2] == wire.CMD_PREAMBLE:
                    size = wire.frame_size_hint(bytes(buf[:8]))
                    if size is None or len(buf) < size:
                        break  # incomplete frame; wait for more bytes
                    frame = bytes(buf[:size])
                    del buf[:size]
                    if frame[2] & wire.TYPE_JOB:
                        try:
                            fields = wire.parse_job_frame(frame)
                        except wire.ProtocolError:
                            continue  # drop malformed job frames
                        with self.chain.lock:
                            responses = self.chain.dispatch_job(fields)
                        out.extend(b"".join(responses))
                    else:
                        try:
                            cmd = wire.parse_cmd_frame(frame)
                        except wire.ProtocolError:
                            continue  # drop CRC-bad frames (resync by size)
                        with self.chain.lock:
                            try:
                                responses = route_command(self.chain, cmd)
                            except wire.ProtocolError:
                                responses = []
                        out.extend(b"".join(responses))
                elif buf[0] == 0x00:
                    # inter-frame UART idle padding — skip
                    del buf[:1]
                else:
                    # resync: scan to next preamble
                    idx = bytes(buf).find(wire.CMD_PREAMBLE)
                    del buf[: idx if idx > 0 else 1]
            if out:
                try:
                    conn.sendall(bytes(out))
                    self.tx_bytes += len(out)
                except OSError:
                    return

    # -- context manager ----------------------------------------------------

    def __enter__(self) -> "ChainServer":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="chain_server",
        description=(
            "BM1362 hashboard-chain emulator (emu-twin). Host-side TCP chain "
            "that REALLY mines: real double-SHA256 nonce search, physics-"
            "driven temperature/power, sigmoid HW-error cliff. "
            "Fund: https://d-central.tech/fund/"
        ),
    )
    parser.add_argument("--host", default="127.0.0.1",
                        help="bind host (loopback only by policy)")
    parser.add_argument("--port", type=int, default=40260,
                        help="TCP port for this chain")
    parser.add_argument("--chips", type=int, default=8,
                        help="simulated chips on the chain")
    parser.add_argument("--difficulty", type=float, default=0.001,
                        help="share difficulty (may be fractional)")
    parser.add_argument("--rail-v", type=float, default=13.8,
                        help="chain rail voltage")
    parser.add_argument("--pwm", type=float, default=100.0,
                        help="fan PWM percent (thermal model)")
    parser.add_argument("--search-fraction", type=float, default=1.0,
                        help="fraction of chips running the real search")
    parser.add_argument("--max-nonces", type=int, default=1 << 20,
                        help="per-chip per-job nonce scan bound")
    parser.add_argument("--no-hw-errors", action="store_true",
                        help="disable HW-error injection")
    parser.add_argument("--print-status-interval", type=float, default=30.0,
                        help="seconds between status prints (0 = never)")
    parser.add_argument("--status-log", default=None,
                        help="append status lines to this file (device paths "
                        "are refused by the G-spirit guard)")
    args = parser.parse_args(argv)

    chain = SimChain(
        n_chips=args.chips,
        difficulty=args.difficulty,
        rail_v=args.rail_v,
        pwm_percent=args.pwm,
        searching_fraction=args.search_fraction,
        max_nonces_per_job=args.max_nonces,
        hw_error_injection=not args.no_hw_errors,
    )
    server = ChainServer(chain, host=args.host, port=args.port)
    server.start()
    print(
        f"emu-twin chain server: {args.chips} BM1362 chips on "
        f"{server.host}:{server.port} (difficulty {args.difficulty}, rail "
        f"{args.rail_v} V, PWM {args.pwm}%)",
        flush=True,
    )
    status_log = open_status_log(args.status_log)
    try:
        last_status = time.monotonic()
        while True:
            time.sleep(0.5)
            if args.print_status_interval > 0 and (
                time.monotonic() - last_status >= args.print_status_interval
            ):
                last_status = time.monotonic()
                line = f"status: {chain.status()}"
                print(line, flush=True)
                if status_log is not None:
                    status_log.write(line + "\n")
                    status_log.flush()
    except KeyboardInterrupt:
        pass
    finally:
        server.close()
        if status_log is not None:
            status_log.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
