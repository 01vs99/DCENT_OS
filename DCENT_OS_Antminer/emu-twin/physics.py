"""Physics models for the emu-twin chain emulator: power, thermal RC, and
the HW-error cliff.

TIER HONESTY: everything in this module is a MODEL (T1 sim surface).  Model
outputs, not silicon truth.  Every load-bearing coefficient carries a
provenance label in the comments/`source` fields:

  [LUXOS-79-LIVE]     live LuxOS .79 BM1362 S19j Pro capture rows mirrored in
                      `dcentrald-silicon-profiles/src/operating_points.rs`
                      S19J_PRO_POINTS (K-doc §1.1/§1.2/§1.4) — watts/TH/freq/
                      voltage per step, chain-rail volts.
  [BRAIINS-AUTOTUNE]  Braiins autotune JSON per-chip PLL spread at the tuned
                      1300 W point (231.7/232.7/233.2 MHz) via
                      wave1/a2-twin-architecture.md §Plan inputs.
  [A2-TWIN-SPEC]      model-shape parameters from the twin architecture doc
                      (leakage x2 per 20 C, fan-affinity h ~ PWM^0.9, sensor
                      lag 2-5 s, preheat 38->55 C in ~2 min at nameplate).
  [DCENT-MODEL]       first-order engineering assumption with no measured
                      anchor (thermal derate of the error cliff, default
                      nameplate fmax bins).  These are SIMULATION knobs, not
                      claims about silicon.

Power model (per chip):
    P = P_dynamic + P_static = c_eff * V^2 * f + p_leak(T)
    p_leak(T) = p_leak_ref * 2^((T - T_ref) / 20)   [A2-TWIN-SPEC]
    c_eff and p_leak_ref are calibrated so the [LUXOS-79-LIVE] Step 0 row
    (545 MHz / 13.8 V rail / 3126 W AC wall, ~12% APW loss) reproduces, with
    the Step -9 sweet-spot row (320 MHz / 12.45 V / 1714 W wall) as the
    cross-check — see `calibrate_bm1362_s19jpro()`.

Thermal model (per hashboard/chain): per-chip die nodes -> shared board node
-> airflow (fan-affinity conductance) -> ambient, plus a first-order sensor
node (LM75 placement).  Board C is set so the [A2-TWIN-SPEC] preheat anchor
(38 -> 55 C in ~2 min at nameplate power) holds.

HW-error cliff (per chip bin):
    error_rate = 1 / (1 + e^{-k * (f - f_cliff(T))})
    f_cliff(T) = f_cliff25 - derate * (T_die - 25)   [DCENT-MODEL]
Temperature from the thermal model feeds back into both the cliff and
leakage — the autotuner stress loop the twin exists to exercise.

License: GPL-3.0 (DCENT_OS emu-twin).
Fund: https://d-central.tech/fund/
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

# ---------------------------------------------------------------------------
# Anchored operating rows used for calibration
# ---------------------------------------------------------------------------

# [LUXOS-79-LIVE] via operating_points.rs S19J_PRO_POINTS (BHB42601, BM1362,
# 3 boards x 126 chips; voltage is CHAIN RAIL; watts are AC-side wall).
# (step label, freq MHz, rail mV, TH/s unit, wall W unit)
S19J_PRO_ANCHOR_ROWS: Tuple[Tuple[str, int, int, float, int], ...] = (
    ("step_-16", 145, 11880, 28.1, 997),
    ("step_-13_whisper", 220, 11880, 42.7, 1244),
    ("step_-11_atm_floor", 270, 12150, 52.4, 1466),
    ("step_-9_sweet", 320, 12450, 62.1, 1714),
    ("step_-7_heater", 370, 12750, 71.8, 1994),
    ("step_-5", 420, 13050, 81.6, 2297),
    ("step_0_default", 545, 13800, 105.8, 3126),
)

CHIPS_PER_BOARD_S19J_PRO = 126  # [LUXOS-79-LIVE] BHB42601 geometry
BOARDS_PER_UNIT = 3
APW_PSU_LOSS_FRACTION = 0.12    # [A2-TWIN-SPEC] "~12% APW loss" (Step 0 note)


# ---------------------------------------------------------------------------
# Power parameters
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PowerParams:
    """Per-chip power-model coefficients + provenance."""

    c_eff: float              # W / (V^2 * MHz) per chip
    p_leak_ref: float         # W per chip at T_ref
    t_ref_c: float            # leakage reference temperature, C
    leakage_doubling_c: float  # C per leakage doubling [A2-TWIN-SPEC] = 20
    psu_loss_fraction: float  # AC wall -> board DC loss
    source: str = ""

    def static_watts(self, temp_c: float) -> float:
        """Leakage at a die temperature."""
        exponent = (temp_c - self.t_ref_c) / self.leakage_doubling_c
        return self.p_leak_ref * (2.0 ** exponent)

    def chip_power(self, freq_mhz: float, rail_v: float, temp_c: float) -> float:
        """Total per-chip power: c_eff*V^2*f + leakage(T)."""
        if freq_mhz < 0 or rail_v < 0:
            raise ValueError("frequency and voltage must be non-negative")
        dynamic = self.c_eff * rail_v * rail_v * freq_mhz
        return dynamic + self.static_watts(temp_c)

    def board_power(
        self,
        freqs_mhz: Sequence[float],
        rail_v: float,
        temps_c: Sequence[float],
    ) -> float:
        """Board (chain) DC power summed over chips."""
        if len(freqs_mhz) != len(temps_c):
            raise ValueError("freq and temp lists must align")
        return sum(
            self.chip_power(f, rail_v, t) for f, t in zip(freqs_mhz, temps_c)
        )

    def wall_watts(self, board_dc_w: float) -> float:
        """AC-side wall watts for one board's DC power (per-board PSU share)."""
        return board_dc_w / (1.0 - self.psu_loss_fraction)


def calibrate_bm1362_s19jpro(
    static_share_at_ref: float = 0.08,
    t_ref_c: float = 60.0,
) -> PowerParams:
    """Solve c_eff/p_leak so the [LUXOS-79-LIVE] Step 0 nameplate row
    reproduces exactly, then leave the other rows as cross-checks.

    static_share_at_ref: leakage fraction of chip power at T_ref
    [A2-TWIN-SPEC] "leakage share ~6-10%" — 8% mid-band.
    """
    _, f0, v0_mv, _, w0 = S19J_PRO_ANCHOR_ROWS[-1]  # step_0_default
    rail0 = v0_mv / 1000.0
    board_dc = w0 * (1.0 - APW_PSU_LOSS_FRACTION) / BOARDS_PER_UNIT
    per_chip = board_dc / CHIPS_PER_BOARD_S19J_PRO
    p_leak_ref = static_share_at_ref * per_chip
    dynamic = per_chip - p_leak_ref
    c_eff = dynamic / (rail0 * rail0 * f0)
    return PowerParams(
        c_eff=c_eff,
        p_leak_ref=p_leak_ref,
        t_ref_c=t_ref_c,
        leakage_doubling_c=20.0,
        psu_loss_fraction=APW_PSU_LOSS_FRACTION,
        source=(
            "calibrated on [LUXOS-79-LIVE] step_0 (545 MHz/13.8 V rail/"
            "3126 W wall, 12% APW loss) via operating_points.rs "
            "S19J_PRO_POINTS; static share 8% [A2-TWIN-SPEC]"
        ),
    )


def calibration_residuals(params: PowerParams) -> Dict[str, float]:
    """Model-vs-anchor wall-watt residuals for every anchored row
    (labels -> percent error).  Honesty surface: shows the two-point model's
    fit across the whole LuxOS curve."""
    out: Dict[str, float] = {}
    temps = [params.t_ref_c] * CHIPS_PER_BOARD_S19J_PRO
    for label, f, v_mv, _, wall in S19J_PRO_ANCHOR_ROWS:
        freqs = [float(f)] * CHIPS_PER_BOARD_S19J_PRO
        board = params.board_power(freqs, v_mv / 1000.0, temps)
        model_wall = params.wall_watts(board) * BOARDS_PER_UNIT
        out[label] = (model_wall - wall) / wall * 100.0
    return out


# ---------------------------------------------------------------------------
# Thermal parameters + RC network
# ---------------------------------------------------------------------------


# [DCENT-MODEL] Die-temperature ceiling for the runaway guard.  Past this
# point a real daemon's thermal supervisor would already have curtailed
# hash power (the space-heater posture rule: cut hash before damage).  The
# twin's model clamps rather than chasing leakage thermal runaway to an
# OverflowError; the clamp is a SIMULATION policy, not a silicon limit.
MODEL_MAX_DIE_C = 125.0


@dataclass(frozen=True)
class ThermalParams:
    """Board/chip thermal RC parameters (single chain == single board)."""

    ambient_c: float
    c_die_j_per_k: float          # per-chip die capacitance
    theta_die_board_k_per_w: float  # per-chip die -> board conductance share
    c_board_j_per_k: float        # board + heatsink capacitance
    theta_board_air_full_fan: float  # K/W at 100% PWM
    fan_exponent: float           # h ~ PWM^fan_exponent [A2-TWIN-SPEC] 0.9
    sensor_tau_s: float           # LM75 sensor lag [A2-TWIN-SPEC] 2-5 s
    source: str = ""

    def theta_board_air(self, pwm_percent: float) -> float:
        """Board -> air thermal resistance at a fan PWM (0..100).

        Conductance scales with fan affinity; PWM 0 keeps a floor so the
        board always eventually reaches equilibrium (passive convection).
        """
        pwm = min(max(pwm_percent, 0.0), 100.0)
        effective = max(pwm, 5.0)  # passive-convection floor [DCENT-MODEL]
        conductance = (effective / 100.0) ** self.fan_exponent
        return self.theta_board_air_full_fan / conductance


def default_s19jpro_thermal_params(ambient_c: float = 25.0) -> ThermalParams:
    """Defaults anchored on the [A2-TWIN-SPEC] preheat law.

    Board C is fit so that at nameplate board power (~917 W DC, PWM 100,
    theta_air 0.049 K/W -> T_eq ~ 70 C) a board starting at 38 C reaches
    ~55 C in ~120 s: tau = C*theta ~ 157 s -> C ~ 3.2 kJ/K."""
    return ThermalParams(
        ambient_c=ambient_c,
        c_die_j_per_k=0.6,            # [DCENT-MODEL] small-die 5 nm node
        theta_die_board_k_per_w=0.30,  # [DCENT-MODEL] die a few K above board
        c_board_j_per_k=3200.0,       # [DCENT-MODEL] fit to preheat anchor
        theta_board_air_full_fan=0.049,  # [DCENT-MODEL] ~45 K rise @ 917 W
        fan_exponent=0.9,             # [A2-TWIN-SPEC] fan affinity
        sensor_tau_s=3.0,             # [A2-TWIN-SPEC] 2-5 s band
        source=(
            "RC shape [DCENT-MODEL] fit to [A2-TWIN-SPEC] anchors: "
            "preheat 38->55 C ~2 min at nameplate; fan h~PWM^0.9; "
            "sensor lag 2-5 s"
        ),
    )


class ChipThermalNode:
    """One chip's die node: C_die * dT/dt = P_chip - (T_die - T_board)/theta.

    Advanced with the exact exponential solution (unconditionally stable;
    the die time constant ~0.2 s is far below any server tick)."""

    def __init__(self, params: ThermalParams, temp_c: float) -> None:
        self.params = params
        self.die_temp_c = temp_c

    def step(self, dt_s: float, power_w: float, board_temp_c: float) -> float:
        """Advance one tick; returns the new die temperature.

        Clamped at MODEL_MAX_DIE_C (leakage-runaway guard; a real supervisor
        would have curtailed hash power long before — see MODEL_MAX_DIE_C).
        """
        theta = self.params.theta_die_board_k_per_w
        tau = self.params.c_die_j_per_k * theta
        equilibrium = board_temp_c + power_w * theta
        decay = math.exp(-dt_s / tau)
        self.die_temp_c = equilibrium + (self.die_temp_c - equilibrium) * decay
        if self.die_temp_c > MODEL_MAX_DIE_C:
            self.die_temp_c = MODEL_MAX_DIE_C
        return self.die_temp_c


class BoardThermalModel:
    """Per-chain thermal network: N die nodes -> board node -> sensor node.

    This is the model the chain server advances every physics tick; the
    daemon-side reads (LM75 via the future I2C sidecar, analog mux) are fed
    from `sensor_temp_c`.
    """

    def __init__(
        self,
        n_chips: int,
        thermal: ThermalParams,
        power: PowerParams,
        pwm_percent: float = 100.0,
    ) -> None:
        self.thermal = thermal
        self.power = power
        self.pwm_percent = pwm_percent
        self.board_temp_c = thermal.ambient_c
        self.sensor_temp_c = thermal.ambient_c
        self.chips = [
            ChipThermalNode(thermal, thermal.ambient_c) for _ in range(n_chips)
        ]

    def step(
        self,
        dt_s: float,
        freqs_mhz: Sequence[float],
        rail_v: float,
    ) -> None:
        """Advance the whole network one tick with per-chip frequencies."""
        if len(freqs_mhz) != len(self.chips):
            raise ValueError("frequency list must match chip count")
        total_power = 0.0
        for node, f in zip(self.chips, freqs_mhz):
            p = self.power.chip_power(f, rail_v, node.die_temp_c)
            node.step(dt_s, p, self.board_temp_c)
            total_power += p
        theta_air = self.thermal.theta_board_air(self.pwm_percent)
        tau_board = self.thermal.c_board_j_per_k * theta_air
        equilibrium = self.thermal.ambient_c + total_power * theta_air
        decay = math.exp(-dt_s / tau_board)
        self.board_temp_c = equilibrium + (
            self.board_temp_c - equilibrium
        ) * decay
        # first-order sensor lag towards board temperature
        alpha = 1.0 - math.exp(-dt_s / self.thermal.sensor_tau_s)
        self.sensor_temp_c += alpha * (self.board_temp_c - self.sensor_temp_c)

    def chip_die_temps(self) -> List[float]:
        return [c.die_temp_c for c in self.chips]

    def board_power_w(self, freqs_mhz: Sequence[float], rail_v: float) -> float:
        return self.power.board_power(
            freqs_mhz, rail_v, self.chip_die_temps()
        )


# ---------------------------------------------------------------------------
# HW-error cliff (sigmoid) with per-chip bins
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ChipBin:
    """Silicon-bin error-cliff parameters for one chip."""

    label: str
    k_per_mhz: float       # sigmoid steepness
    f_cliff25_mhz: float   # cliff center at 25 C die
    derate_mhz_per_c: float  # cliff droop with temperature [DCENT-MODEL]
    source: str = ""


def error_rate(freq_mhz: float, die_temp_c: float, chip_bin: ChipBin) -> float:
    """Sigmoid HW-error rate: 1 / (1 + e^{-k (f - f_cliff(T))}).

    Below the cliff ~0 errors; above it ~1 (every returned nonce suspect).
    The temperature feedback (cliff droop) is what makes the autotuner's
    over-frequency stress visible in the twin.
    """
    cliff = chip_bin.f_cliff25_mhz - chip_bin.derate_mhz_per_c * (
        die_temp_c - 25.0
    )
    z = chip_bin.k_per_mhz * (freq_mhz - cliff)
    # guard the exp overflow for extreme z
    if z > 60.0:
        return 1.0
    if z < -60.0:
        return 0.0
    return 1.0 / (1.0 + math.exp(-z))


def braiins_tuned_bins() -> List[ChipBin]:
    """The [BRAIINS-AUTOTUNE] per-chip PLL spread at the tuned 1300 W point
    (231.7 / 232.7 / 233.2 MHz) as three example bins — the spread the
    real autotuner must hunt across when the board is tuned low."""
    return [
        ChipBin(
            label="braiins_tuned_231.7",
            k_per_mhz=0.8,
            f_cliff25_mhz=231.7 + 20.0,
            derate_mhz_per_c=0.5,
            source="[BRAIINS-AUTOTUNE] 231.7 MHz spread anchor + 20 MHz "
            "margin [DCENT-MODEL]",
        ),
        ChipBin(
            label="braiins_tuned_232.7",
            k_per_mhz=0.8,
            f_cliff25_mhz=232.7 + 20.0,
            derate_mhz_per_c=0.5,
            source="[BRAIINS-AUTOTUNE] 232.7 MHz spread anchor + 20 MHz "
            "margin [DCENT-MODEL]",
        ),
        ChipBin(
            label="braiins_tuned_233.2",
            k_per_mhz=0.8,
            f_cliff25_mhz=233.2 + 20.0,
            derate_mhz_per_c=0.5,
            source="[BRAIINS-AUTOTUNE] 233.2 MHz spread anchor + 20 MHz "
            "margin [DCENT-MODEL]",
        ),
    ]


def default_nameplate_bins(n_chips: int, jitter_mhz: float = 6.0) -> List[ChipBin]:
    """Nameplate-operation bins: cliffs near 545 MHz + spread.

    [DCENT-MODEL] the 545 MHz default has no measured per-chip fmax roster;
    the center + jitter and the sigmoid steepness are simulation knobs, not
    claims about BM1362 silicon.  Deterministic (seeded RNG) so twin runs
    are reproducible.
    """
    import random

    rng = random.Random(0xC0FFEE ^ n_chips)
    bins: List[ChipBin] = []
    for i in range(n_chips):
        offset = rng.uniform(-jitter_mhz, jitter_mhz)
        bins.append(
            ChipBin(
                label=f"nameplate_ch{i}",
                k_per_mhz=0.8,
                f_cliff25_mhz=560.0 + offset,
                derate_mhz_per_c=0.5,
                source="[DCENT-MODEL] nameplate bin center 560 MHz + jitter",
            )
        )
    return bins


__all__ = [
    "MODEL_MAX_DIE_C",
    "S19J_PRO_ANCHOR_ROWS",
    "CHIPS_PER_BOARD_S19J_PRO",
    "BOARDS_PER_UNIT",
    "APW_PSU_LOSS_FRACTION",
    "PowerParams",
    "ThermalParams",
    "ChipBin",
    "calibrate_bm1362_s19jpro",
    "calibration_residuals",
    "default_s19jpro_thermal_params",
    "ChipThermalNode",
    "BoardThermalModel",
    "error_rate",
    "braiins_tuned_bins",
    "default_nameplate_bins",
]
