"""Physics tests: power-model calibration honesty, thermal RC sanity, and
the HW-error cliff.

Every assertion checks a MODEL property, not silicon truth (tier honesty:
T1 sim surface).  Provenance labels ([LUXOS-79-LIVE], [A2-TWIN-SPEC],
[DCENT-MODEL], [BRAIINS-AUTOTUNE]) are carried in physics.py.

License: GPL-3.0 (DCENT_OS emu-twin).
Fund: https://d-central.tech/fund/
"""

from __future__ import annotations

import pytest

import physics as phys


class TestPowerModel:
    def test_calibration_reproduces_step0_anchor_exactly(self):
        # The calibration row ([LUXOS-79-LIVE] step_0: 545 MHz / 13.8 V /
        # 3126 W wall) must come out exact by construction.
        params = phys.calibrate_bm1362_s19jpro()
        residuals = phys.calibration_residuals(params)
        assert residuals["step_0_default"] == pytest.approx(0.0, abs=1e-9)

    def test_residual_band_is_documented_and_bounded(self):
        # A two-point model does not fit a 7-row curve; the test pins the
        # honesty band: every anchored row within +/-20% (leakage share is
        # the loosest knob at the low-watt end).
        params = phys.calibrate_bm1362_s19jpro()
        residuals = phys.calibration_residuals(params)
        for label, pct in residuals.items():
            assert abs(pct) < 20.0, (label, pct)

    def test_power_monotonic_in_frequency_and_voltage(self):
        params = phys.calibrate_bm1362_s19jpro()
        p1 = params.chip_power(400.0, 13.0, 60.0)
        p2 = params.chip_power(500.0, 13.0, 60.0)
        p3 = params.chip_power(500.0, 14.0, 60.0)
        assert p2 > p1
        assert p3 > p2

    def test_static_leakage_doubles_per_20c(self):
        # [A2-TWIN-SPEC] leakage law
        params = phys.calibrate_bm1362_s19jpro()
        at_ref = params.static_watts(params.t_ref_c)
        at_hot = params.static_watts(params.t_ref_c + 20.0)
        assert at_hot == pytest.approx(at_ref * 2.0, rel=1e-9)

    def test_board_power_scales_with_chip_count(self):
        params = phys.calibrate_bm1362_s19jpro()
        freqs = [545.0] * phys.CHIPS_PER_BOARD_S19J_PRO
        temps = [60.0] * phys.CHIPS_PER_BOARD_S19J_PRO
        board = params.board_power(freqs, 13.8, temps)
        chip = params.chip_power(545.0, 13.8, 60.0)
        assert board == pytest.approx(chip * phys.CHIPS_PER_BOARD_S19J_PRO)


class TestThermalModel:
    N = 126  # full S19j Pro board so board power is nameplate-real

    def _model(self, ambient=25.0, pwm=100.0):
        return phys.BoardThermalModel(
            n_chips=self.N,
            thermal=phys.default_s19jpro_thermal_params(ambient_c=ambient),
            power=phys.calibrate_bm1362_s19jpro(),
            pwm_percent=pwm,
        )

    def test_temperature_rises_with_f_times_v(self):
        low = self._model()
        high = self._model()
        for _ in range(300):  # 300 s
            low.step(1.0, [200.0] * self.N, 11.88)   # [LUXOS-79-LIVE] whisper
            high.step(1.0, [545.0] * self.N, 13.8)   # nameplate
        assert high.board_temp_c > low.board_temp_c + 5.0
        assert low.board_temp_c > 25.0

    def test_die_above_board_above_ambient_under_load(self):
        model = self._model()
        for _ in range(600):
            model.step(1.0, [545.0] * self.N, 13.8)
        dies = model.chip_die_temps()
        assert all(d > model.board_temp_c for d in dies)
        assert model.board_temp_c > 25.0
        assert model.sensor_temp_c > 25.0

    def test_sensor_lags_board(self):
        model = self._model()
        model.step(1.0, [545.0] * self.N, 13.8)
        # after a single 1 s tick the sensor (tau 3 s) trails the board
        assert model.sensor_temp_c < model.board_temp_c

    def test_equilibrium_approached(self):
        model = self._model()
        freqs = [545.0] * self.N
        for _ in range(20_000):  # ~5.5 h simulated
            model.step(1.0, freqs, 13.8)
        params = phys.calibrate_bm1362_s19jpro()
        total = sum(
            params.chip_power(f, 13.8, t)
            for f, t in zip(freqs, model.chip_die_temps())
        )
        theta = model.thermal.theta_board_air(100.0)
        equilibrium = 25.0 + total * theta
        assert abs(model.board_temp_c - equilibrium) < 0.5

    def test_preheat_anchor_band(self):
        # [A2-TWIN-SPEC] anchor: preheat 38 -> 55 C in ~2 min at nameplate.
        # Full 126-chip board starting from a 38 C soak.
        model = self._model()
        model.board_temp_c = 38.0
        model.sensor_temp_c = 38.0
        for _ in range(120):
            model.step(1.0, [545.0] * self.N, 13.8)
        assert 53.0 <= model.board_temp_c <= 57.0

    def test_lower_pwm_runs_hotter(self):
        full = self._model(pwm=100.0)
        quiet = self._model(pwm=20.0)
        for _ in range(600):
            full.step(1.0, [400.0] * self.N, 13.0)
            quiet.step(1.0, [400.0] * self.N, 13.0)
        assert quiet.board_temp_c > full.board_temp_c


class TestErrorCliff:
    BIN = phys.ChipBin(
        label="test", k_per_mhz=0.8, f_cliff25_mhz=560.0,
        derate_mhz_per_c=0.5, source="[DCENT-MODEL]",
    )

    def test_below_cliff_is_quiet(self):
        assert phys.error_rate(400.0, 25.0, self.BIN) < 1e-6

    def test_above_cliff_is_saturated(self):
        assert phys.error_rate(650.0, 25.0, self.BIN) > 1 - 1e-6

    def test_at_cliff_is_half(self):
        assert phys.error_rate(560.0, 25.0, self.BIN) == pytest.approx(0.5, rel=1e-9)

    def test_temperature_pushes_chip_over_the_edge(self):
        # same 545 MHz, hotter die -> higher error rate (feedback loop)
        cold = phys.error_rate(545.0, 30.0, self.BIN)
        hot = phys.error_rate(545.0, 90.0, self.BIN)
        assert hot > cold
        # at 90 C the cliff has dropped to 560 - 0.5*65 = 527.5 < 545:
        assert hot > 0.9

    def test_braiins_bins_carry_the_anchor_spread(self):
        # [BRAIINS-AUTOTUNE] 231.7 / 232.7 / 233.2 MHz tuned-point spread
        bins = phys.braiins_tuned_bins()
        anchors = [231.7, 232.7, 233.2]
        for bin_spec, anchor in zip(bins, anchors):
            assert str(anchor) in bin_spec.source  # provenance-labeled
            assert bin_spec.f_cliff25_mhz > anchor  # spread + margin

    def test_default_bins_deterministic(self):
        a = phys.default_nameplate_bins(8)
        b = phys.default_nameplate_bins(8)
        assert [c.f_cliff25_mhz for c in a] == [c.f_cliff25_mhz for c in b]

    def test_error_rates_spread_with_bins(self):
        bins = [
            phys.ChipBin("a", 0.8, 500.0, 0.5, "[DCENT-MODEL]"),
            phys.ChipBin("b", 0.8, 600.0, 0.5, "[DCENT-MODEL]"),
        ]
        f = 545.0
        assert phys.error_rate(f, 25.0, bins[0]) > phys.error_rate(f, 25.0, bins[1])


class TestThermalFeedbackIntoCliff:
    def test_full_loop_frequency_to_temperature_to_errors(self):
        """The loop the twin exists for: raise f -> physics raises T ->
        error cliff bites a chip whose bin was fine at the old f/T.

        Full 126-chip board, warm ambient (45 C), nameplate 545 MHz, bins
        centered 575 MHz @25 C with 0.5 MHz/C derate: cool die is quiet,
        hot die crosses the cliff (leakage feedback settles ~100 C)."""
        power = phys.calibrate_bm1362_s19jpro()
        model = phys.BoardThermalModel(
            n_chips=126,
            thermal=phys.default_s19jpro_thermal_params(ambient_c=45.0),
            power=power,
            pwm_percent=100.0,
        )
        bin_spec = phys.ChipBin("ch", 0.8, 575.0, 0.5, "[DCENT-MODEL]")
        # cold-start sanity: at 25 C die the same chip is quiet
        assert phys.error_rate(545.0, 25.0, bin_spec) < 1e-6
        for _ in range(1800):  # 30 min
            model.step(1.0, [545.0] * 126, 13.8)
        hot = model.chip_die_temps()[0]
        assert hot > 80.0, "expected the warm-ambient full-board point to bite"
        rate = phys.error_rate(545.0, hot, bin_spec)
        assert rate > 0.5, "cliff must engage once the die heats past the bin"

    def test_leakage_runaway_is_clamped_not_overflowing(self):
        """A config past the thermal edge (nameplate power, PWM 20, hot
        ambient) must saturate at the model ceiling, not raise OverflowError
        — a real supervisor would have curtailed hash power long before."""
        power = phys.calibrate_bm1362_s19jpro()
        model = phys.BoardThermalModel(
            n_chips=126,
            thermal=phys.default_s19jpro_thermal_params(ambient_c=55.0),
            power=power,
            pwm_percent=20.0,
        )
        for _ in range(3600):  # 1 h simulated
            model.step(1.0, [545.0] * 126, 13.8)
        dies = model.chip_die_temps()
        assert all(d <= phys.MODEL_MAX_DIE_C + 1e-6 for d in dies)
        assert dies[0] == phys.MODEL_MAX_DIE_C  # hit the ceiling
