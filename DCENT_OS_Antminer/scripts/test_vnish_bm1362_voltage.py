"""Reproduce vendor constants from held binaries; refuse cross-board transfer."""
import os
from pathlib import Path
import unittest

from extract_vnish_bm1362_voltage import extract, require_exact_board


class VendorVoltageTest(unittest.TestCase):
    def test_exact_held_a_and_plus_constants_and_identity_mismatch(self):
        held = Path(os.environ.get('DCENT_HELD_ASSETS', str(Path(__file__).resolve().parents[3] / 'knowledge-base')))
        for model, board, chips, chain_control, mhz, preset in (
                ('s19jpro-a', 'BHB42601', 126, True, 525, 660),
                ('s19jpro-plus', 'BHB42612', 120, False, 660, 675)):
            with self.subTest(model=model):
                info = extract(held, model)
                self.assertEqual((info['default_mv'], info['startup_mv']), (13800, 15000))
                self.assertEqual((info['minimum_mv'], info['maximum_mv']), (12000, 15000))
                self.assertEqual((info['default_mhz'], info['startup_mhz']), (mhz, 50))
                self.assertEqual(info['factory_config_voltage'], 1380)
                self.assertEqual(info['presets_at_12800mv_mhz'], [preset])
                self.assertEqual(require_exact_board(info, board, chips, chain_control), (13800, 15000))
                for wrong_board in ('BHB42603', 'BHB42631', 'BHB42651'):
                    with self.assertRaisesRegex(ValueError, 'exact board/controller'):
                        require_exact_board(info, wrong_board, 126, False)
                with self.assertRaises(ValueError):
                    require_exact_board(info, board, chips + 1, chain_control)
                with self.assertRaises(ValueError):
                    require_exact_board(info, board, chips, not chain_control)


if __name__ == '__main__':
    unittest.main()
