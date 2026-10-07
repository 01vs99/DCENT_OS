#![cfg(feature = "sim-hal")]

//! Exercise the real S9/S9i/S9j driver over the HAL recording transport.
//! Oracle: held Braiins braiins_io.rs WorkTx::send_work (423..441) and
//! WorkRxResponse::from_hw (356..366). This is a synthetic wire fixture,
//! not a captured physical share or a silicon qualification receipt.

use dcentrald_asic::drivers::{bm1387::Bm1387Driver, ChipDriver, MiningWork};
use dcentrald_hal::{fpga_chain::FpgaChain, platform::sim::TraceEvent};

#[test]
fn bm1387_beta_driver_writes_four_distinct_midstates_in_held_wire_order() {
    let driver = Bm1387Driver::new();
    let work = MiningWork {
        work_id: 0x3123,
        fpga_midstate_cnt: 2,
        version: 0x20000000,
        nbits: 0x1d00ffff,
        ntime: 0x495fab29,
        merkle_tail: [0x4b, 0x1e, 0x5e, 0x4a],
        midstates: (0..4)
            .map(|slot| std::array::from_fn(|byte| slot * 32 + byte as u8))
            .collect(),
        merkle_root: [0; 32],
        prev_block_hash: [0; 32],
    };
    for chain_id in [6, 7, 8] {
        let mut chain = FpgaChain::open_sim(chain_id).unwrap();
        assert_eq!(driver.send_work(&mut chain, &work).unwrap(), 0x3123);
        let writes: Vec<_> = chain
            .drain_sim_trace()
            .unwrap()
            .into_iter()
            .filter_map(|event| {
                if let TraceEvent::Work { chain_id, bytes } = event {
                    Some((chain_id, bytes))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].0, chain_id);
        let actual = &writes[0].1;
        // Native little-endian header stores and 16-bit extended work ID.
        assert_eq!(
            &actual[..16],
            &[
                0x8c, 0xc4, 0, 0, 0xff, 0xff, 0, 0x1d, 0x29, 0xab, 0x5f, 0x49, 0x4b, 0x1e, 0x5e,
                0x4a,
            ]
        );
        assert_eq!(actual.len(), 144);
        // Held source iterates eight words in reverse and applies host-to-BE
        // to its raw memory words. On LE ARM this reverses all 32 source bytes.
        for slot in 0..4 {
            let expected: Vec<u8> = ((slot * 32)..(slot * 32 + 32))
                .rev()
                .map(|value| value as u8)
                .collect();
            assert_eq!(&actual[16 + slot * 32..48 + slot * 32], expected);
        }
    }
}

#[test]
fn bm1387_beta_nonce_echo_keeps_full_slot_id_and_native_nonce_order() {
    let driver = Bm1387Driver::new();
    // Independent Bitcoin block-0 nonce, with synthetic FPGA metadata. The
    // nonce is intentionally not symmetric under byte swapping.
    for slot in 0..4u32 {
        let decoded = driver
            .decode_nonce(&[0x7c2bac1d, 0xa5c48c09 | (slot << 8)])
            .unwrap();
        assert_eq!(decoded.nonce, 2083236893);
        assert_eq!(decoded.work_id, 0x3123);
        assert_eq!(decoded.midstate_idx, slot as u8);
        assert_eq!(decoded.solution_id, 9);
    }
}
