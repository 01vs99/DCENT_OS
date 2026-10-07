//! Completeness check for the behavioral spine. The shell runner separately
//! inventories and executes every exact test named here; this check prevents a
//! newly promoted Beta row from silently escaping that blocking job.
#![cfg(feature = "sim-hal")]

use dcentrald_common::{BoardDesc, ReleaseChannel};
use std::collections::BTreeSet;

fn inventory(source: &str) -> Result<BTreeSet<&str>, String> {
    let (_, tail) = source
        .split_once("done <<'ROWS'\n")
        .ok_or("missing row table")?;
    let (table, _) = tail
        .split_once("\nROWS\n")
        .ok_or("unterminated row table")?;
    let mut rows = BTreeSet::new();
    let mut tests = BTreeSet::new();
    for line in table.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.len() != 3
            || !matches!(
                fields[1],
                "chain-owner" | "full-coordinator" | "adapter-owner"
            )
            || !fields[2].contains("::")
        {
            return Err(format!("invalid row: {line}"));
        }
        if !rows.insert(fields[0]) || !tests.insert(fields[2]) {
            return Err(format!("duplicate row or shared exact test: {line}"));
        }
    }
    Ok(rows)
}

#[test]
fn every_beta_row_has_its_own_blocking_native_positive_path() {
    let script = include_str!("../../../scripts/run_native_spine_tests.sh");
    let expected: BTreeSet<_> = BoardDesc::all_registered()
        .iter()
        .filter(|board| board.release_channel == ReleaseChannel::Beta)
        .map(|board| board.board_target)
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(
        inventory(script).unwrap(),
        expected,
        "each Beta row needs a distinct executable init/work/nonce/independent-submit test"
    );
}

#[test]
fn malformed_duplicate_and_shared_test_rows_are_rejected() {
    for rows in [
        "a chain-owner m::a\na chain-owner m::b",
        "a chain-owner m::a\nb chain-owner m::a",
        "a untested m::a",
        "a chain-owner",
        "a chain-owner unqualified",
    ] {
        assert!(inventory(&format!("done <<'ROWS'\n{rows}\nROWS\n")).is_err());
    }
    assert!(inventory("no table").is_err());
    assert!(inventory("done <<'ROWS'\na chain-owner m::a").is_err());
    assert_eq!(
        inventory("done <<'ROWS'\na chain-owner m::a\nROWS\n").unwrap(),
        BTreeSet::from(["a"])
    );
}
