//! Export the actual registry through the pinned workspace dependency graph.
fn main() {
    print!(
        "{}",
        dcentrald_common::runtime_policy::board_runtime_policy_json()
    );
}
