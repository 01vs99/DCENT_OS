//! Export the actual BoardDesc policy through the pinned workspace dependency graph.
fn main() {
    match std::env::args().nth(1).as_deref() {
        Some("json") => print!("{}", dcentrald_common::install_matrix_json()),
        Some("tsv") => print!("{}", dcentrald_common::install_matrix_tsv()),
        Some("producers") => print!(
            "{}",
            dcentrald_common::artifact_producer::artifact_producer_manifest_json()
        ),
        _ => {
            eprintln!("usage: export_install_matrix <json|tsv|producers>");
            std::process::exit(2);
        }
    }
}
