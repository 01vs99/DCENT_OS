//! Explicit powered native initialization followed by terminal closeout.
//! This purpose never creates a pool connection or a UART work sender.
use anyhow::Result;
use dcentrald_common::AsicProtocolIdentity;

pub(crate) const FLAG: &str = "--bm1366-native-no-work";

pub(crate) fn requested(args: &[String]) -> Result<bool> {
    if !args.iter().any(|arg| arg == FLAG) {
        return Ok(false);
    }
    anyhow::ensure!(
        args.iter().filter(|arg| arg.as_str() == FLAG).count() == 1
            && args.iter().any(|arg| arg == "--serial-mining")
            && args.iter().skip(1).filter(|arg| arg.starts_with('-')).all(|arg|
                matches!(arg.as_str(), FLAG | "--serial-mining" | "--config")),
        "{FLAG} requires --serial-mining, accepts only --config, and refuses other modes or one-shots"
    );
    Ok(true)
}

pub(super) fn admit(
    requested: bool,
    board_target: &str,
    identity: AsicProtocolIdentity,
    passthrough: bool,
) -> Result<()> {
    anyhow::ensure!(
        !requested || (!passthrough && identity == AsicProtocolIdentity::Bm1366
            && matches!(board_target, "am3-s19k" | "am3-s19xp" | "am3-s19jxp")),
        "native no-work initialization requires an exact S19k Pro, S19 XP or S19j XP native dispatch"
    );
    Ok(())
}

pub(super) async fn finish<T>(
    closeout: impl std::future::Future<Output = Result<T>>,
) -> Result<()> {
    closeout.await?;
    tracing::info!("BM1366 native initialization completed; checked terminal power cut and watchdog closeout completed; no pool or work was started");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_diagnostic_refuses_other_modes_and_one_shots() {
        let args = |tail: &[&str]| {
            std::iter::once("dcentrald")
                .chain(tail.iter().copied())
                .map(str::to_owned)
                .collect::<Vec<_>>()
        };
        assert!(!requested(&args(&[])).unwrap());
        assert!(requested(&args(&[
            FLAG,
            "--serial-mining",
            "--config",
            "/data/test.toml"
        ]))
        .unwrap());
        assert!(requested(&args(&[FLAG])).is_err());
        for extra in [
            FLAG,
            "--set-fan",
            "--safe-off",
            "--stock-fpga",
            "--allow-loud",
            "--s19k-track1-no-work",
            "--s19k-install-custody-safeoff",
        ] {
            assert!(
                requested(&args(&[FLAG, "--serial-mining", extra])).is_err(),
                "{extra}"
            );
        }
        assert!(crate::unrecognized_cli_flags(&args(&[FLAG, "--serial-mining"])).is_empty());
    }

    #[test]
    fn native_diagnostic_is_exact_model_and_owner_bound() {
        for target in ["am3-s19k", "am3-s19xp", "am3-s19jxp"] {
            assert!(admit(true, target, AsicProtocolIdentity::Bm1366, false).is_ok());
            assert!(admit(true, target, AsicProtocolIdentity::Bm1366, true).is_err());
            assert!(admit(true, target, AsicProtocolIdentity::Bm1368, false).is_err());
        }
        for target in ["am3-s19kpro", "am3-s21", "am2-s19pro", "", "am3-s19k-extra"] {
            assert!(admit(true, target, AsicProtocolIdentity::Bm1366, false).is_err());
            assert!(admit(false, target, AsicProtocolIdentity::Bm1366, false).is_ok());
        }
    }

    #[tokio::test]
    async fn no_work_completion_requires_successful_awaited_terminal_closeout() {
        let completed = std::sync::atomic::AtomicBool::new(false);
        finish(async {
            tokio::task::yield_now().await;
            completed.store(true, std::sync::atomic::Ordering::Release);
            Ok(())
        })
        .await
        .unwrap();
        assert!(completed.load(std::sync::atomic::Ordering::Acquire));
        let failure =
            finish(async { Err::<(), _>(anyhow::anyhow!("cutoff readback failed")) }).await;
        assert!(failure
            .unwrap_err()
            .to_string()
            .contains("cutoff readback failed"));
    }

    #[test]
    fn production_no_work_exit_precedes_pool_and_work_actor_construction() {
        let source = include_str!("../serial_mining.rs");
        let run = source.split("pub async fn run(&mut self)").nth(1).unwrap();
        let initialized = run.find("let published_chain_chip_count").unwrap();
        let diagnostic = run.find("if self.bm1366_native_no_work {").unwrap();
        assert!(initialized < diagnostic);
        let cutoff = run[diagnostic..]
            .find("return bm1366_native_no_work::finish(closeout_native_nopic_failure(")
            .unwrap();
        assert!(cutoff < 150);
        assert!(diagnostic < run.find("StratumRouter::new").unwrap());
        assert!(diagnostic < run.find(".spawn_serial_io(").unwrap());
        let main = include_str!("../main.rs");
        assert!(main.contains("!s19k_install_custody_safeoff && !bm1366_native_no_work"));
        let entry = main.split("fn main() -> Result<()> {").nth(1).unwrap();
        assert!(
            entry
                .find("bm1366_native_no_work::requested(&args)?")
                .unwrap()
                < entry
                    .find("s19k_arm_permanent_pdeathsig_from_env()?")
                    .unwrap()
        );
    }
}
