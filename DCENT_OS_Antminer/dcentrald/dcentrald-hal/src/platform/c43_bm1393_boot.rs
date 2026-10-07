//! C43 idle boot uses only reset assertion, fixed PIC off and then quiet PWM.
//! Source operations are the existing C43 transport; this owner admits no work.
use super::*;

pub struct C43BootParked<R: C43Registers> {
    _registers: Arc<R>,
    _transport: Option<Arc<C43Transport<R>>>,
    chains: Vec<u8>,
    pwm_word: u32,
}
impl<R: C43Registers> C43BootParked<R> {
    pub fn present_chains(&self) -> &[u8] {
        &self.chains
    }
    pub fn quiet_pwm_word(&self) -> u32 {
        self.pwm_word
    }
}

/// Called only by the standalone boot command, after its exact target check.
/// The native constructor independently checks current-boot C43 fabric identity.
pub async fn park_boot_source(deadline: Instant) -> Result<C43BootParked<C43NativeMmio>, String> {
    park_registers(C43NativeMmio::open().await?, deadline).await
}

async fn park_registers<R: C43Registers>(
    registers: Arc<R>,
    deadline: Instant,
) -> Result<C43BootParked<R>, String> {
    // Detaching a cancelled caller retains the entire cut sequence. In
    // particular it cannot stop between the first and last present PIC.
    tokio::spawn(async move {
        let reader = registers.clone();
        let chains = tokio::task::spawn_blocking(move || {
            if Instant::now() >= deadline {
                return Err("C43 boot deadline elapsed before observation".to_owned());
            }
            let presence = reader.read(reg::HASH_ON_PLUG.byte_offset)?;
            let chains = (0..16)
                .filter(|chain| reg::hash_on_plug_populated(presence, *chain))
                .collect::<Vec<u8>>();
            if chains.len() > 3 {
                return Err("C43 boot population exceeds exact carrier".into());
            }
            Ok(chains)
        })
        .await
        .map_err(|e| format!("C43 boot presence worker: {e}"))??;
        let transport = if chains.is_empty() {
            None
        } else {
            let reader = registers.clone();
            let selected = chains.clone();
            let owner = tokio::task::spawn_blocking(move || C43Transport::new(reader, selected))
                .await
                .map_err(|e| format!("C43 boot owner worker: {e}"))??;
            let cut = owner.terminal_cut().await;
            if !cut.completed() {
                return Err(format!(
                    "C43 boot reset/PIC off incomplete: {:?}",
                    cut.errors()
                ));
            }
            Some(owner)
        };
        let reader = registers.clone();
        let expected_chains = chains.clone();
        let pwm_word = tokio::task::spawn_blocking(move || {
            if Instant::now() >= deadline {
                return Err("C43 boot deadline elapsed after cutoff".to_owned());
            }
            // Recheck the complete observed presence before quieting, including
            // an empty carrier. No normal transport is created for zero chains.
            let presence = reader.read(reg::HASH_ON_PLUG.byte_offset)?;
            let current = (0..16)
                .filter(|chain| reg::hash_on_plug_populated(presence, *chain))
                .collect::<Vec<u8>>();
            if current != expected_chains {
                return Err("C43 boot presence changed during cutoff".into());
            }
            // Original set_PWM1981a: floor(50*30/100), floor(50*70/100).
            let word = 0x000f_0023;
            reader.write(reg::FAN_CONTROL.byte_offset, word)?;
            let observed = reader.read(reg::FAN_CONTROL.byte_offset)?;
            if observed != word || Instant::now() >= deadline {
                return Err("C43 boot quiet PWM missing or completed late".into());
            }
            Ok(observed)
        })
        .await
        .map_err(|e| format!("C43 boot quiet worker: {e}"))??;
        Ok(C43BootParked {
            _registers: registers,
            _transport: transport,
            chains,
            pwm_word,
        })
    })
    .await
    .map_err(|e| format!("C43 retained boot sequence: {e}"))?
}

#[cfg(test)]
#[path = "c43_bm1393_boot_tests.rs"]
mod tests;
