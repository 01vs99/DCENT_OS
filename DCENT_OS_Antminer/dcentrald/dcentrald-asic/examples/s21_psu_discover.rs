//! Offline bench card from supplied observations. No hardware/network I/O.
use dcentrald_asic::voltage_rail_adapters::S21DiscoverOnlyRail;
use dcentrald_common::voltage_rail::BenchPsuIdentity;

fn number(s: &str) -> Result<u16, String> {
    if let Some(hex) = s.strip_prefix("0x") {
        u16::from_str_radix(hex, 16).map_err(|e| e.to_string())
    } else {
        s.parse::<u16>().map_err(|e| e.to_string())
    }
}

fn run(args: &[String]) -> Result<String, String> {
    if !matches!(args.len(), 8 | 11) || args[0] != "discover-only" {
        return Err("usage: s21_psu_discover discover-only TARGET BOARD1 COUNT1 BOARD2 COUNT2 BOARD3 COUNT3 [PSU_FAMILY ADDRESS VERSION]; observations only, no live probing".into());
    }
    let boards = [
        (args[2].as_str(), number(&args[3])?),
        (args[4].as_str(), number(&args[5])?),
        (args[6].as_str(), number(&args[7])?),
    ];
    let byte =
        |s: &str| -> Result<u8, String> { u8::try_from(number(s)?).map_err(|e| e.to_string()) };
    let psu = if args.len() == 11 {
        Some(BenchPsuIdentity {
            family: &args[8],
            address_7bit: byte(&args[9])?,
            version: byte(&args[10])?,
        })
    } else {
        None
    };
    let rail = S21DiscoverOnlyRail::new(&args[1], &boards, psu, None).map_err(|e| e.to_string())?;
    let discovery = rail.discovery();
    Ok(format!("{}\nASIC={:?}; chains=3; chips/chain={}\nObserved PSU={:?} (unverified supplied observation)\n{}\nT21 APW11A tuple source: stock Zynq variant; AML wiring is not implied.",
        discovery.polarity_card, discovery.profile.asic(), discovery.profile.chips_per_chain(),
        discovery.observed_psu, discovery.voltage_ceiling))
}

fn main() {
    match run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        Ok(card) => println!("{card}"),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn invoke(s: &str) -> Result<String, String> {
        run(&s.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
    }
    #[test]
    fn bench_cli_positive_t21_and_s21plus() {
        let t21 =
            invoke("discover-only am3-t21 BHB68701 108 BHB68703 108 BHB68705 108 APW11A 0x10 66")
                .unwrap();
        assert!(t21.contains("chips/chain=108"));
        assert!(t21.contains("undriven"));
        let plus =
            invoke("discover-only amlogic-s21plus A3HB70701 55 A3HB70702 55 A3HB70703 55").unwrap();
        assert!(plus.contains("chips/chain=55"));
        assert!(plus.contains("Observed PSU=None"));
    }
    #[test]
    fn bench_cli_refuses_mutation_options_and_malformed_input() {
        for input in [
            "",
            "enable am3-t21 BHB68701 108 BHB68701 108 BHB68701 108",
            "discover-only am3-t21 BHB68701 0 BHB68701 108 BHB68701 108",
            "discover-only am3-t21 BHB68701 108 BHB68701 108 BHB68701 108 APW11 0x10 66",
            "discover-only am3-t21 BHB68701 108 BHB68701 108 BHB68701 108 APW11A 0x110 66",
            "discover-only am3-t21 BHB68701 invalid BHB68701 108 BHB68701 108",
            "discover-only am3-t21 BHB68701 108 BHB68701 108 BHB68701 108 --enable",
        ] {
            assert!(invoke(input).is_err(), "{input}");
        }
    }
}
