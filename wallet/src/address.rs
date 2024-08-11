use core::{fmt, str::FromStr};

use bech32::{primitives::decode::SegwitHrpstringError, Hrp};
use bitcoin::blockdata::script::witness_version::WitnessVersion;
use protocol::{
    bitcoin,
    bitcoin::{
        address::{Address, ParseError},
        network::Network,
        ScriptBuf, WitnessProgram,
    },
};

#[derive(Debug, Clone)]
pub struct SpaceAddress(pub Address);

impl SpaceAddress {
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.0.script_pubkey()
    }
}

impl fmt::Display for SpaceAddress {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        // let pubkey = self.0.script_pubkey();
        // let raw_program = &pubkey.as_bytes()[2..];
        let program = self.0.witness_program().expect("p2tr address");
        let address = self.0.to_string();
        let hrp = find_bech32_prefix(&address);
        let hrp = Hrp::parse(&format!("{}s", hrp)).expect("valid hrp");

        let version = program.version().to_fe();
        let program = program.program().as_ref();

        if fmt.alternate() {
            bech32::segwit::encode_upper_to_fmt_unchecked(fmt, hrp, version, program)
        } else {
            bech32::segwit::encode_lower_to_fmt_unchecked(fmt, hrp, version, program)
        }
    }
}

impl From<Address> for SpaceAddress {
    fn from(value: Address) -> Self {
        SpaceAddress(value)
    }
}

impl FromStr for SpaceAddress {
    type Err = protocol::bitcoin::address::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // try bech32
        let bech32_prefix = find_bech32_prefix(s);
        let network = match bech32_prefix {
            // note that upper or lowercase is allowed but NOT mixed case
            "bcs" | "BCS" => Some(Network::Bitcoin),
            "tbs" | "TBS" => Some(Network::Testnet),
            "bcrts" | "BCRTS" => Some(Network::Regtest),
            _ => None,
        };

        if let Some(network) = network {
            let (_hrp, version, data) = bech32::segwit::decode(s)?;

            let version = WitnessVersion::try_from(version).expect("we know this is in range 0-16");
            let witness_program = WitnessProgram::new(version, data.as_slice())?;

            return Ok(SpaceAddress(Address::from_witness_program(
                witness_program,
                network,
            )));
        }

        Err(ParseError::Bech32(SegwitHrpstringError::NoData.into()))
    }
}

/// Extracts the bech32 prefix.
///
/// # Returns
/// The input slice if no prefix is found.
///
/// From bitcoin rust crate
fn find_bech32_prefix(bech32: &str) -> &str {
    // Split at the last occurrence of the separator character '1'.
    match bech32.rfind('1') {
        None => bech32,
        Some(sep) => bech32.split_at(sep).0,
    }
}
