use protocol::bitcoin::address::{Address, ParseError, Payload};
use protocol::bitcoin::bech32::{Hrp};
use protocol::bitcoin::network::Network;
use core::str::FromStr;
use protocol::bitcoin::{bech32, ScriptBuf, WitnessProgram};
use core::fmt;
use bdk::bitcoin::bech32::primitives::decode::{SegwitHrpstringError};
use protocol::bitcoin;
use protocol::bitcoin::script::PushBytesBuf;
use bitcoin::blockdata::script::witness_version::WitnessVersion;

#[derive(Debug, Clone)]
pub struct SpaceAddress(pub Address);

impl SpaceAddress {
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.0.script_pubkey()
    }
}

impl fmt::Display for SpaceAddress {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let pubkey = self.0.script_pubkey();
        let raw_program = &pubkey.as_bytes()[2..];
        let program = WitnessProgram::new(WitnessVersion::V1, raw_program.to_vec())
            .expect("p2tr address");

        let hrp = Hrp::parse(match self.0.network() {
            Network::Bitcoin => "bcs",
            Network::Testnet | Network::Signet  => "tbs",
            Network::Regtest => "bcrts",
            _ => "tbs"
        }).expect("valid hrp");

        let version = program.version().to_fe();
        let program = program.program().as_ref();

        if fmt.alternate() {
            bech32::segwit::encode_upper_to_fmt_unchecked(fmt, &hrp, version, program)
        } else {
            bech32::segwit::encode_lower_to_fmt_unchecked(fmt, &hrp, version, program)
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
        let bech32_network = match find_bech32_prefix(s) {
            // note that upper or lowercase is allowed but NOT mixed case
            "bcs" | "BCS" => Some(Network::Bitcoin),
            "tbs" | "TBS" => Some(Network::Testnet), // this may also be signet
            "bcrts" | "BCRTS" => Some(Network::Regtest),
            _ => None,
        };
        if let Some(network) = bech32_network {
            let (_hrp, version, data) = bech32::segwit::decode(s)?;

            let version = WitnessVersion::try_from(version).expect("we know this is in range 0-16");
            let program = PushBytesBuf::try_from(data).expect("decode() guarantees valid length");
            let witness_program = WitnessProgram::new(version, program)?;

            return Ok(SpaceAddress(Address::new(network, Payload::WitnessProgram(witness_program))));
        }

        Err(ParseError::Bech32(SegwitHrpstringError::MissingWitnessVersion.into()))
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
