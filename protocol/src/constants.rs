use bitcoin::{
    absolute::{Height, LockTime},
    blockdata::transaction::Version,
    hashes::Hash,
    BlockHash, Sequence,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Represents a specific point in the blockchain
/// Could be used as a general block identifier.
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ChainAnchor {
    pub hash: BlockHash,
    pub height: u32,
}

/// The number of blocks between each rollout of new spaces for auction.
pub const ROLLOUT_BLOCK_INTERVAL: u32 = 144;

/// The number of spaces released for auction at each rollout interval.
pub const ROLLOUT_BATCH_SIZE: usize = 10;

/// The duration of the auction phase in blocks.
/// After this period, the winning bidder can safely register the name.
pub const AUCTION_DURATION: u32 = 144 * 10;

/// The number of blocks by which an auction is extended
/// if a bid is placed near the end of the original auction period.
pub const AUCTION_EXTENSION_ON_BID: u32 = 144;

/// The interval, in blocks, at which space holders must renew their ownership.
/// Renewal is done by performing a transaction, which extends the space's lifetime.
pub const RENEWAL_INTERVAL: u32 = 144 * 365;

/// The transaction version used in the carried bid PSBT.
/// This must match for correct PSBT reconstruction.
pub const BID_PSBT_TX_VERSION: Version = Version::TWO;

/// The lock time for bid PSBTs.
/// This must match for correct PSBT reconstruction.
pub const BID_PSBT_TX_LOCK_TIME: LockTime = LockTime::Blocks(Height::ZERO);

/// The sequence number for bid PSBT inputs.
/// This enables Replace-By-Fee (RBF) (mainly for older Bitcoin Core versions).
/// It must match for correct PSBT reconstruction.
pub const BID_PSBT_INPUT_SEQUENCE: Sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;

impl ChainAnchor {
    pub fn new(hash: [u8; 32], height: u32) -> Self {
        Self {
            hash: BlockHash::from_byte_array(hash),
            height,
        }
    }

    // Testnet4 activation block
    pub const TESTNET4: fn() -> Self = || {
        Self::new(
            [
                0x66, 0x02, 0x57, 0xdf, 0x48, 0xcb, 0xd5, 0x82, 0xf0, 0xa8, 0x5d, 0x9e, 0xad, 0x85,
                0x3d, 0x68, 0x8f, 0x7a, 0x90, 0x0d, 0x56, 0x79, 0xe0, 0x63, 0x08, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            38_580,
        )
    };

    pub const MAINNET_ALPHA: fn() -> Self = || {
        ChainAnchor {
            hash: BlockHash::all_zeros(),
            height: 869_000,
        }
    };

    pub const MAINNET: fn() -> Self = || {
        ChainAnchor {
            hash: BlockHash::all_zeros(),
            height: 871_222,
        }
    };

    // Testnet activation block
    pub const TESTNET: fn() -> Self = || {
        Self::new(
            [
                0xb8, 0x9d, 0xd5, 0xe4, 0x5e, 0xd7, 0x0a, 0x50, 0x73, 0x25, 0x2e, 0x0f, 0x5f, 0xba,
                0x4a, 0x9e, 0xd2, 0x37, 0x73, 0x9d, 0x3b, 0x5a, 0x19, 0x58, 0x1a, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            2_865_460,
        )
    };

    // Regtest activation block
    pub const REGTEST: fn() -> Self = || {
        Self::new(
            [
                0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb,
                0x5b, 0xbf, 0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c,
                0xf1, 0x88, 0x91, 0x0f,
            ],
            0,
        )
    };
}

#[cfg(feature = "bincode")]
pub mod bincode_impl {
    use bincode::{
        config,
        de::Decoder,
        enc::Encoder,
        error::{DecodeError, EncodeError},
        Decode, Encode,
    };
    use bitcoin::{hashes::Hash, BlockHash};

    use crate::constants::ChainAnchor;

    impl Encode for ChainAnchor {
        fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
            Encode::encode(&self.hash.to_byte_array(), encoder)?;
            Encode::encode(&self.height, encoder)
        }
    }

    impl Decode for ChainAnchor {
        fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
            Ok(Self {
                hash: BlockHash::from_byte_array(Decode::decode(decoder)?),
                height: Decode::decode(decoder)?,
            })
        }
    }

    impl TryFrom<&[u8]> for ChainAnchor {
        type Error = DecodeError;
        fn try_from(value: &[u8]) -> core::result::Result<Self, Self::Error> {
            let (meta, _): (ChainAnchor, _) = bincode::decode_from_slice(value, config::standard())
                .map_err(|_| DecodeError::OtherString("could not parse chain anchor".to_owned()))?;
            Ok(meta)
        }
    }

    impl ChainAnchor {
        pub fn to_vec(&self) -> Vec<u8> {
            bincode::encode_to_vec(self, config::standard()).expect("encodes chain anchor")
        }
    }
}

impl Ord for ChainAnchor {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.height.cmp(&other.height)
    }
}

impl PartialOrd for ChainAnchor {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
