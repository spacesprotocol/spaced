#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use bitcoin::{Amount, OutPoint};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::alloc::string::ToString;

pub type Hash = [u8; 32];

pub trait KeyHasher {
    fn hash(data: &[u8]) -> Hash;
}

#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct SpaceKey(Hash);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct BidKey(Hash);

#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct BaseHash(pub Hash);

impl BaseHash {
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut hash = [0u8; 32];
        hash.copy_from_slice(slice);
        Self(hash)
    }
}

#[derive(Copy, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct OutpointKey(Hash);

pub trait KeyHash {}
impl KeyHash for SpaceKey {}
impl KeyHash for OutpointKey {}
impl KeyHash for BidKey {}
impl KeyHash for BaseHash {}

impl From<Hash> for SpaceKey {
    fn from(mut value: Hash) -> Self {
        value[0] &= 0b0111_1111;
        value[31] &= 0b1111_1110;
        SpaceKey(value)
    }
}

impl SpaceKey {
    #[inline(always)]
    pub fn from_raw(value: Hash) -> crate::errors::Result<Self> {
        if (value[0] & 0b1000_0000) == 0 && (value[31] & 0b0000_0001) == 0 {
            return Ok(Self { 0: value });
        }
        return Err(crate::errors::Error::IO("bad space hash".to_string()));
    }

    pub fn from_slice_unchecked(slice: &[u8]) -> Self {
        let mut h = [0u8; 32];
        h.copy_from_slice(slice);
        Self(h)
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        return &self.0;
    }
}

impl From<SpaceKey> for Hash {
    fn from(value: SpaceKey) -> Self {
        value.0
    }
}

impl From<BidKey> for Hash {
    fn from(value: BidKey) -> Self {
        value.0
    }
}

impl From<OutpointKey> for Hash {
    fn from(value: OutpointKey) -> Self {
        value.0
    }
}

impl From<Hash> for BaseHash {
    fn from(value: Hash) -> Self {
        Self(value)
    }
}

impl From<BaseHash> for Hash {
    fn from(value: BaseHash) -> Self {
        value.0
    }
}

impl OutpointKey {
    pub fn from_outpoint<H: KeyHasher>(value: OutPoint) -> Self {
        let mut buffer = [0u8; 32 + 4];
        buffer[0..32].copy_from_slice(value.txid.as_ref());
        buffer[32..].copy_from_slice(&value.vout.to_be_bytes());
        let h = H::hash(&buffer);
        h.into()
    }
}

impl BidKey {
    pub fn from_bid(bid_value: Amount, mut base_hash: Hash) -> Self {
        let priority = core::cmp::min(bid_value.to_sat(), (1 << 31) - 1) as u32;
        let priority_bytes = priority.to_be_bytes();
        base_hash[..4].copy_from_slice(&priority_bytes);

        // first bit is always 1
        base_hash[0] |= 0b1000_0000;
        BidKey(base_hash)
    }

    pub fn priority(&self) -> u32 {
        let mut bytes = [0u8; 4];
        bytes.copy_from_slice(&self.0[..4]);

        // Clear the most significant bit
        bytes[0] &= 0b0111_1111;

        u32::from_be_bytes(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    #[inline(always)]
    pub fn is_valid(key: &Hash) -> bool {
        key[0] & 0b1000_0000 == 0b1000_0000
    }

    pub fn from_slice_unchecked(slice: &[u8]) -> Self {
        let mut h = [0u8; 32];
        h.copy_from_slice(slice);
        Self(h)
    }
}

impl From<Hash> for BidKey {
    fn from(mut value: Hash) -> Self {
        // First bit is always 0 and last bit is always 1
        value[0] &= 0b0111_1111;
        value[31] |= 0b0000_0001;
        BidKey(value)
    }
}

impl From<Hash> for OutpointKey {
    fn from(mut value: Hash) -> Self {
        // First bit is always 0 and last bit is always 1
        value[0] &= 0b0111_1111;
        value[31] |= 0b0000_0001;
        OutpointKey(value)
    }
}
