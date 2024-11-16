use alloc::string::String;
use core::fmt::{self, Display, Formatter};

use crate::slabel::NameErrorKind;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    TX(TXErrorKind),
    IO(String),
    Name(NameErrorKind),
}

#[derive(Debug)]
pub enum TXErrorKind {
    SpaceAlreadyExists,
    MissingAuctionedOutput,
    AuctionedOutputAlreadySpent,
    InvalidBidPSBTSignature,
    InvalidBidPSBTFormat,
}

#[derive(Debug)]
pub enum StateErrorKind {
    ExpectedSpace,
    InvalidRolloutState,
    MissingOpenTxOut,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Error::TX(kind) => write!(f, "Transaction Error: {}", kind),
            Error::IO(msg) => write!(f, "IO Error: {}", msg),
            Error::Name(kind) => write!(f, "Name Error: {}", kind),
        }
    }
}

impl Display for TXErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TXErrorKind::SpaceAlreadyExists => write!(f, "Space already exists"),
            TXErrorKind::MissingAuctionedOutput => write!(f, "Missing auctioned output"),
            TXErrorKind::AuctionedOutputAlreadySpent => write!(f, "Auctioned output already spent"),
            TXErrorKind::InvalidBidPSBTSignature => write!(f, "Invalid bid PSBT signature"),
            TXErrorKind::InvalidBidPSBTFormat => write!(f, "Invalid bid PSBT format"),
        }
    }
}

impl Display for StateErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            StateErrorKind::ExpectedSpace => write!(f, "Expected space"),
            StateErrorKind::InvalidRolloutState => write!(f, "Invalid rollout state"),
            StateErrorKind::MissingOpenTxOut => write!(f, "Missing open transaction output"),
        }
    }
}

impl Display for NameErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Malformed name")
    }
}

// Conditional compilation for the std environment
#[cfg(feature = "std")]
impl std::error::Error for Error {}

#[cfg(feature = "std")]
impl std::error::Error for TXErrorKind {}

#[cfg(feature = "std")]
impl std::error::Error for StateErrorKind {}

#[cfg(feature = "std")]
impl std::error::Error for NameErrorKind {}
