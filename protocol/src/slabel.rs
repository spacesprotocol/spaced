#[cfg(feature = "serde")]
use alloc::string::ToString;
use alloc::{string::String, vec::Vec};
use core::{
    fmt::{Display, Formatter},
    str::FromStr,
};

#[cfg(feature = "serde")]
use serde::{de::Error as ErrorUtil, Deserialize, Deserializer, Serialize, Serializer};

use crate::errors::Error;

pub const MAX_LABEL_LEN: usize = 62;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SLabel([u8; MAX_LABEL_LEN + 1]);

#[cfg(feature = "bincode")]
pub mod bincode_impl {
    use bincode::{
        de::{read::Reader, Decoder},
        enc::Encoder,
        error::{DecodeError, EncodeError},
        impl_borrow_decode, Decode, Encode,
    };

    use super::*;

    impl Encode for SLabel {
        fn encode<E: Encoder>(&self, encoder: &mut E) -> Result<(), EncodeError> {
            // We skip encoding the length byte since bincode adds a length prefix
            // which we reuse as our length byte when decoding
            Encode::encode(&self.as_ref()[1..], encoder)
        }
    }

    impl Decode for SLabel {
        fn decode<D: Decoder>(decoder: &mut D) -> Result<Self, DecodeError> {
            let reader = decoder.reader();
            let mut buf = [0u8; MAX_LABEL_LEN + 1];

            // read bincode's length byte
            reader.read(&mut buf[..1])?;
            let len = buf[0] as usize;
            if len > MAX_LABEL_LEN {
                return Err(DecodeError::Other("length exceeds maximum for the label"));
            }
            reader.read(&mut buf[1..=len])?;
            Ok(SLabel(buf))
        }
    }

    impl_borrow_decode!(SLabel);
}

#[cfg(feature = "serde")]
impl Serialize for SLabel {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(self.to_string().as_str())
        } else {
            serializer.serialize_bytes(&self.0)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SLabel {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            SLabel::from_str(&s).map_err(|_| D::Error::custom("malformed name"))
        } else {
            let bytes: Vec<u8> = Deserialize::deserialize(deserializer)?;
            let mut buf = [0u8; MAX_LABEL_LEN + 1];
            buf.copy_from_slice(&bytes);
            Ok(SLabel(buf))
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SLabelRef<'a>(pub &'a [u8]);

impl AsRef<[u8]> for SLabel {
    fn as_ref(&self) -> &[u8] {
        let len = self.0[0] as usize;
        &self.0[..=len]
    }
}

impl<'a> AsRef<[u8]> for SLabelRef<'a> {
    fn as_ref(&self) -> &[u8] {
        let len = self.0[0] as usize;
        &self.0[..=len]
    }
}

impl FromStr for SLabel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}

impl<const N: usize> TryFrom<&[u8; N]> for SLabel {
    type Error = Error;

    fn try_from(value: &[u8; N]) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&Vec<u8>> for SLabel {
    type Error = Error;

    fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&[u8]> for SLabel {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let name_ref: SLabelRef = value.try_into()?;
        Ok(name_ref.to_owned())
    }
}

#[derive(Debug)]
pub enum NameErrorKind {
    Empty,
    ZeroLength,
    TooLong,
    EOF,
    InvalidCharacter,
    NotCanonical,
}

impl<'a> TryFrom<&'a [u8]> for SLabelRef<'a> {
    type Error = Error;

    fn try_from(value: &'a [u8]) -> Result<Self, Self::Error> {
        if value.is_empty() {
            return Err(Error::Name(NameErrorKind::Empty));
        }
        let label_len = value[0] as usize;
        if label_len == 0 {
            return Err(Error::Name(NameErrorKind::ZeroLength));
        }
        if label_len > MAX_LABEL_LEN {
            return Err(Error::Name(NameErrorKind::TooLong));
        }
        if label_len + 1 > value.len() {
            return Err(Error::Name(NameErrorKind::EOF));
        }
        let label = &value[..=label_len];
        if !label[1..]
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return Err(Error::Name(NameErrorKind::InvalidCharacter));
        }
        Ok(SLabelRef(label))
    }
}

impl TryFrom<String> for SLabel {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&str> for SLabel {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if !value.starts_with('@') {
            return Err(Error::Name(NameErrorKind::NotCanonical));
        }
        let label = &value[1..];
        if label.is_empty() {
            return Err(Error::Name(NameErrorKind::ZeroLength));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(Error::Name(NameErrorKind::TooLong));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return Err(Error::Name(NameErrorKind::InvalidCharacter));
        }
        let mut label_bytes = [0; MAX_LABEL_LEN + 1];
        label_bytes[0] = label.len() as u8;
        label_bytes[1..=label.len()].copy_from_slice(label.as_bytes());
        Ok(SLabel(label_bytes))
    }
}

impl Display for SLabel {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let label_len = self.0[0] as usize;
        let label = &self.0[1..=label_len];

        let label_str = core::str::from_utf8(label).map_err(|_| core::fmt::Error)?;
        write!(f, "@{}", label_str)
    }
}

impl Display for SLabelRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

impl SLabel {
    pub fn as_name_ref(&self) -> SLabelRef {
        SLabelRef(&self.0)
    }
}

impl SLabelRef<'_> {
    pub fn to_owned(&self) -> SLabel {
        let mut owned = SLabel([0; MAX_LABEL_LEN + 1]);
        owned.0[..self.0.len()].copy_from_slice(self.0);
        owned
    }
}

#[cfg(test)]
mod tests {
    use alloc::{borrow::ToOwned, format, string::ToString};

    use super::*;

    #[test]
    fn test_valid_label() {
        let label_str = "@example";
        let label = SLabel::try_from(label_str).unwrap();
        assert_eq!(
            label.to_string(),
            "@example",
            "Valid label should serialize correctly"
        );

        let dns_encoded = b"\x07example";
        let label = SLabel::try_from(dns_encoded).expect("valid label");
        assert_eq!(
            label.as_ref(),
            &dns_encoded[..],
            "Valid label should serialize correctly"
        );
        assert_eq!(
            label.to_string(),
            "@example",
            "Valid label should serialize correctly"
        );
    }

    #[test]
    fn test_invalid_label() {
        assert!(
            SLabel::try_from("example").is_err(),
            "Should fail if label does not start with '@'"
        );
        assert!(
            SLabel::try_from("@").is_err(),
            "Should fail if label is empty after '@'"
        );
        assert!(
            SLabel::try_from("@EXAMPLE").is_err(),
            "Should fail if label contains uppercase characters"
        );
        assert!(
            SLabel::try_from("@exampl3$").is_err(),
            "Should fail if label contains invalid characters"
        );
        assert!(
            SLabel::try_from("@example-ok").is_err(),
            "Should fail if label contains hyphens"
        );
        assert!(
            SLabel::try_from(b"\x07exam").is_err(),
            "Should fail if buffer is too short"
        );
        assert_eq!(
            SLabel::try_from(b"\x02exam").unwrap().to_string(),
            "@ex",
            "Should work"
        );
        assert_eq!(
            SLabel::try_from(b"\x02exam").unwrap().as_ref(),
            b"\x02ex",
            "Should work"
        );
    }

    #[test]
    fn test_label_length() {
        let long_label = "@".to_owned() + &"a".repeat(62);
        assert!(
            SLabel::try_from(long_label.as_str()).is_ok(),
            "Should allow label with 62 characters"
        );

        let too_long_label = "@".to_owned() + &"a".repeat(63);
        assert!(
            SLabel::try_from(too_long_label.as_str()).is_err(),
            "Should fail if label exceeds 62 characters"
        );
    }

    #[test]
    fn test_display() {
        let label_str = "@example";
        let label = SLabel::try_from(label_str).unwrap();
        assert_eq!(
            format!("{}", label),
            label_str,
            "Display should match input label"
        );
    }

    #[test]
    fn test_serialization() {
        #[cfg(feature = "serde")]
        {
            use serde_json;

            let label = SLabel::try_from("@example").unwrap();
            let serialized = serde_json::to_string(&label).unwrap();
            assert_eq!(
                serialized, "\"@example\"",
                "Serialization should produce correct JSON"
            );

            let deserialized: SLabel = serde_json::from_str(&serialized).unwrap();
            assert_eq!(
                deserialized, label,
                "Deserialization should produce the original label"
            );
        }

        #[cfg(feature = "bincode")]
        {
            use bincode::config;
            let label = SLabel::try_from("@example").unwrap();
            let serialized =
                bincode::encode_to_vec(label.clone(), config::standard()).expect("encoded");

            assert_eq!(
                serialized.len(),
                label.as_ref().len(),
                "Serialization should produce correct length"
            );
            let (deserialized, _): (SLabel, _) =
                bincode::decode_from_slice(serialized.as_slice(), config::standard())
                    .expect("deserialize");
            assert_eq!(
                deserialized, label,
                "Deserialization should produce the original label"
            );
        }
    }
}
