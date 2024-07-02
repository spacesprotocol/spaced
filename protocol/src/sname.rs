use alloc::string::{String};
use alloc::vec::Vec;
use core::fmt::{Display, Formatter};
use core::str::FromStr;
use crate::errors::{Error, NameErrorKind};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize, Serializer, Deserializer, de::{Error as ErrorUtil, SeqAccess, Visitor}};

pub const MAX_SPACE_LEN: usize = 255;
pub const MAX_LABEL_LEN: usize = 63;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SName([u8; MAX_SPACE_LEN]);

#[cfg(feature = "serde")]
impl Serialize for SName {
    fn serialize<S>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error>
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
struct SNameVisitorBytes;

#[cfg(feature = "serde")]
impl<'de> Visitor<'de> for SNameVisitorBytes {
    type Value = SName;

    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
        formatter.write_str("a byte array representing SNAME")
    }

    fn visit_seq<A>(self, mut seq: A) -> core::result::Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
    {
        let mut bytes = [0; MAX_SPACE_LEN];
        let mut index = 0;

        while let Some(byte) = seq.next_element()? {
            if index >= MAX_SPACE_LEN {
                return Err(serde::de::Error::invalid_length(index, &self));
            }
            bytes[index] = byte;
            index += 1;
        }

        Ok(SName(bytes))
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for SName {
    fn deserialize<D>(deserializer: D) -> core::result::Result<Self, D::Error>
        where
            D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            SName::from_str(&s).map_err(|_| D::Error::custom("malformed name"))
        } else {
            deserializer.deserialize_seq(SNameVisitorBytes)
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SNameRef<'a>(pub &'a [u8]);

pub struct LabelIterator<'a>(&'a [u8]);

impl NameLike for SName {
    fn inner_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl NameLike for SNameRef<'_> {
    fn inner_bytes(&self) -> &[u8] {
        self.0
    }
}



pub trait NameLike {
    fn inner_bytes(&self) -> &[u8];

    fn to_bytes(&self) -> &[u8] {
        let mut len = 0;
        for label in self.iter() {
            len += label.len() + 1;
        }
        len += 1; // null byte
        &self.inner_bytes()[..len]
    }

    #[inline(always)]
    fn is_single_label(&self) -> bool {
        self.label_count() == 1
    }

    fn label_count(&self) -> usize {
        let mut count = 0;
        let mut slice = &self.inner_bytes()[..];
        while !slice.is_empty() && slice[0] != 0 {
            slice = &slice[slice[0] as usize + 1..];
            count += 1;
        }
        count
    }

    #[inline(always)]
    fn iter(&self) -> LabelIterator {
        LabelIterator(&self.inner_bytes()[..])
    }
}

impl FromStr for SName {
    type Err = crate::errors::Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        s.try_into()
    }
}

impl<const N: usize> TryFrom<&[u8; N]> for SName {
    type Error = crate::errors::Error;

    fn try_from(value: &[u8; N]) -> std::result::Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}

impl TryFrom<&Vec<u8>> for SName {
    type Error = crate::errors::Error;

    fn try_from(value: &Vec<u8>) -> std::result::Result<Self, Self::Error> {
        value.as_slice().try_into()
    }
}


impl core::convert::TryFrom<&[u8]> for SName {
    type Error = crate::errors::Error;

    fn try_from(value: &[u8]) -> std::result::Result<Self, Self::Error> {
        let name_ref : SNameRef = value.try_into()?;
        Ok(name_ref.to_owned())
    }
}

impl<'a> core::convert::TryFrom<&'a [u8]> for SNameRef<'a> {
    type Error = crate::errors::Error;

    fn try_from(value: &'a [u8]) -> core::result::Result<Self, Self::Error> {
        let mut remaining = value;
        if remaining.len() == 0 || remaining.len() > MAX_SPACE_LEN {
            return Err(Error::Name(NameErrorKind::MalformedName));
        }

        let mut parsed_len = 0;
        loop {
            if remaining.is_empty() {
                return Err(Error::Name(NameErrorKind::MalformedName));
            }
            let label_len = remaining[0] as usize;
            if label_len == 0 {
                parsed_len += 1;
                break;
            }
            if label_len > MAX_LABEL_LEN || label_len + 1 > remaining.len() {
                return Err(Error::Name(NameErrorKind::MalformedName));
            }
            remaining = &remaining[label_len + 1..];
            parsed_len += label_len + 1;
        }

        Ok(SNameRef(&value[..parsed_len]))
    }
}

impl TryFrom<String> for SName {
    type Error = crate::errors::Error;

    fn try_from(value: String) -> std::result::Result<Self, Self::Error> {
        value.as_str().try_into()
    }
}

impl TryFrom<&str> for SName {
    type Error = crate::errors::Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        let (subspace, space) = value.split_once('@')
            .ok_or(Error::Name(NameErrorKind::MalformedName))?;

        if space.is_empty() || space.contains('.') {
            return Err(Error::Name(NameErrorKind::MalformedName));
        }

        let mut space_bytes = [0; MAX_SPACE_LEN];
        let mut space_len = 0;

        for label in subspace.split('.').chain(core::iter::once(space)) {
            if space_len == 0 && label.is_empty() {
                continue; // Skip initial subspace label if empty
            }

            let label_bytes = label.as_bytes();
            let label_len = label_bytes.len();

            if label_len == 0 ||
                label_len > MAX_LABEL_LEN ||
                space_len + label_len + 2 > MAX_SPACE_LEN {
                return Err(Error::Name(NameErrorKind::MalformedName));
            }

            if label.bytes().any(|b| !b.is_ascii_alphanumeric() || b.is_ascii_uppercase()) {
                return Err(Error::Name(NameErrorKind::MalformedName));
            }

            // Insert the length of the label before the label itself
            space_bytes[space_len] = label_len as u8;
            space_len += 1;

            // Copy the label into the space_bytes array
            space_bytes[space_len..space_len + label_len].copy_from_slice(label_bytes);
            space_len += label_len;
        }

        // Mark end with null byte
        space_bytes[space_len] = 0;

        Ok(SName(space_bytes))
    }
}

impl core::fmt::Display for SName {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let labels: Vec<&str> = self.iter()
            .map(|label| core::str::from_utf8(label).unwrap())
            .collect();

        let last_label = labels.last().unwrap();
        let all_but_last = &labels[..labels.len() - 1];
        write!(f, "{}@{}", all_but_last.join("."), last_label)
    }
}

impl Display for SNameRef<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self)
    }
}

impl<'a> Iterator for LabelIterator<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.0.is_empty() || self.0[0] == 0 {
            return None;
        }

        let label_len = self.0[0] as usize;
        let (label, rest) = self.0.split_at(label_len + 1);
        self.0 = rest;
        Some(&label[1..])
    }
}

impl SName {
    pub fn as_name_ref(&self) -> SNameRef {
        SNameRef(&self.0)
    }
}

impl SNameRef<'_> {
    pub fn to_owned(&self) -> SName {
        let mut owned = SName([0; MAX_SPACE_LEN]);
        owned.0[..self.0.len()].copy_from_slice(self.0);
        owned
    }
}


#[cfg(test)]
mod tests {
    use alloc::vec;
    use super::*;

    #[test]
    fn test_from_slice() {
        assert!(SName::try_from(b"").is_err(), "Should fail on empty slice");

        assert!(SName::try_from(b"\x00").is_ok(), "Should succeed on root domain (empty space)");
        assert_eq!(SName::try_from(b"\x00").unwrap().label_count(), 0, "Root domain should have 0 labels");

        assert!(SName::try_from(b"\x03bob").is_err(), "Should fail on missing null byte");

        assert!(SName::try_from(b"\x03bob\x00").is_ok(), "Should succeed on single label");
        assert_eq!(SName::try_from(b"\x03bob\x00").unwrap().label_count(), 1, "Should count single label");

        assert!(SName::try_from(b"\x03bob\x07bitcoin\x00").is_ok(), "Should succeed on two labels");
        assert_eq!(SName::try_from(b"\x03bob\x07bitcoin\x00").unwrap().label_count(), 2, "Should count two labels");

        let mut max_label = vec![0x3f]; // Length byte for 63 characters
        max_label.extend_from_slice(&vec![b'a'; 63]); // 63 'a's
        max_label.push(0x00); // Null byte
        assert!(SName::try_from(&max_label).is_ok(), "Should succeed on max length label");

        assert!(SName::try_from(b"\x03bob\x00\x03foo").is_ok(), "Should stop parsing at null byte");
        assert_eq!(SName::try_from(b"\x03bob\x00\x03foo").unwrap().label_count(), 1, "Should parse up to first null byte");

        let mut long_label = vec![0x40]; // Length byte for 64 characters
        long_label.extend_from_slice(&vec![b'b'; 64]); // 64 'b's
        long_label.push(0x00); // Null byte
        assert!(SName::try_from(&long_label).is_err(), "Should fail on label too long");

        assert!(SName::try_from(b"\x03bob\x04foo\x00").is_err(), "Should fail on incorrect label length byte");
    }

    #[test]
    fn test_iter() {
        let space = SName::try_from(b"\x03bob\x07bitcoin\x00").unwrap();
        let mut iter = space.iter();
        assert_eq!(iter.next(), Some(b"bob" as &[u8]));
        assert_eq!(iter.next(), Some(b"bitcoin" as &[u8]));
        assert_eq!(iter.next(), None);
    }


    #[test]
    fn test_from_string() {
        assert!(SName::from_str("").is_err(), "Should fail on empty string");
        assert!(SName::from_str("bitcoin").is_err(), "Should fail on missing @");
        assert!(SName::from_str("@").is_err(), "Should fail on missing subspace");
        assert!(SName::from_str("hey..bob@bitcoin").is_err(), "Should fail on empty label");

        assert!(SName::from_str("@bitcoin").is_ok(), "Should succeed on single label");
        assert!(SName::from_str("bob@bitcoin").is_ok(), "Should succeed on two label");
        assert!(SName::from_str("hello.bob@bitcoin").is_ok(), "Should succeed on multi labels");

        let mut example = SName::from_str("hello.bob@bitcoin").unwrap();
        assert_eq!(example.label_count(), 3, "Should count three labels");
        let mut iter = example.iter();
        assert_eq!(iter.next(), Some(b"hello" as &[u8]));
        assert_eq!(iter.next(), Some(b"bob" as &[u8]));
        assert_eq!(iter.next(), Some(b"bitcoin" as &[u8]));
        assert_eq!(iter.next(), None);
        assert_eq!(example.to_bytes(), b"\x05hello\x03bob\x07bitcoin\x00" as &[u8]);
    }
}
