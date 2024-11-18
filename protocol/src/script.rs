use alloc::vec::Vec;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use bitcoin::{
    opcodes::all::OP_DROP,
    script,
    script::{Instruction, PushBytesBuf},
    Script,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    constants::RESERVED_SPACES,
    hasher::{KeyHasher, SpaceKey},
    prepare::DataSource,
    slabel::{SLabel, SLabelRef},
    validate::RejectParams,
    FullSpaceOut,
};

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(tag = "type", rename_all = "snake_case")
)]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[non_exhaustive]
pub enum ScriptError {
    MalformedName,
    ReservedName,
    Reject(RejectParams),
}

pub type ScriptResult<T> = Result<T, ScriptError>;

pub const OP_OPEN: u8 = 1;
pub const OP_SETFALLBACK: u8 = 2;
pub const OP_RESERVE_1: u8 = 252;
pub const OP_RESERVE_2: u8 = 253;
pub const OP_RESERVE_3: u8 = 254;
pub const OP_RESERVE_4: u8 = 255;

pub const MAGIC: &[u8] = &[0xde, 0xde, 0xde, 0xde];
pub const MAGIC_LEN: usize = MAGIC.len();

#[derive(Clone, Debug)]
pub enum OpenHistory {
    /// If OP_OPEN is attempting to initiate an auction for an existing Space,
    /// a reference for the previous space is included
    ExistingSpace(FullSpaceOut),

    /// A new Space we haven't seen before
    NewSpace(SLabel),
}

#[derive(Clone, Debug)]
pub enum SpaceScript {
    Open(OpenHistory),
    Set(Vec<u8>),
    Reserve,
}

impl SpaceScript {
    pub fn create_open(name: SLabel) -> Vec<u8> {
        let name = name.as_ref();
        let mut space_script = Vec::with_capacity(MAGIC_LEN + 1 + name.len());
        space_script.extend(MAGIC);
        space_script.push(OP_OPEN);
        space_script.extend(name);
        space_script
    }

    pub fn create_set_fallback(data: &[u8]) -> Vec<u8> {
        let mut space_script = Vec::with_capacity(MAGIC_LEN + 1 + data.len());
        space_script.extend(MAGIC);
        space_script.push(OP_SETFALLBACK);
        space_script.extend(data);
        space_script
    }

    pub fn create_reserve() -> Vec<u8> {
        let mut space_script = Vec::with_capacity(MAGIC_LEN + 1);
        space_script.extend(MAGIC);
        space_script.push(OP_RESERVE_1);
        space_script
    }

    pub fn nop_script(space_script: Vec<u8>) -> script::Builder {
        script::Builder::new()
            .push_slice(
                PushBytesBuf::try_from(space_script)
                    .expect("push bytes")
                    .as_push_bytes(),
            )
            .push_opcode(OP_DROP)
    }

    pub fn eval<T: DataSource, H: KeyHasher>(
        src: &mut T,
        script: &Script,
    ) -> crate::errors::Result<Option<ScriptResult<Self>>> {
        let space_script = Self::find_space_script(script);
        if space_script.is_none() {
            return Ok(None);
        }
        let space_script = space_script.unwrap();
        let op = space_script[0];
        let op_data = &space_script[1..];

        match op {
            OP_OPEN => {
                let open_result = Self::op_open::<T, H>(src, op_data)?;
                if open_result.is_err() {
                    return Ok(Some(Err(open_result.unwrap_err())));
                }
                Ok(Some(Ok(SpaceScript::Open(open_result.unwrap()))))
            }
            OP_SETFALLBACK => Ok(Some(Ok(SpaceScript::Set(op_data.to_vec())))),
            OP_RESERVE_1..=u8::MAX => Ok(Some(Ok(SpaceScript::Reserve))),
            _ => {
                // NOOP
                Ok(None)
            }
        }
    }

    fn op_open<T: DataSource, H: KeyHasher>(
        src: &mut T,
        op_data: &[u8],
    ) -> crate::errors::Result<ScriptResult<OpenHistory>> {
        let name = SLabelRef::try_from(op_data);
        if name.is_err() {
            return Ok(Err(ScriptError::MalformedName));
        }
        let name = name.unwrap();

        if RESERVED_SPACES
            .iter()
            .any(|reserved| *reserved == name.as_ref())
        {
            return Ok(Err(ScriptError::ReservedName));
        }

        let kind = {
            let spacehash = SpaceKey::from(H::hash(name.as_ref()));
            let existing = src.get_space_outpoint(&spacehash)?;
            match existing {
                None => OpenHistory::NewSpace(name.to_owned()),
                Some(outpoint) => OpenHistory::ExistingSpace(FullSpaceOut {
                    txid: outpoint.txid,
                    spaceout: src.get_spaceout(&outpoint)?.expect("spaceout exists"),
                }),
            }
        };
        let open = Ok(kind);
        Ok(open)
    }

    // Find the first OP_PUSH bytes in a bitcoin script prefixed with our magic
    #[inline(always)]
    fn find_space_script(script: &Script) -> Option<&[u8]> {
        // Find the first OP_PUSH bytes in a bitcoin script prefixed with our magic
        let mut space_script = None;
        for op in script.instructions() {
            if op.is_err() {
                return None;
            }
            match op.unwrap() {
                Instruction::Op(_) => continue,
                Instruction::PushBytes(push_bytes) => {
                    let mut bytes = push_bytes.as_bytes();
                    // Starts with our prefix + at least 1 additional op code byte
                    if bytes.len() < MAGIC_LEN + 1 || !bytes.starts_with(MAGIC) {
                        continue;
                    }
                    bytes = &bytes[MAGIC_LEN..];
                    space_script = Some(bytes);
                    break;
                }
            }
        }
        space_script
    }
}

impl core::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use ScriptError::*;

        match *self {
            MalformedName => f.write_str("malformed name"),
            ReservedName => f.write_str("reserved name"),
            Reject(_) => f.write_str("rejected"),
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeMap, format, string::ToString, vec::Vec};
    use core::str::FromStr;

    use bitcoin::{
        hashes::Hash as OtherHash, opcodes, script::PushBytesBuf, OutPoint, ScriptBuf, Txid,
    };

    use crate::{
        hasher::{Hash, KeyHasher, SpaceKey},
        prepare::DataSource,
        script::{OpenHistory, ScriptError, SpaceScript, MAGIC, MAGIC_LEN, OP_OPEN},
        slabel::SLabel,
        Covenant, FullSpaceOut, Space, SpaceOut,
    };

    pub struct DummySource {
        spaces: BTreeMap<SpaceKey, OutPoint>,
        spaceouts: BTreeMap<OutPoint, SpaceOut>,
    }
    impl DummySource {
        fn new() -> Self {
            let mut ds = Self {
                spaces: Default::default(),
                spaceouts: Default::default(),
            };

            for i in 0..20 {
                let name = format!("@test{}", i);
                ds.insert(FullSpaceOut {
                    txid: Txid::all_zeros(),
                    spaceout: SpaceOut {
                        n: i,
                        space: Some(Space {
                            name: SLabel::from_str(&name).unwrap(),
                            covenant: Covenant::Reserved,
                        }),
                        value: Default::default(),
                        script_pubkey: Default::default(),
                    },
                });
            }

            ds
        }

        fn insert(&mut self, space: FullSpaceOut) {
            let key = DummyHasher::hash(space.spaceout.space.as_ref().unwrap().name.as_ref());
            assert!(
                self.spaces
                    .insert(SpaceKey::from(key), space.outpoint())
                    .is_none(),
                "space already exists"
            );
            assert!(
                self.spaceouts
                    .insert(space.outpoint(), space.spaceout)
                    .is_none(),
                "outpoint already exists"
            );
        }
    }
    impl DataSource for DummySource {
        fn get_space_outpoint(
            &mut self,
            space_hash: &SpaceKey,
        ) -> crate::errors::Result<Option<OutPoint>> {
            Ok(self.spaces.get(space_hash).cloned())
        }
        fn get_spaceout(&mut self, outpoint: &OutPoint) -> crate::errors::Result<Option<SpaceOut>> {
            Ok(self.spaceouts.get(outpoint).cloned())
        }
    }

    pub struct DummyHasher;

    impl KeyHasher for DummyHasher {
        fn hash(data: &[u8]) -> Hash {
            let mut hash = [*data.last().unwrap(); 32];
            let len = data.len().min(32);
            hash[..len].copy_from_slice(&data[..len]);
            hash
        }
    }

    #[test]
    pub fn test_open_scripts() {
        let mut src = DummySource::new();

        let mut builder = ScriptBuf::new();

        // Doesn't matter just throwing some dummy script
        builder.push_slice(&[0u8; 32]);
        builder.push_opcode(opcodes::all::OP_CHECKSIG);

        // Should ignore magic without an opcode
        builder.push_slice(
            PushBytesBuf::try_from(MAGIC.to_vec())
                .expect("push bytes")
                .as_push_bytes(),
        );

        // Valid script with correct magic
        let pancake_space = SpaceScript::create_open(SLabel::from_str("@pancakes").unwrap());
        builder.push_slice(
            PushBytesBuf::try_from(pancake_space)
                .expect("push bytes")
                .as_push_bytes(),
        );
        builder.push_opcode(opcodes::all::OP_DROP);

        // Another script, ignored since it picks the first one it sees
        let example_space = SpaceScript::create_open(SLabel::from_str("@example").unwrap());
        builder.push_slice(
            PushBytesBuf::try_from(example_space)
                .expect("push bytes")
                .as_push_bytes(),
        );
        builder.push_opcode(opcodes::all::OP_DROP);

        let res = SpaceScript::eval::<_, DummyHasher>(&mut src, &builder)
            .expect("execute")
            .expect("result")
            .expect("script");

        match res {
            SpaceScript::Open(ctx) => match ctx {
                OpenHistory::NewSpace(space) => assert_eq!(space.to_string(), "@pancakes"),
                _ => panic!("unexpected space type"),
            },
            _ => panic!("unexpected op type"),
        }

        // Test with existing space
        let mut builder2 = ScriptBuf::new();
        let test_space = SpaceScript::create_open(SLabel::from_str("@test12").unwrap());
        builder2.push_slice(
            PushBytesBuf::try_from(test_space)
                .expect("push bytes")
                .as_push_bytes(),
        );
        builder2.push_opcode(opcodes::all::OP_DROP);

        let res = SpaceScript::eval::<_, DummyHasher>(&mut src, &builder2)
            .expect("execute")
            .expect("result")
            .expect("script");

        match res {
            SpaceScript::Open(ctx) => match ctx {
                OpenHistory::ExistingSpace(e) => {
                    assert_eq!(
                        e.spaceout.space.as_ref().unwrap().name.to_string(),
                        "@test12"
                    )
                }
                _ => panic!("unexpected space type"),
            },
            _ => panic!("unexpected op type"),
        }
    }

    #[test]
    fn test_open_malformed_name() {
        let mut src = DummySource::new();

        // Now try an OP_OPEN with malformed name
        let bad_name = [200u8; 60];
        let mut space_script = Vec::with_capacity(MAGIC_LEN + 1 + bad_name.len());
        space_script.extend(MAGIC);
        space_script.push(OP_OPEN);
        space_script.extend(bad_name);

        let mut builder3 = ScriptBuf::new();
        builder3.push_slice(
            PushBytesBuf::try_from(space_script)
                .expect("push bytes")
                .as_push_bytes(),
        );

        let res = SpaceScript::eval::<_, DummyHasher>(&mut src, &builder3).expect("execute");

        assert_eq!(res.unwrap().err(), Some(ScriptError::MalformedName));
    }

    #[test]
    fn test_reserve() {
        let mut src = DummySource::new();

        let mut builder = ScriptBuf::new();
        let reserve_script = SpaceScript::create_reserve();
        builder.push_slice(
            PushBytesBuf::try_from(reserve_script)
                .expect("push bytes")
                .as_push_bytes(),
        );
        builder.push_opcode(opcodes::all::OP_DROP);

        let res = SpaceScript::eval::<_, DummyHasher>(&mut src, &builder)
            .expect("execute")
            .expect("result")
            .expect("script");

        match res {
            SpaceScript::Reserve => {}
            _ => panic!("unexpected op type"),
        }
    }
}
