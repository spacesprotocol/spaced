use alloc::collections::btree_map::BTreeMap;
use alloc::vec::Vec;

#[cfg(feature = "bincode")]
use bincode::{Decode, Encode};
use bitcoin::{
    consensus::{Decodable, Encodable},
    opcodes::{
        all::{OP_DROP, OP_ENDIF, OP_IF},
        OP_FALSE,
    },
    script::{Instruction, Instructions, PushBytesBuf},
    Script, VarInt,
};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

use crate::{
    hasher::{KeyHasher, SpaceHash},
    opcodes::{SpaceOpcode, *},
    prepare::DataSource,
    sname::{NameLike, SName, SNameRef},
    FullSpaceOut,
};

pub const MAGIC: &[u8] = &[0xde, 0xde, 0xde, 0xde];
pub const MAGIC_LEN: usize = MAGIC.len();

pub type ScriptResult<T> = Result<T, ScriptError>;

#[derive(Clone, Debug)]
pub struct ScriptMachine {
    pub open: Option<OpOpenContext>,
    pub default_sdata: Option<Vec<u8>>,
    pub sdata: BTreeMap<u8, Vec<u8>>,
    pub reserve: bool,
}

#[derive(Clone, Debug)]
pub struct OpOpenContext {
    // Whether its attempting to open a new space or an existing one
    pub spaceout: SpaceKind,
}

#[derive(Clone, Debug)]
pub enum SpaceKind {
    /// If OP_OPEN is attempting to initiate an auction for an existing Space,
    /// a reference for the previous space is included
    ExistingSpace(FullSpaceOut),

    /// A new Space we haven't seen before
    NewSpace(SName),
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
pub struct ScriptBuilder(Vec<u8>);

pub trait SpaceScript {
    fn space_instructions(&self) -> SpaceInstructions;
}

pub struct SpaceInstructions<'a> {
    inner: Instructions<'a>,
    seen_magic: bool,
    push_len: u64,
    remaining: u64,
    next: Option<&'a [u8]>,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum SpaceInstruction<'a> {
    /// A bunch of pushed data.
    PushBytes(Vec<&'a [u8]>),
    /// Some non-push opcode.
    Op(SpaceOpcode),
}

impl ScriptMachine {
    fn op_open<T: DataSource, H: KeyHasher>(
        src: &mut T,
        stack: &mut Vec<Vec<&[u8]>>,
    ) -> crate::errors::Result<ScriptResult<OpOpenContext>> {
        let name = match stack.pop() {
            None => return Ok(Err(ScriptError::EarlyEndOfScript)),
            Some(slices) => {
                if slices.len() != 1 {
                    return Ok(Err(ScriptError::EarlyEndOfScript));
                }
                let name = SNameRef::try_from(slices[0]);
                if name.is_err() {
                    return Ok(Err(ScriptError::UnexpectedLabelCount));
                }
                let name = name.unwrap();
                if name.label_count() != 1 {
                    return Ok(Err(ScriptError::UnexpectedLabelCount));
                }
                name
            }
        };

        let spaceout = {
            let spacehash = SpaceHash::from(H::hash(name.to_bytes()));
            let existing = src.get_space_outpoint(&spacehash)?;
            match existing {
                None => SpaceKind::NewSpace(name.to_owned()),
                Some(outpoint) => SpaceKind::ExistingSpace(FullSpaceOut {
                    outpoint,
                    spaceout: src.get_spaceout(&outpoint)?.expect("spaceout exists"),
                }),
            }
        };

        let open = Ok(OpOpenContext { spaceout });
        Ok(open)
    }

    pub fn execute<T: DataSource, H: KeyHasher>(
        src: &mut T,
        script: &Script,
    ) -> crate::errors::Result<Result<Self, ScriptError>> {
        let mut machine = Self {
            open: None,
            default_sdata: None,
            sdata: Default::default(),
            reserve: false,
        };

        let mut stack = Vec::new();
        for instruction in script.space_instructions() {
            if instruction.is_err() {
                return Ok(Err(instruction.unwrap_err()));
            }
            match instruction.unwrap() {
                SpaceInstruction::PushBytes(data) => {
                    stack.push(data);
                }
                SpaceInstruction::Op(op) => {
                    match op.code {
                        OP_OPEN => {
                            let open_result = Self::op_open::<T, H>(src, &mut stack)?;
                            if open_result.is_err() {
                                return Ok(Err(open_result.unwrap_err()));
                            }

                            machine.open = Some(open_result.unwrap());
                        }
                        OP_SET => {
                            let slices = stack.pop();
                            match slices {
                                None => return Ok(Err(ScriptError::EarlyEndOfScript)),
                                Some(slices) => {
                                    if slices.len() != 1 {
                                        // Only one stack item worth of data is allowed
                                        return Ok(Err(ScriptError::TooManyItems));
                                    }
                                    let slice = slices[0];
                                    if slice.len() < 1 {
                                        return Ok(Err(ScriptError::EarlyEndOfScript));
                                    }
                                    let vout = slice[0];
                                    let data = if slice.len() > 1 {
                                        (&slice[1..]).to_vec()
                                    } else {
                                        Vec::with_capacity(0)
                                    };
                                    machine.sdata.insert(vout, data);
                                }
                            }
                        }
                        OP_SETALL => {
                            let slices = stack.pop();
                            match slices {
                                None => return Ok(Err(ScriptError::EarlyEndOfScript)),
                                Some(slices) => {
                                    if slices.len() != 1 {
                                        return Ok(Err(ScriptError::TooManyItems));
                                    }
                                    machine.default_sdata = Some(slices[0].to_vec());
                                }
                            }
                        }
                        // all reserved op codes
                        OP_RESERVED_1E..=OP_RESERVED_FF => {
                            machine.reserve = true;
                            return Ok(Ok(machine));
                        }
                        OP_PUSH => panic!("must be handled by push bytes"),
                        _ => {
                            // nop
                        }
                    }
                }
            }
        }

        Ok(Ok(machine))
    }
}

impl SpaceScript for Script {
    fn space_instructions(&self) -> SpaceInstructions {
        SpaceInstructions {
            inner: self.instructions(),
            seen_magic: false,
            push_len: 0,
            remaining: 0,
            next: None,
        }
    }
}

impl ScriptBuilder {
    pub fn new() -> Self {
        Self(Vec::new())
    }

    pub fn push_opcode(mut self, op: SpaceOpcode) -> Self {
        self.0.push(op.into());
        self
    }

    pub fn push_slice(mut self, data: &[u8]) -> Self {
        self.0.push(OP_PUSH.into());

        let varint_len = VarInt(data.len() as u64);
        self.0.reserve(varint_len.size());

        varint_len
            .consensus_encode(&mut self.0)
            .expect("should encode");

        self.0.extend_from_slice(data);
        self
    }

    pub fn to_nop_script(self) -> bitcoin::script::Builder {
        let script_len = self.0.len();
        let script_varint = VarInt(script_len as u64);
        let mut data = Vec::with_capacity(MAGIC_LEN + script_varint.size() + script_len);

        data.extend_from_slice(MAGIC);
        script_varint
            .consensus_encode(&mut data)
            .expect("should encode");

        data.extend_from_slice(self.0.as_slice());

        let mut builder = bitcoin::script::Builder::new();

        if data.len() <= bitcoin::blockdata::constants::MAX_SCRIPT_ELEMENT_SIZE {
            builder = builder
                .push_slice(
                    PushBytesBuf::try_from(data)
                        .expect("push bytes")
                        .as_push_bytes(),
                )
                .push_opcode(OP_DROP);
        } else {
            let chunks = data.chunks(bitcoin::blockdata::constants::MAX_SCRIPT_ELEMENT_SIZE);
            builder = builder.push_opcode(OP_FALSE).push_opcode(OP_IF);
            for chunk in chunks {
                builder = builder.push_slice(
                    PushBytesBuf::try_from(chunk.to_vec())
                        .expect("push bytes")
                        .as_push_bytes(),
                );
            }
            builder = builder.push_opcode(OP_ENDIF);
        }

        builder
    }
}

impl<'a> SpaceInstructions<'a> {
    #[inline(always)]
    fn next_bytes(&mut self) -> Option<Result<&'a [u8], ScriptError>> {
        if let Some(next) = self.next.take() {
            return Some(Ok(next));
        }
        while let Some(op) = self.inner.next() {
            if op.is_err() {
                return Some(Err(ScriptError::Serialization));
            }
            match op.unwrap() {
                Instruction::PushBytes(data) => {
                    let mut data = data.as_bytes();
                    if !self.seen_magic {
                        if !data.starts_with(MAGIC) {
                            return None;
                        }

                        self.seen_magic = true;

                        if data.len() < MAGIC_LEN {
                            continue;
                        }
                        data = &data[MAGIC_LEN..];

                        if let Ok(script_len) = VarInt::consensus_decode(&mut data) {
                            self.remaining = script_len.0;

                            if data.is_empty() {
                                continue;
                            }
                        } else {
                            return Some(Err(ScriptError::ExpectedValidVarInt));
                        }
                    }

                    if self.remaining == 0 {
                        return None;
                    }

                    if data.len() as u64 > self.remaining {
                        data = &data[..self.remaining as usize];
                        self.remaining = 0;
                    } else {
                        self.remaining -= data.len() as u64;
                    }
                    return Some(Ok(data));
                }
                Instruction::Op(_) => continue,
            }
        }

        if self.remaining > 0 {
            return Some(Err(ScriptError::EarlyEndOfScript));
        }
        None
    }
}

impl<'a> Iterator for SpaceInstructions<'a> {
    type Item = Result<SpaceInstruction<'a>, ScriptError>;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(bytes) = self.next_bytes() {
            if bytes.is_err() {
                return Some(Err(bytes.unwrap_err()));
            }

            let mut data = bytes.unwrap();

            if self.push_len > 0 {
                let mut slices = Vec::new();

                if data.len() as u64 > self.push_len {
                    slices.push(&data[..self.push_len as usize]);
                    self.next = Some(&data[self.push_len as usize..]);
                    self.push_len = 0;
                } else {
                    slices.push(data);
                    self.push_len -= data.len() as u64;
                }

                while self.push_len > 0 {
                    if let Some(more_bytes) = self.next_bytes() {
                        if more_bytes.is_err() {
                            return Some(Err(more_bytes.unwrap_err()));
                        }

                        let more_data = more_bytes.unwrap();
                        if more_data.len() as u64 > self.push_len {
                            slices.push(&more_data[..self.push_len as usize]);
                            self.next = Some(&more_data[self.push_len as usize..]);
                            self.push_len = 0;
                        } else {
                            slices.push(more_data);
                            self.push_len -= more_data.len() as u64;
                        }

                        continue;
                    }

                    return Some(Err(ScriptError::EarlyEndOfScript));
                }

                return Some(Ok(SpaceInstruction::PushBytes(slices)));
            }

            if data.is_empty() {
                return Some(Err(ScriptError::EarlyEndOfScript));
            }

            let op: SpaceOpcode = data[0].into();

            if op.code == OP_PUSH {
                if data.len() < 2 {
                    return Some(Err(ScriptError::EarlyEndOfScript));
                }
                data = &data[1..];

                let push_bytes_len = match VarInt::consensus_decode(&mut data)
                    .map_err(|_| ScriptError::ExpectedValidVarInt)
                {
                    Ok(b) => b,
                    Err(err) => return Some(Err(err)),
                };

                self.push_len = push_bytes_len.0;
                self.next = Some(data);
                continue;
            }

            if data.len() > 1 {
                self.next = Some(&data[1..]);
            }

            return Some(Ok(SpaceInstruction::Op(op)));
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        opcodes::{OP_OPEN, OP_RESERVED_1E},
        script::{ScriptBuilder, SpaceInstruction, SpaceInstructions},
    };

    #[test]
    fn test_builder() {
        let b = ScriptBuilder::new();
        let script = b
            .push_opcode(OP_OPEN.into())
            .push_slice("data 1".as_bytes())
            .push_slice("data 2".as_bytes())
            .push_opcode(OP_OPEN.into())
            .push_slice("data 4".repeat(4096).as_bytes())
            .push_opcode(OP_OPEN.into())
            .push_opcode(OP_RESERVED_1E.into())
            .to_nop_script();

        let iter = SpaceInstructions {
            inner: script.as_script().instructions(),
            seen_magic: false,
            push_len: 0,
            remaining: 0,
            next: None,
        };

        for instruction in iter {
            let instruction = instruction.unwrap();
            match instruction {
                SpaceInstruction::PushBytes(bytes) => {
                    for b in bytes {
                        println!("got {}", core::str::from_utf8(b).unwrap())
                    }
                }
                SpaceInstruction::Op(op) => {
                    println!("{op}");
                }
            }
        }
    }
}

/// Ways that a script might fail. Not everything is split up as
/// much as it could be; patches welcome if more detailed errors
/// would help you.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "bincode", derive(Encode, Decode))]
#[non_exhaustive]
pub enum ScriptError {
    /// Some opcode expected a parameter but it was missing or truncated.
    EarlyEndOfScript,
    Serialization,
    /// Tried to to parse a varint
    ExpectedValidVarInt,
    /// invalid/malformed during OP_OPEN
    UnexpectedLabelCount,
    TooManyItems,
    MultiOpen,
}

impl core::fmt::Display for ScriptError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        use ScriptError::*;

        match *self {
            EarlyEndOfScript => f.write_str("unexpected end of script"),
            Serialization => f.write_str("script serialization"),
            ExpectedValidVarInt => f.write_str("expected a valid varint"),
            UnexpectedLabelCount => f.write_str("unexpected label count in space name"),
            TooManyItems => f.write_str("too many items"),
            MultiOpen => f.write_str("multiple opens"),
        }
    }
}
