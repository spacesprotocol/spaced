#[derive(Copy, Clone, PartialEq, Ord, PartialOrd, Eq, Debug)]
pub struct SpaceOpcode {
    pub code: u8,
}

impl From<u8> for SpaceOpcode {
    fn from(value: u8) -> Self {
        return SpaceOpcode { code: value };
    }
}

impl From<SpaceOpcode> for u8 {
    fn from(value: SpaceOpcode) -> Self {
        value.code
    }
}

macro_rules! define_space_opcodes {
    ($($op:ident => $val:expr, $doc:expr);*) => {
        $(
            #[doc = $doc]
            pub const $op: u8 = $val;
        )*

        impl core::fmt::Display for SpaceOpcode {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                 match *self {
                   $(
                        SpaceOpcode { code: $op } => core::fmt::Display::fmt(stringify!($op), f),
                    )+
                }
            }
        }
    }
}

define_space_opcodes! {
    OP_PUSH        => 0x00, "Reads varint bytes as N; push the next N bytes as an array onto the stack.";
    OP_OPEN        => 0x01, "Pops a space encoded name off the stack; initiates the auction.";
    OP_SET         => 0x02, "Pops encoded space element from the stack; associates this data with the space being transferred.";
    OP_SETALL      => 0x03, "Pops encoded space records as a single element off the stack; \
    associates it with all spaces being transferred.";
    OP_NOP_4       => 0x04, "Does nothing.";
    OP_NOP_5       => 0x05, "Does nothing.";
    OP_NOP_6       => 0x06, "Does nothing.";
    OP_NOP_7       => 0x07, "Does nothing.";
    OP_NOP_8       => 0x08, "Does nothing.";
    OP_NOP_9       => 0x09, "Does nothing.";
    OP_NOP_A       => 0x0A, "Does nothing.";
    OP_NOP_B       => 0x0B, "Does nothing.";
    OP_NOP_C       => 0x0C, "Does nothing.";
    OP_NOP_D       => 0x0D, "Does nothing.";
    OP_NOP_E       => 0x0E, "Does nothing.";
    OP_NOP_F       => 0x0F, "Does nothing.";
    OP_NOP_10      => 0x10, "Does nothing.";
    OP_NOP_11      => 0x11, "Does nothing.";
    OP_NOP_12      => 0x12, "Does nothing.";
    OP_NOP_13      => 0x13, "Does nothing.";
    OP_NOP_14      => 0x14, "Does nothing.";
    OP_NOP_15      => 0x15, "Does nothing.";
    OP_NOP_16      => 0x16, "Does nothing.";
    OP_NOP_17      => 0x17, "Does nothing.";
    OP_NOP_18      => 0x18, "Does nothing.";
    OP_NOP_19      => 0x19, "Does nothing.";
    OP_NOP_1A      => 0x1A, "Does nothing.";
    OP_NOP_1B      => 0x1B, "Does nothing.";
    OP_NOP_1C      => 0x1C, "Does nothing.";
    OP_NOP_1D      => 0x1D, "Does nothing.";
    OP_RESERVED_1E => 0x1E, "Reserved op code.";
    OP_RESERVED_1F => 0x1F, "Reserved op code.";
    OP_RESERVED_20 => 0x20, "Reserved op code.";
    OP_RESERVED_21 => 0x21, "Reserved op code.";
    OP_RESERVED_22 => 0x22, "Reserved op code.";
    OP_RESERVED_23 => 0x23, "Reserved op code.";
    OP_RESERVED_24 => 0x24, "Reserved op code.";
    OP_RESERVED_25 => 0x25, "Reserved op code.";
    OP_RESERVED_26 => 0x26, "Reserved op code.";
    OP_RESERVED_27 => 0x27, "Reserved op code.";
    OP_RESERVED_28 => 0x28, "Reserved op code.";
    OP_RESERVED_29 => 0x29, "Reserved op code.";
    OP_RESERVED_2A => 0x2A, "Reserved op code.";
    OP_RESERVED_2B => 0x2B, "Reserved op code.";
    OP_RESERVED_2C => 0x2C, "Reserved op code.";
    OP_RESERVED_2D => 0x2D, "Reserved op code.";
    OP_RESERVED_2E => 0x2E, "Reserved op code.";
    OP_RESERVED_2F => 0x2F, "Reserved op code.";
    OP_RESERVED_30 => 0x30, "Reserved op code.";
    OP_RESERVED_31 => 0x31, "Reserved op code.";
    OP_RESERVED_32 => 0x32, "Reserved op code.";
    OP_RESERVED_33 => 0x33, "Reserved op code.";
    OP_RESERVED_34 => 0x34, "Reserved op code.";
    OP_RESERVED_35 => 0x35, "Reserved op code.";
    OP_RESERVED_36 => 0x36, "Reserved op code.";
    OP_RESERVED_37 => 0x37, "Reserved op code.";
    OP_RESERVED_38 => 0x38, "Reserved op code.";
    OP_RESERVED_39 => 0x39, "Reserved op code.";
    OP_RESERVED_3A => 0x3A, "Reserved op code.";
    OP_RESERVED_3B => 0x3B, "Reserved op code.";
    OP_RESERVED_3C => 0x3C, "Reserved op code.";
    OP_RESERVED_3D => 0x3D, "Reserved op code.";
    OP_RESERVED_3E => 0x3E, "Reserved op code.";
    OP_RESERVED_3F => 0x3F, "Reserved op code.";
    OP_RESERVED_40 => 0x40, "Reserved op code.";
    OP_RESERVED_41 => 0x41, "Reserved op code.";
    OP_RESERVED_42 => 0x42, "Reserved op code.";
    OP_RESERVED_43 => 0x43, "Reserved op code.";
    OP_RESERVED_44 => 0x44, "Reserved op code.";
    OP_RESERVED_45 => 0x45, "Reserved op code.";
    OP_RESERVED_46 => 0x46, "Reserved op code.";
    OP_RESERVED_47 => 0x47, "Reserved op code.";
    OP_RESERVED_48 => 0x48, "Reserved op code.";
    OP_RESERVED_49 => 0x49, "Reserved op code.";
    OP_RESERVED_4A => 0x4A, "Reserved op code.";
    OP_RESERVED_4B => 0x4B, "Reserved op code.";
    OP_RESERVED_4C => 0x4C, "Reserved op code.";
    OP_RESERVED_4D => 0x4D, "Reserved op code.";
    OP_RESERVED_4E => 0x4E, "Reserved op code.";
    OP_RESERVED_4F => 0x4F, "Reserved op code.";
    OP_RESERVED_50 => 0x50, "Reserved op code.";
    OP_RESERVED_51 => 0x51, "Reserved op code.";
    OP_RESERVED_52 => 0x52, "Reserved op code.";
    OP_RESERVED_53 => 0x53, "Reserved op code.";
    OP_RESERVED_54 => 0x54, "Reserved op code.";
    OP_RESERVED_55 => 0x55, "Reserved op code.";
    OP_RESERVED_56 => 0x56, "Reserved op code.";
    OP_RESERVED_57 => 0x57, "Reserved op code.";
    OP_RESERVED_58 => 0x58, "Reserved op code.";
    OP_RESERVED_59 => 0x59, "Reserved op code.";
    OP_RESERVED_5A => 0x5A, "Reserved op code.";
    OP_RESERVED_5B => 0x5B, "Reserved op code.";
    OP_RESERVED_5C => 0x5C, "Reserved op code.";
    OP_RESERVED_5D => 0x5D, "Reserved op code.";
    OP_RESERVED_5E => 0x5E, "Reserved op code.";
    OP_RESERVED_5F => 0x5F, "Reserved op code.";
    OP_RESERVED_60 => 0x60, "Reserved op code.";
    OP_RESERVED_61 => 0x61, "Reserved op code.";
    OP_RESERVED_62 => 0x62, "Reserved op code.";
    OP_RESERVED_63 => 0x63, "Reserved op code.";
    OP_RESERVED_64 => 0x64, "Reserved op code.";
    OP_RESERVED_65 => 0x65, "Reserved op code.";
    OP_RESERVED_66 => 0x66, "Reserved op code.";
    OP_RESERVED_67 => 0x67, "Reserved op code.";
    OP_RESERVED_68 => 0x68, "Reserved op code.";
    OP_RESERVED_69 => 0x69, "Reserved op code.";
    OP_RESERVED_6A => 0x6A, "Reserved op code.";
    OP_RESERVED_6B => 0x6B, "Reserved op code.";
    OP_RESERVED_6C => 0x6C, "Reserved op code.";
    OP_RESERVED_6D => 0x6D, "Reserved op code.";
    OP_RESERVED_6E => 0x6E, "Reserved op code.";
    OP_RESERVED_6F => 0x6F, "Reserved op code.";
    OP_RESERVED_70 => 0x70, "Reserved op code.";
    OP_RESERVED_71 => 0x71, "Reserved op code.";
    OP_RESERVED_72 => 0x72, "Reserved op code.";
    OP_RESERVED_73 => 0x73, "Reserved op code.";
    OP_RESERVED_74 => 0x74, "Reserved op code.";
    OP_RESERVED_75 => 0x75, "Reserved op code.";
    OP_RESERVED_76 => 0x76, "Reserved op code.";
    OP_RESERVED_77 => 0x77, "Reserved op code.";
    OP_RESERVED_78 => 0x78, "Reserved op code.";
    OP_RESERVED_79 => 0x79, "Reserved op code.";
    OP_RESERVED_7A => 0x7A, "Reserved op code.";
    OP_RESERVED_7B => 0x7B, "Reserved op code.";
    OP_RESERVED_7C => 0x7C, "Reserved op code.";
    OP_RESERVED_7D => 0x7D, "Reserved op code.";
    OP_RESERVED_7E => 0x7E, "Reserved op code.";
    OP_RESERVED_7F => 0x7F, "Reserved op code.";
    OP_RESERVED_80 => 0x80, "Reserved op code.";
    OP_RESERVED_81 => 0x81, "Reserved op code.";
    OP_RESERVED_82 => 0x82, "Reserved op code.";
    OP_RESERVED_83 => 0x83, "Reserved op code.";
    OP_RESERVED_84 => 0x84, "Reserved op code.";
    OP_RESERVED_85 => 0x85, "Reserved op code.";
    OP_RESERVED_86 => 0x86, "Reserved op code.";
    OP_RESERVED_87 => 0x87, "Reserved op code.";
    OP_RESERVED_88 => 0x88, "Reserved op code.";
    OP_RESERVED_89 => 0x89, "Reserved op code.";
    OP_RESERVED_8A => 0x8A, "Reserved op code.";
    OP_RESERVED_8B => 0x8B, "Reserved op code.";
    OP_RESERVED_8C => 0x8C, "Reserved op code.";
    OP_RESERVED_8D => 0x8D, "Reserved op code.";
    OP_RESERVED_8E => 0x8E, "Reserved op code.";
    OP_RESERVED_8F => 0x8F, "Reserved op code.";
    OP_RESERVED_90 => 0x90, "Reserved op code.";
    OP_RESERVED_91 => 0x91, "Reserved op code.";
    OP_RESERVED_92 => 0x92, "Reserved op code.";
    OP_RESERVED_93 => 0x93, "Reserved op code.";
    OP_RESERVED_94 => 0x94, "Reserved op code.";
    OP_RESERVED_95 => 0x95, "Reserved op code.";
    OP_RESERVED_96 => 0x96, "Reserved op code.";
    OP_RESERVED_97 => 0x97, "Reserved op code.";
    OP_RESERVED_98 => 0x98, "Reserved op code.";
    OP_RESERVED_99 => 0x99, "Reserved op code.";
    OP_RESERVED_9A => 0x9A, "Reserved op code.";
    OP_RESERVED_9B => 0x9B, "Reserved op code.";
    OP_RESERVED_9C => 0x9C, "Reserved op code.";
    OP_RESERVED_9D => 0x9D, "Reserved op code.";
    OP_RESERVED_9E => 0x9E, "Reserved op code.";
    OP_RESERVED_9F => 0x9F, "Reserved op code.";
    OP_RESERVED_A0 => 0xA0, "Reserved op code.";
    OP_RESERVED_A1 => 0xA1, "Reserved op code.";
    OP_RESERVED_A2 => 0xA2, "Reserved op code.";
    OP_RESERVED_A3 => 0xA3, "Reserved op code.";
    OP_RESERVED_A4 => 0xA4, "Reserved op code.";
    OP_RESERVED_A5 => 0xA5, "Reserved op code.";
    OP_RESERVED_A6 => 0xA6, "Reserved op code.";
    OP_RESERVED_A7 => 0xA7, "Reserved op code.";
    OP_RESERVED_A8 => 0xA8, "Reserved op code.";
    OP_RESERVED_A9 => 0xA9, "Reserved op code.";
    OP_RESERVED_AA => 0xAA, "Reserved op code.";
    OP_RESERVED_AB => 0xAB, "Reserved op code.";
    OP_RESERVED_AC => 0xAC, "Reserved op code.";
    OP_RESERVED_AD => 0xAD, "Reserved op code.";
    OP_RESERVED_AE => 0xAE, "Reserved op code.";
    OP_RESERVED_AF => 0xAF, "Reserved op code.";
    OP_RESERVED_B0 => 0xB0, "Reserved op code.";
    OP_RESERVED_B1 => 0xB1, "Reserved op code.";
    OP_RESERVED_B2 => 0xB2, "Reserved op code.";
    OP_RESERVED_B3 => 0xB3, "Reserved op code.";
    OP_RESERVED_B4 => 0xB4, "Reserved op code.";
    OP_RESERVED_B5 => 0xB5, "Reserved op code.";
    OP_RESERVED_B6 => 0xB6, "Reserved op code.";
    OP_RESERVED_B7 => 0xB7, "Reserved op code.";
    OP_RESERVED_B8 => 0xB8, "Reserved op code.";
    OP_RESERVED_B9 => 0xB9, "Reserved op code.";
    OP_RESERVED_BA => 0xBA, "Reserved op code.";
    OP_RESERVED_BB => 0xBB, "Reserved op code.";
    OP_RESERVED_BC => 0xBC, "Reserved op code.";
    OP_RESERVED_BD => 0xBD, "Reserved op code.";
    OP_RESERVED_BE => 0xBE, "Reserved op code.";
    OP_RESERVED_BF => 0xBF, "Reserved op code.";
    OP_RESERVED_C0 => 0xC0, "Reserved op code.";
    OP_RESERVED_C1 => 0xC1, "Reserved op code.";
    OP_RESERVED_C2 => 0xC2, "Reserved op code.";
    OP_RESERVED_C3 => 0xC3, "Reserved op code.";
    OP_RESERVED_C4 => 0xC4, "Reserved op code.";
    OP_RESERVED_C5 => 0xC5, "Reserved op code.";
    OP_RESERVED_C6 => 0xC6, "Reserved op code.";
    OP_RESERVED_C7 => 0xC7, "Reserved op code.";
    OP_RESERVED_C8 => 0xC8, "Reserved op code.";
    OP_RESERVED_C9 => 0xC9, "Reserved op code.";
    OP_RESERVED_CA => 0xCA, "Reserved op code.";
    OP_RESERVED_CB => 0xCB, "Reserved op code.";
    OP_RESERVED_CC => 0xCC, "Reserved op code.";
    OP_RESERVED_CD => 0xCD, "Reserved op code.";
    OP_RESERVED_CE => 0xCE, "Reserved op code.";
    OP_RESERVED_CF => 0xCF, "Reserved op code.";
    OP_RESERVED_D0 => 0xD0, "Reserved op code.";
    OP_RESERVED_D1 => 0xD1, "Reserved op code.";
    OP_RESERVED_D2 => 0xD2, "Reserved op code.";
    OP_RESERVED_D3 => 0xD3, "Reserved op code.";
    OP_RESERVED_D4 => 0xD4, "Reserved op code.";
    OP_RESERVED_D5 => 0xD5, "Reserved op code.";
    OP_RESERVED_D6 => 0xD6, "Reserved op code.";
    OP_RESERVED_D7 => 0xD7, "Reserved op code.";
    OP_RESERVED_D8 => 0xD8, "Reserved op code.";
    OP_RESERVED_D9 => 0xD9, "Reserved op code.";
    OP_RESERVED_DA => 0xDA, "Reserved op code.";
    OP_RESERVED_DB => 0xDB, "Reserved op code.";
    OP_RESERVED_DC => 0xDC, "Reserved op code.";
    OP_RESERVED_DD => 0xDD, "Reserved op code.";
    OP_RESERVED_DE => 0xDE, "Reserved op code.";
    OP_RESERVED_DF => 0xDF, "Reserved op code.";
    OP_RESERVED_E0 => 0xE0, "Reserved op code.";
    OP_RESERVED_E1 => 0xE1, "Reserved op code.";
    OP_RESERVED_E2 => 0xE2, "Reserved op code.";
    OP_RESERVED_E3 => 0xE3, "Reserved op code.";
    OP_RESERVED_E4 => 0xE4, "Reserved op code.";
    OP_RESERVED_E5 => 0xE5, "Reserved op code.";
    OP_RESERVED_E6 => 0xE6, "Reserved op code.";
    OP_RESERVED_E7 => 0xE7, "Reserved op code.";
    OP_RESERVED_E8 => 0xE8, "Reserved op code.";
    OP_RESERVED_E9 => 0xE9, "Reserved op code.";
    OP_RESERVED_EA => 0xEA, "Reserved op code.";
    OP_RESERVED_EB => 0xEB, "Reserved op code.";
    OP_RESERVED_EC => 0xEC, "Reserved op code.";
    OP_RESERVED_ED => 0xED, "Reserved op code.";
    OP_RESERVED_EE => 0xEE, "Reserved op code.";
    OP_RESERVED_EF => 0xEF, "Reserved op code.";
    OP_RESERVED_F0 => 0xF0, "Reserved op code.";
    OP_RESERVED_F1 => 0xF1, "Reserved op code.";
    OP_RESERVED_F2 => 0xF2, "Reserved op code.";
    OP_RESERVED_F3 => 0xF3, "Reserved op code.";
    OP_RESERVED_F4 => 0xF4, "Reserved op code.";
    OP_RESERVED_F5 => 0xF5, "Reserved op code.";
    OP_RESERVED_F6 => 0xF6, "Reserved op code.";
    OP_RESERVED_F7 => 0xF7, "Reserved op code.";
    OP_RESERVED_F8 => 0xF8, "Reserved op code.";
    OP_RESERVED_F9 => 0xF9, "Reserved op code.";
    OP_RESERVED_FA => 0xFA, "Reserved op code.";
    OP_RESERVED_FB => 0xFB, "Reserved op code.";
    OP_RESERVED_FC => 0xFC, "Reserved op code.";
    OP_RESERVED_FD => 0xFD, "Reserved op code.";
    OP_RESERVED_FE => 0xFE, "Reserved op code.";
    OP_RESERVED_FF => 0xFF, "Reserved op code."
}
