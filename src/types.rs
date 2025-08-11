use num_bigint::BigInt;
use std::convert::TryFrom;
pub const LONG_FORM_DECODE: u8 = 0x7F;
pub const LONG_FORM: u8 = 0x80;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tag {
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    Utf8String = 0x0C,
    PrintableString = 0x13,
    UtcTime = 0x17,
    GeneralizedTime = 0x18,
    Sequence = 0x30,
    Set = 0x31,
    ContextSpecific0 = 0xA0, // hard coded to be followed by a seq
    ContextSpecific3 = 0xA3, // hard coded to be followed by a seq
}

impl From<Tag> for u8 {
    fn from(tag: Tag) -> Self {
        tag as u8
    }
}

impl TryFrom<u8> for Tag {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Tag::Boolean),
            0x02 => Ok(Tag::Integer),
            0x03 => Ok(Tag::BitString),
            0x04 => Ok(Tag::OctetString),
            0x05 => Ok(Tag::Null),
            0x06 => Ok(Tag::ObjectIdentifier),
            0x0C => Ok(Tag::Utf8String),
            0x13 => Ok(Tag::PrintableString),
            0x17 => Ok(Tag::UtcTime),
            0x18 => Ok(Tag::GeneralizedTime),
            0x30 => Ok(Tag::Sequence),
            0x31 => Ok(Tag::Set),
            0xA0 => Ok(Tag::ContextSpecific0),
            0xA3 => Ok(Tag::ContextSpecific3),
            _ => Err(()),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DecodedValue {
    Integer(i64),
    BigInteger(BigInt),
    Boolean(bool),
    Utf8String(String),
    OctetString(Vec<u8>),
    BitString { unused_bits: u8, data: Vec<u8> },
    ObjectIdentifier(String),
    Null,
    PrintableString(String),
    GeneralizedTime(String),
    UtcTime(String),
    Sequence(Vec<DecodedValue>),
    ContextSequence0(Vec<DecodedValue>),
    ContextSequence3(Vec<DecodedValue>),
    Set(Vec<DecodedValue>),
    Unknown(u8, Vec<u8>),
}
