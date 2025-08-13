use num_bigint::BigInt;
use std::convert::TryFrom;
pub const LONG_FORM_DECODE: u8 = 0x7F;
pub const LONG_FORM: u8 = 0x80;

/// Represents ASN.1 DER tags for various data types.
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
    Context(u8),
}

//impl Tag {
//    /// Constructed means the value is made up of other DER elements
//    /// (like a SEQUENCE, SET, or context-specific wrapper
//    /// In ASN.1 DER encoding, the constructed bit is bit 6 (value 0x20).
//    /// If this bit is set, the tag is considered constructed,
//    pub fn is_constructed(&self) -> bool {
//        let byte = *self as u8;
//        byte & 0x20 != 0
//    }
//    ///Context-specific tags are used in ASN.1 to wrap values in
//    /// a specific context, often inside a SEQUENCE or CHOICE.
//    pub fn is_context_specific(&self) -> bool {
//        let byte = *self as u8;
//        byte & 0xC0 == 0x80
//    }
//}

/// Converts a `Tag` into its corresponding `u8` value.
impl From<Tag> for u8 {
    fn from(tag: Tag) -> Self {
        match tag {
            Tag::Integer => 0x02,
            Tag::OctetString => 0x04,
            Tag::Sequence => 0x30,
            Tag::Set => 0x31,
            Tag::Boolean => 0x01,
            Tag::Utf8String => 0x0C,
            Tag::BitString => 0x03,
            Tag::ObjectIdentifier => 0x06,
            Tag::GeneralizedTime => 0x18,
            Tag::UtcTime => 0x17,
            Tag::Null => 0x05,
            Tag::PrintableString => 0x13,
            Tag::Context(n) => 0xA0 | (n & 0x1F), // context-specific constructed tag
        }
    }
}

/// Attempts to convert a `u8` value into a `Tag`.
/// Returns `Err(())` if the value does not match any known tag.
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
            b if b & 0xC0 == 0x80 && b & 0x20 != 0 => Ok(Tag::Context(b & 0x1F)),
            _ => Err(()),
        }
    }
}

/// Represents a decoded ASN.1 value in a structured form.
/// Used for converting between DER and Rust-native types.
#[derive(Debug, PartialEq)]
pub enum DecodedValue {
    Integer(i64),                                 // Small integer value
    BigInteger(BigInt),                           // Arbitrary precision integer
    Boolean(bool),                                // Boolean value
    Utf8String(String),                           // UTF-8 encoded string
    OctetString(Vec<u8>),                         // Raw byte string
    BitString { unused_bits: u8, data: Vec<u8> }, // Bit string with unused bits count
    ObjectIdentifier(String),                     // Object identifier (e.g., "1.2.840.113549")
    Null,                                         // Null value
    PrintableString(String),                      // PrintableString (subset of ASCII)
    GeneralizedTime(String),                      // GeneralizedTime in "YYYYMMDDHHMMSSZ" format
    UtcTime(String),                              // UTCTime in "YYMMDDHHMMSSZ" format
    Sequence(Vec<DecodedValue>),                  // Sequence of values
    Context(u8, Vec<DecodedValue>),
    Set(Vec<DecodedValue>), // Set of values (unordered, sorted in DER)
    Unknown(u8, Vec<u8>),   // Unknown tag with raw data
}
// allowed tags, in Context
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextTag {
    Tag0 = 0xA0,
    Tag1 = 0xA1,
    Tag2 = 0xA2,
    Tag3 = 0xA3,
    Tag4 = 0xA4,
    Tag5 = 0xA5,
    Tag6 = 0xA6,
    Tag7 = 0xA7,
    Tag8 = 0xA8,
    Tag9 = 0xA9,
    Tag10 = 0xAA,
    Tag11 = 0xAB,
    Tag12 = 0xAC,
    Tag13 = 0xAD,
    Tag14 = 0xAE,
    Tag15 = 0xAF,
    Tag16 = 0xB0,
    Tag17 = 0xB1,
    Tag18 = 0xB2,
    Tag19 = 0xB3,
    Tag20 = 0xB4,
    Tag21 = 0xB5,
    Tag22 = 0xB6,
    Tag23 = 0xB7,
    Tag24 = 0xB8,
    Tag25 = 0xB9,
    Tag26 = 0xBA,
    Tag27 = 0xBB,
    Tag28 = 0xBC,
    Tag29 = 0xBD,
    Tag30 = 0xBE,
    Tag31 = 0xBF,
}
