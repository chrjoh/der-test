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
    ContextSpecific0 = 0xA0, // hard coded to be followed by a seq not wrapped
    ContextSpecific3 = 0xA3, // hard coded to be followed by a seq not wrapped
}

impl Tag {
    /// Constructed means the value is made up of other DER elements
    /// (like a SEQUENCE, SET, or context-specific wrapper
    pub fn is_constructed(&self) -> bool {
        let byte = *self as u8;
        byte & 0x20 != 0
    }
    ///Context-specific tags are used in ASN.1 to wrap values in
    /// a specific context, often inside a SEQUENCE or CHOICE.
    pub fn is_context_specific(&self) -> bool {
        let byte = *self as u8;
        byte & 0xC0 == 0x80
    }
}

/// Converts a `Tag` into its corresponding `u8` value.
impl From<Tag> for u8 {
    fn from(tag: Tag) -> Self {
        tag as u8
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
            0xA0 => Ok(Tag::ContextSpecific0),
            0xA3 => Ok(Tag::ContextSpecific3),
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
    ContextSequence0(Vec<DecodedValue>),          // Context-specific sequence with tag 0
    ContextSequence3(Vec<DecodedValue>),          // Context-specific sequence with tag 3
    Set(Vec<DecodedValue>),                       // Set of values (unordered, sorted in DER)
    Unknown(u8, Vec<u8>),                         // Unknown tag with raw data
}
