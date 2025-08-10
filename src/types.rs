pub const INTEGER_TAG: u8 = 0x02;
pub const OCTET_STRING_TAG: u8 = 0x04;
pub const BIT_STRING_TAG: u8 = 0x03;
pub const SEQUENCE_TAG: u8 = 0x30;
pub const OBJECT_IDENTIFIER_TAG: u8 = 0x06;
pub const SET_TAG: u8 = 0x31;
pub const BOOLEAN_TAG: u8 = 0x01;
pub const UTF8STRING_TAG: u8 = 0x0C;
pub const GENERALIZED_TIME_TAG: u8 = 0x18;
pub const UTC_TIME_TAG: u8 = 0x17;
pub const NULL_TAG: u8 = 0x05;
pub const PRINTABLE_STRING_TAG: u8 = 0x13;
pub const CONTEXT_SPECIFIC_0_TAG: u8 = 0xA0; // hard coded to be followed by a seq
pub const CONTEXT_SPECIFIC_3_TAG: u8 = 0xA3; // hard coded to be followed by a seq
pub const LONG_FORM_DECODE: u8 = 0x7F;
pub const LONG_FORM: u8 = 0x80;

#[derive(Debug, PartialEq)]
pub enum DecodedValue {
    Integer(i64),
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
//PrintableString
