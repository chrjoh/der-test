#![allow(dead_code)]
use crate::types::*;

//encodeing
// 0x80 = binary 10000000
// 0x80 | 2 = 0x82 → means "length is encoded in 2 bytes"
// decoding
// 0x7F = binary 01111111
// first & 0x7F removes the high bit and gives you the number of length bytes.
// 0x82 & 0x7F = 0x02 → means "length is encoded in 2 bytes"
//
//  i.e if the array starts with 30 82 01 F4
// 0x30 is the tag for a SEQUENCE.
// 0x82 means the length is in long form, and the next 2 bytes (0x01 0xF4) encode the length.
// 0x01F4 = 500, so the sequence contains 500 bytes of data after the length field.
// [82 01 F4]
// First iteration: length = (0 << 8) | 0x01 = 1
// Second iteration: length = (1 << 8) | 0xF4 = 256 | 244 = 500
fn decode_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }

    let first = data[0];
    if first & LONG_FORM == 0 {
        // Short form
        Some((first as usize, 1))
    } else {
        // Long form
        let num_bytes = (first & LONG_FORM_DECODE) as usize;
        if data.len() < 1 + num_bytes {
            return None;
        }
        let mut length = 0;
        for i in 0..num_bytes {
            length = (length << 8) | data[1 + i] as usize;
        }
        Some((length, 1 + num_bytes))
    }
}
fn decode_integer_value(bytes: &[u8]) -> Option<DecodedValue> {
    let mut value: i64 = 0;
    for &b in bytes {
        value = (value << 8) | b as i64;
    }
    Some(DecodedValue::Integer(value))
}

fn decode_boolean_value(bytes: &[u8]) -> Option<DecodedValue> {
    if bytes.len() != 1 {
        return None;
    }
    let value = bytes[0] != 0x00;
    Some(DecodedValue::Boolean(value))
}

fn decode_octet_string_value(bytes: &[u8]) -> Option<DecodedValue> {
    Some(DecodedValue::OctetString(bytes.to_vec()))
}

fn decode_utf8_string_value(bytes: &[u8]) -> Option<DecodedValue> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Some(DecodedValue::Utf8String(s.to_string())),
        Err(_) => None, // Invalid UTF-8
    }
}
fn decode_printable_string_value(bytes: &[u8]) -> Option<DecodedValue> {
    match std::str::from_utf8(bytes) {
        Ok(s) => Some(DecodedValue::PrintableString(s.to_string())),
        Err(_) => None,
    }
}
fn decode_bit_string_value(bytes: &[u8]) -> Option<DecodedValue> {
    if bytes.is_empty() {
        return None;
    }

    let unused_bits = bytes[0];
    let bit_data = bytes[1..].to_vec();
    Some(DecodedValue::BitString {
        unused_bits,
        data: bit_data,
    })
}
// 128 decoding of first byte is need to handle 2.200
// to handle 2.200 for example 128 encoding is needed
// first_byte=40×first+second
// This is because the first component is limited to values 0, 1, or 2, and the second component can vary.
// If value < 40: ->  0 * 40 + value = value
// If value < 80: -> 1 * 40 + (value - 40) = value
// else -> 2 * 40 + (value - 80) = value
//
// value to get: 113549
// Start with value = 0
// value = (0 << 7) | 0x06 = 6
// value = (6 << 7) | 0x77 = 845
// value = (845 << 7) | 0x0D = 113549
//
// 6 = 00000110
// Shift left by 7 bits:(This means we add 7 zeros to the right)
// 00000110 << 7 = 0011000000000
//
pub fn decode_object_identifier_value(bytes: &[u8]) -> Option<DecodedValue> {
    if bytes.is_empty() {
        return None;
    }

    let mut parts = Vec::new();
    let mut value: u32 = 0;
    let mut is_initial_oid_part = true;

    for &byte in bytes {
        value = (value << 7) | (byte & 0x7F) as u32;
        if byte & 0x80 == 0 {
            // this indicate the end of the first 128-bit encoded value and give
            if is_initial_oid_part {
                // Decode first two components from combined value
                let (f, s) = match value {
                    v if v < 40 => (0, v),
                    v if v < 80 => (1, v - 40),
                    v => (2, v - 80),
                };
                parts.push(f);
                parts.push(s);
                is_initial_oid_part = false;
            } else {
                parts.push(value);
            }
            value = 0;
        }
    }

    if value != 0 {
        return None; // Incomplete encoding
    }

    let oid_string = parts
        .iter()
        .map(|n| n.to_string())
        .collect::<Vec<_>>()
        .join(".");
    Some(DecodedValue::ObjectIdentifier(oid_string))
}

fn decode_generalized_time_value(bytes: &[u8]) -> Option<DecodedValue> {
    let s = std::str::from_utf8(bytes).ok()?;
    if s.len() != 15 || !s.ends_with('Z') {
        return None;
    }

    Some(DecodedValue::GeneralizedTime(s.to_string()))
}
fn decode_utc_time_value(bytes: &[u8]) -> Option<DecodedValue> {
    let s = std::str::from_utf8(bytes).ok()?;
    if s.len() != 13 || !s.ends_with('Z') {
        return None;
    }

    Some(DecodedValue::UtcTime(s.to_string()))
}
fn decode_null_value(bytes: &[u8]) -> Option<DecodedValue> {
    if bytes.is_empty() {
        Some(DecodedValue::Null)
    } else {
        None // NULL must have zero-length content
    }
}

fn decode_sequence_with_variant<F>(bytes: &[u8], wrap: F) -> Option<DecodedValue>
where
    F: Fn(Vec<DecodedValue>) -> DecodedValue,
{
    let mut elements = vec![];
    let mut cursor = 0;
    while cursor < bytes.len() {
        let (element, consumed) = decode_element(&bytes[cursor..])?;
        elements.push(element);
        cursor += consumed;
    }
    Some(wrap(elements))
}

fn decode_set_value(bytes: &[u8]) -> Option<DecodedValue> {
    let mut elements = vec![];
    let mut cursor = 0;
    while cursor < bytes.len() {
        let (element, consumed) = decode_element(&bytes[cursor..])?;
        elements.push(element);
        cursor += consumed;
    }
    Some(DecodedValue::Set(elements))
}

fn decode_element(data: &[u8]) -> Option<(DecodedValue, usize)> {
    if data.is_empty() {
        return None;
    }

    let tag = data[0];
    let (length, len_len) = decode_length(&data[1..])?;
    let start = 1 + len_len;
    let end = start + length;
    if end > data.len() {
        return None;
    }

    let value_bytes = &data[start..end];

    let decoded = match tag {
        INTEGER_TAG => decode_integer_value(value_bytes),
        OCTET_STRING_TAG => decode_octet_string_value(value_bytes),
        CONTEXT_SPECIFIC_0_TAG => {
            decode_sequence_with_variant(value_bytes, DecodedValue::ContextSequence0)
        }
        CONTEXT_SPECIFIC_3_TAG => {
            decode_sequence_with_variant(value_bytes, DecodedValue::ContextSequence3)
        }
        SEQUENCE_TAG => decode_sequence_with_variant(value_bytes, DecodedValue::Sequence),
        SET_TAG => decode_set_value(value_bytes),
        BOOLEAN_TAG => decode_boolean_value(value_bytes),
        UTF8STRING_TAG => decode_utf8_string_value(value_bytes),
        BIT_STRING_TAG => decode_bit_string_value(value_bytes),
        OBJECT_IDENTIFIER_TAG => decode_object_identifier_value(value_bytes),
        GENERALIZED_TIME_TAG => decode_generalized_time_value(value_bytes),
        UTC_TIME_TAG => decode_utc_time_value(value_bytes),
        NULL_TAG => decode_null_value(value_bytes),
        PRINTABLE_STRING_TAG => decode_printable_string_value(value_bytes),
        _ => Some(DecodedValue::Unknown(tag, value_bytes.to_vec())),
    }?;

    Some((decoded, end))
}

pub fn decode(data: Vec<u8>) -> Result<DecodedValue, String> {
    match decode_element(&data) {
        Some((value, _)) => Ok(value),
        None => Err("Failed to decode DER structure".to_string()),
    }
}

pub fn print_decoded_value(value: &DecodedValue, indent: usize) {
    let indent_str = " ".repeat(indent);

    match value {
        DecodedValue::Integer(i) => println!("{indent_str}Integer({})", i),
        DecodedValue::Boolean(b) => println!("{indent_str}Boolean({})", b),
        DecodedValue::Utf8String(s) => println!("{indent_str}Utf8String({})", s),
        DecodedValue::PrintableString(s) => println!("{indent_str}PrintableString({})", s),
        DecodedValue::GeneralizedTime(s) => println!("{indent_str}GeneralizedTime({})", s),
        DecodedValue::UtcTime(s) => println!("{indent_str}UtcTime({})", s),
        DecodedValue::ObjectIdentifier(oid) => {
            println!("{indent_str}ObjectIdentifier({})", oid)
        }
        DecodedValue::Null => println!("{indent_str}Null"),

        DecodedValue::OctetString(data) => {
            println!("{indent_str}OctetString [");
            print_vec_u8(data, indent + 4);
            println!("{indent_str}]");
        }

        DecodedValue::BitString { unused_bits, data } => {
            println!("{indent_str}BitString {{");
            println!("{indent_str}    unused_bits: {},", unused_bits);
            println!("{indent_str}    data: [");
            print_vec_u8(data, indent + 8);
            println!("{indent_str}    ]");
            println!("{indent_str}}}");
        }

        DecodedValue::Unknown(tag, data) => {
            println!("{indent_str}Unknown(tag: {}, data: [", tag);
            print_vec_u8(data, indent + 4);
            println!("{indent_str}])");
        }

        DecodedValue::Sequence(seq) => {
            println!("{indent_str}Sequence [");
            for item in seq {
                print_decoded_value(item, indent + 4);
            }
            println!("{indent_str}]");
        }
        DecodedValue::ContextSequence0(seq) => {
            println!("{indent_str}Sequence0 [");
            for item in seq {
                print_decoded_value(item, indent + 4);
            }
            println!("{indent_str}]");
        }
        DecodedValue::ContextSequence3(seq) => {
            println!("{indent_str}Sequence3 [");
            for item in seq {
                print_decoded_value(item, indent + 4);
            }
            println!("{indent_str}]");
        }

        DecodedValue::Set(set) => {
            println!("{indent_str}Set [");
            for item in set {
                print_decoded_value(item, indent + 4);
            }
            println!("{indent_str}]");
        }
    }
}

fn print_vec_u8(data: &[u8], indent: usize) {
    let indent_str = " ".repeat(indent);
    for (i, byte) in data.iter().enumerate() {
        if i % 16 == 0 {
            print!("{indent_str}");
        }
        print!("{:02X} ", byte);
        if i % 16 == 15 || i == data.len() - 1 {
            println!();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_length_short() {
        assert_eq!(decode_length(&[0x7F]), Some((127, 1)));
    }

    #[test]
    fn test_decode_length_long() {
        assert_eq!(decode_length(&[0x82, 0x01, 0xF4]), Some((500, 3)));
    }

    #[test]
    fn test_decode_integer_value() {
        let encoded = vec![INTEGER_TAG, 0x02, 0x01, 0x2C];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::Integer(300));
    }

    #[test]
    fn test_decode_boolean_true() {
        let encoded = vec![BOOLEAN_TAG, 0x01, 0xFF];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::Boolean(true));
    }

    #[test]
    fn test_decode_boolean_false() {
        let encoded = vec![BOOLEAN_TAG, 0x01, 0x00];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::Boolean(false));
    }

    #[test]
    fn test_decode_octet_string() {
        let encoded = vec![OCTET_STRING_TAG, 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let decoded = decode(encoded).unwrap();
        assert_eq!(
            decoded,
            DecodedValue::OctetString(vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
    }

    #[test]
    fn test_decode_utf8_string() {
        let encoded = vec![UTF8STRING_TAG, 0x05, b'h', b'e', b'l', b'l', b'o'];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::Utf8String("hello".to_string()));
    }

    #[test]
    fn test_decode_printable_string() {
        let encoded = vec![PRINTABLE_STRING_TAG, 0x05, b'w', b'o', b'r', b'l', b'd'];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::PrintableString("world".to_string()));
    }

    #[test]
    fn test_decode_bit_string() {
        let encoded = vec![BIT_STRING_TAG, 0x02, 0x03, 0b10101010];
        let decoded = decode(encoded).unwrap();
        assert_eq!(
            decoded,
            DecodedValue::BitString {
                unused_bits: 3,
                data: vec![0b10101010]
            }
        );
    }

    #[test]
    fn test_decode_object_identifier() {
        let encoded = vec![
            OBJECT_IDENTIFIER_TAG,
            0x06,
            0x2A,
            0x86,
            0x48,
            0x86,
            0xF7,
            0x0D,
        ];
        let decoded = decode(encoded).unwrap();
        assert_eq!(
            decoded,
            DecodedValue::ObjectIdentifier("1.2.840.113549".to_string())
        );
    }

    #[test]
    fn test_decode_big_object_identifier() {
        let encoded = vec![
            OBJECT_IDENTIFIER_TAG,
            0x07,
            0x82,
            0x18,
            0x86,
            0x48,
            0x86,
            0xF7,
            0x0D,
        ];
        let decoded = decode(encoded).unwrap();
        assert_eq!(
            decoded,
            DecodedValue::ObjectIdentifier("2.200.840.113549".to_string())
        );
    }
    #[test]
    fn test_decode_generalized_time() {
        let encoded = vec![
            GENERALIZED_TIME_TAG,
            0x0F,
            b'2',
            b'0',
            b'2',
            b'5',
            b'0',
            b'1',
            b'0',
            b'1',
            b'0',
            b'0',
            b'0',
            b'0',
            b'0',
            b'0',
            b'Z',
        ];
        let decoded = decode(encoded).unwrap();
        assert_eq!(
            decoded,
            DecodedValue::GeneralizedTime("20250101000000Z".to_string())
        );
    }

    #[test]
    fn test_decode_utc_time() {
        let encoded = vec![
            UTC_TIME_TAG,
            0x0D,
            b'2',
            b'5',
            b'0',
            b'1',
            b'0',
            b'1',
            b'0',
            b'0',
            b'0',
            b'0',
            b'0',
            b'0',
            b'Z',
        ];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::UtcTime("250101000000Z".to_string()));
    }

    #[test]
    fn test_decode_null() {
        let encoded = vec![NULL_TAG, 0x00];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::Null);
    }

    #[test]
    fn test_decode_sequence() {
        let el1 = vec![INTEGER_TAG, 0x01, 0x01];
        let el2 = vec![BOOLEAN_TAG, 0x01, 0xFF];
        let content = [el1.clone(), el2.clone()].concat();
        let encoded = vec![SEQUENCE_TAG, content.len() as u8];
        let mut full = encoded.clone();
        full.extend(content);
        let decoded = decode(full).unwrap();
        assert_eq!(
            decoded,
            DecodedValue::Sequence(vec![DecodedValue::Integer(1), DecodedValue::Boolean(true)])
        );
    }

    #[test]
    fn test_decode_set() {
        let el1 = vec![INTEGER_TAG, 0x01, 0x02];
        let el2 = vec![INTEGER_TAG, 0x01, 0x01];
        let content = [el1.clone(), el2.clone()].concat();
        let encoded = vec![SET_TAG, content.len() as u8];
        let mut full = encoded.clone();
        full.extend(content);
        let decoded = decode(full).unwrap();
        assert_eq!(
            decoded,
            DecodedValue::Set(vec![DecodedValue::Integer(2), DecodedValue::Integer(1)])
        );
    }
}
