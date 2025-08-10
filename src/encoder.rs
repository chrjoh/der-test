#![allow(dead_code)]
use crate::types::*;
// Short form: If the length is less than 128, it's encoded as a single byte.
// Long form: If the length is 128 or more, it's encoded as multiple bytes:
// First byte: 0x80 | number_of_length_bytes
// Followed by: the actual length in big-endian format
// temp & 0xFF extracts the lowest byte.
// temp >>= 8 shifts right to process the next byte.
// insert(0, ...) builds the array in big-endian order.
// Example: length = 300 → len_bytes = [0x01, 0x2C] → len_indicator = 0x82 → result = [0x82, 0x01, 0x2C]
//
fn encode_length(length: usize) -> Vec<u8> {
    if length < 128 {
        vec![length as u8]
    } else {
        let mut len_bytes = vec![];
        let mut temp = length;
        while temp > 0 {
            len_bytes.insert(0, (temp & 0xFF) as u8); // temp & 0xFF extracts the lowest byte.
            temp >>= 8;
        }
        let len_indicator = LONG_FORM | (len_bytes.len() as u8);
        let mut result = vec![len_indicator];
        result.extend(len_bytes);
        result
    }
}

pub fn encode_integer(value: i64) -> Vec<u8> {
    let mut bytes = vec![];
    let mut temp = value;
    while temp != 0 {
        bytes.insert(0, (temp & 0xFF) as u8);
        temp >>= 8;
    }
    if bytes.is_empty() {
        bytes.push(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0x00); // Ensure positive integer
    }

    let mut result: Vec<u8> = vec![INTEGER_TAG];
    result.extend(encode_length(bytes.len()));
    result.extend(bytes);
    result
}

pub fn encode_boolean(value: bool) -> Vec<u8> {
    let mut result: Vec<u8> = vec![BOOLEAN_TAG];
    result.push(0x01);
    if value {
        result.push(0xFF);
    } else {
        result.push(0x0);
    }
    result
}

pub fn encode_bit_string(bits: &[u8], unused_bits: u8) -> Vec<u8> {
    let mut result = vec![BIT_STRING_TAG];
    let mut content = vec![unused_bits];
    content.extend_from_slice(bits);
    result.extend(encode_length(content.len()));
    result.extend(content);
    result
}

pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![OCTET_STRING_TAG];
    result.extend(encode_length(data.len()));
    result.extend(data);
    result
}

pub fn encode_utf8_string(data: String) -> Vec<u8> {
    let mut result = vec![UTF8STRING_TAG];
    let bytes = data.as_bytes();
    result.extend(encode_length(bytes.len()));
    result.extend(bytes);
    result
}
pub fn encode_printable_string(data: String) -> Vec<u8> {
    let mut result = vec![PRINTABLE_STRING_TAG];
    let bytes = data.as_bytes();
    result.extend(encode_length(bytes.len()));
    result.extend(bytes);
    result
}
// This is base-128 encoding of 113549.
// The first byte encodes:
// The first component (parts[0]) is always 0, 1, or 2.
// The second component (parts[1]) must be less than 40 if the first is 0 or 1,
// but can be larger if the first is 2.
//
// encode 1.2 ->
// 1 * 40 + 2 = 42 → 0x2A
//
// 0x86: 10000110 → data bits 0000110 (0x06)→ continuation
// 0xF7: 11110111 → data bits 01110111 (0x77)→ continuation
// 0x0D: 00001101 → data bits 00001101 (0x0D)→ last byte
pub fn encode_object_identifier(oid: &str) -> Option<Vec<u8>> {
    let parts: Vec<u32> = oid.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() < 2 {
        return None;
    }

    let mut encoded: Vec<u8> = Vec::new();

    // Encode first two components as a single base-128 value
    let first_value = parts[0] * 40 + parts[1];
    let mut stack = Vec::new();
    let mut value = first_value;
    stack.push((value & 0x7F) as u8);
    value >>= 7;
    while value > 0 {
        stack.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    encoded.extend(stack.iter().rev());

    // Encode remaining components
    for &part in &parts[2..] {
        let mut stack = Vec::new();
        let mut value = part;
        stack.push((value & 0x7F) as u8);
        value >>= 7;
        while value > 0 {
            stack.push(((value & 0x7F) as u8) | 0x80);
            value >>= 7;
        }
        encoded.extend(stack.iter().rev());
    }

    let mut result = vec![OBJECT_IDENTIFIER_TAG];
    result.extend(encode_length(encoded.len()));
    result.extend(encoded);
    Some(result)
}

pub fn encode_generalized_time(datetime: &str) -> Option<Vec<u8>> {
    if !datetime.ends_with('Z') || datetime.len() != 15 {
        return None; // Must be in "YYYYMMDDHHMMSSZ" format
    }

    let bytes = datetime.as_bytes();
    let mut result = vec![GENERALIZED_TIME_TAG];
    result.extend(encode_length(bytes.len()));
    result.extend_from_slice(bytes);
    Some(result)
}
pub fn encode_utc_time(datetime: &str) -> Option<Vec<u8>> {
    if !datetime.ends_with('Z') || datetime.len() != 13 {
        return None; // Must be in "YYMMDDHHMMSSZ" format
    }

    let bytes = datetime.as_bytes();
    let mut result = vec![UTC_TIME_TAG];
    result.extend(encode_length(bytes.len()));
    result.extend_from_slice(bytes);
    Some(result)
}
pub fn encode_null() -> Vec<u8> {
    vec![NULL_TAG, 0x00]
}

pub fn encode_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    encode_sequence_inner(elements, SEQUENCE_TAG)
}
pub fn encode_sequence_0_tag(elements: &[Vec<u8>]) -> Vec<u8> {
    encode_sequence_inner(elements, CONTEXT_SPECIFIC_0_TAG)
}
pub fn encode_sequence_3_tag(elements: &[Vec<u8>]) -> Vec<u8> {
    encode_sequence_inner(elements, CONTEXT_SPECIFIC_3_TAG)
}
fn encode_sequence_inner(elements: &[Vec<u8>], tag: u8) -> Vec<u8> {
    let mut content: Vec<u8> = vec![];
    for el in elements {
        content.extend(el);
    }

    let mut result = vec![tag];
    result.extend(encode_length(content.len()));
    result.extend(content);
    result
}
// In DER, elements in a SET must be sorted by their encoded byte values (lexicographically).
// So for full DER compliance, you should sort the encoded elements before combining them:
pub fn encode_set(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut content: Vec<u8> = vec![];
    let mut sorted_elements = elements.to_vec();
    sorted_elements.sort(); // Lexicographic sort
    for el in sorted_elements {
        content.extend(el);
    }
    let mut result = vec![SET_TAG];
    result.extend(encode_length(content.len()));
    result.extend(content);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_length_short() {
        assert_eq!(encode_length(127), vec![127]);
    }

    #[test]
    fn test_encode_length_long() {
        assert_eq!(encode_length(300), vec![0x82, 0x01, 0x2C]);
    }

    #[test]
    fn test_encode_integer_positive() {
        assert_eq!(encode_integer(300), vec![INTEGER_TAG, 0x02, 0x01, 0x2C]);
    }

    #[test]
    fn test_encode_integer_zero() {
        assert_eq!(encode_integer(0), vec![INTEGER_TAG, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_boolean_true() {
        assert_eq!(encode_boolean(true), vec![BOOLEAN_TAG, 0x01, 0xFF]);
    }

    #[test]
    fn test_encode_boolean_false() {
        assert_eq!(encode_boolean(false), vec![BOOLEAN_TAG, 0x01, 0x00]);
    }

    #[test]
    fn test_encode_bit_string() {
        let bits = vec![0b10101010];
        assert_eq!(
            encode_bit_string(&bits, 3),
            vec![BIT_STRING_TAG, 0x02, 0x03, 0b10101010]
        );
    }

    #[test]
    fn test_encode_octet_string() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            encode_octet_string(&data),
            vec![OCTET_STRING_TAG, 0x04, 0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn test_encode_utf8_string() {
        let s = "hello".to_string();
        assert_eq!(
            encode_utf8_string(s),
            vec![UTF8STRING_TAG, 0x05, b'h', b'e', b'l', b'l', b'o']
        );
    }

    #[test]
    fn test_encode_printable_string() {
        let s = "world".to_string();
        assert_eq!(
            encode_printable_string(s),
            vec![PRINTABLE_STRING_TAG, 0x05, b'w', b'o', b'r', b'l', b'd']
        );
    }

    #[test]
    fn test_encode_object_identifier_valid() {
        let oid = "1.2.840.113549";
        assert_eq!(
            encode_object_identifier(oid),
            Some(vec![
                OBJECT_IDENTIFIER_TAG,
                0x06,
                0x2A,
                0x86,
                0x48,
                0x86,
                0xF7,
                0x0D
            ])
        );
    }
    #[test]
    fn test_encode_big_object_identifier_valid() {
        let oid = "2.200.840.113549";
        assert_eq!(
            encode_object_identifier(oid),
            Some(vec![
                OBJECT_IDENTIFIER_TAG,
                0x07,
                0x82,
                0x18,
                0x86,
                0x48,
                0x86,
                0xF7,
                0x0D,
            ])
        );
    }
    #[test]
    fn test_encode_object_identifier_invalid() {
        assert_eq!(encode_object_identifier("1"), None);
    }

    #[test]
    fn test_encode_generalized_time_valid() {
        let dt = "20250101000000Z";
        assert_eq!(
            encode_generalized_time(dt),
            Some(vec![
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
                b'Z'
            ])
        );
    }

    #[test]
    fn test_encode_generalized_time_invalid() {
        assert_eq!(encode_generalized_time("20250101Z"), None);
    }

    #[test]
    fn test_encode_utc_time_valid() {
        let dt = "250101000000Z";
        assert_eq!(
            encode_utc_time(dt),
            Some(vec![
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
                b'Z'
            ])
        );
    }

    #[test]
    fn test_encode_utc_time_invalid() {
        assert_eq!(encode_utc_time("250101Z"), None);
    }

    #[test]
    fn test_encode_null() {
        assert_eq!(encode_null(), vec![NULL_TAG, 0x00]);
    }

    #[test]
    fn test_encode_sequence() {
        let el1 = encode_integer(1);
        let el2 = encode_boolean(true);
        let seq = encode_sequence(&[el1.clone(), el2.clone()]);
        assert_eq!(seq[0], SEQUENCE_TAG);
        assert!(seq.ends_with(&[0x01, 0xFF]));
    }

    #[test]
    fn test_encode_set_sorted() {
        let el1 = encode_integer(2);
        let el2 = encode_integer(1);
        let set = encode_set(&[el1, el2]);
        assert_eq!(set[0], SET_TAG);
    }
}
