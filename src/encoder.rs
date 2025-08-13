#![allow(dead_code)]
use crate::types::*;
use num_bigint::BigInt;
use num_traits::Signed;
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

/// Encodes a BigInt as a DER-encoded INTEGER.
/// Ensures minimal encoding while preserving sign.
pub fn encode_integer(value: &BigInt) -> Vec<u8> {
    let mut bytes = value.to_signed_bytes_be();

    // Remove leading 0x00 or 0xFF bytes that are not needed
    // In DER (Distinguished Encoding Rules), integers must be
    // encoded in the shortest possible form that still
    // preserves their value and sign. This means:
    // - Positive integers must not have leading 0x00 bytes
    //   unless needed to prevent misinterpretation as negative.
    // - Negative integers must not have leading 0xFF bytes
    //   unless needed to preserve the sign.
    if (bytes[0] & 0x80 != 0 && value.is_positive())
        || (bytes[0] & 0x80 == 0 && value.is_negative())
    {
        let prefix = if value.is_positive() { 0x00 } else { 0xFF };
        bytes.insert(0, prefix);
    }

    let mut result = vec![Tag::Integer.into()];
    result.extend(encode_length(bytes.len()));
    result.extend(bytes);
    result
}

/// Encodes a boolean value as a DER-encoded BOOLEAN.
/// Uses 0xFF for true and 0x00 for false.
pub fn encode_boolean(value: bool) -> Vec<u8> {
    let mut result: Vec<u8> = vec![Tag::Boolean.into()];
    result.push(0x01);
    if value {
        result.push(0xFF);
    } else {
        result.push(0x0);
    }
    result
}

/// Encodes a bit string with a specified number of unused bits.
/// DER requires the first byte to indicate unused bits.
pub fn encode_bit_string(bits: &[u8], unused_bits: u8) -> Vec<u8> {
    let mut result = vec![Tag::BitString.into()];
    let mut content = vec![unused_bits];
    content.extend_from_slice(bits);
    result.extend(encode_length(content.len()));
    result.extend(content);
    result
}

/// Encodes a byte slice as a DER-encoded OCTET STRING.
pub fn encode_octet_string(data: &[u8]) -> Vec<u8> {
    let mut result = vec![Tag::OctetString.into()];
    result.extend(encode_length(data.len()));
    result.extend(data);
    result
}

/// Encodes a UTF-8 string as a DER-encoded UTF8String.
pub fn encode_utf8_string(data: String) -> Vec<u8> {
    let mut result = vec![Tag::Utf8String.into()];
    let bytes = data.as_bytes();
    result.extend(encode_length(bytes.len()));
    result.extend(bytes);
    result
}

/// Encodes a string as a DER-encoded PrintableString.
pub fn encode_printable_string(data: String) -> Vec<u8> {
    let mut result = vec![Tag::PrintableString.into()];
    let bytes = data.as_bytes();
    result.extend(encode_length(bytes.len()));
    result.extend(bytes);
    result
}

/// Encodes an object identifier (OID) string as a DER-encoded OBJECT IDENTIFIER.
/// Returns None if the OID is invalid.
/// This is base-128 encoding of 113549.
/// The first byte encodes:
/// The first component (parts[0]) is always 0, 1, or 2.
/// The second component (parts[1]) must be less than 40 if the first is 0 or 1,
/// but can be larger if the first is 2.
///
/// encode 1.2 ->
/// 1 * 40 + 2 = 42 → 0x2A
///
/// 0x86: 10000110 → data bits 0000110 (0x06)→ continuation
/// 0xF7: 11110111 → data bits 01110111 (0x77)→ continuation
/// 0x0D: 00001101 → data bits 00001101 (0x0D)→ last byte
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

    let mut result = vec![Tag::ObjectIdentifier.into()];
    result.extend(encode_length(encoded.len()));
    result.extend(encoded);
    Some(result)
}

/// Encodes a generalized time string in "YYYYMMDDHHMMSSZ" format.
/// Returns None if the format is invalid.
pub fn encode_generalized_time(datetime: &str) -> Option<Vec<u8>> {
    if !datetime.ends_with('Z') || datetime.len() != 15 {
        return None; // Must be in "YYYYMMDDHHMMSSZ" format
    }

    let bytes = datetime.as_bytes();
    let mut result = vec![Tag::GeneralizedTime.into()];
    result.extend(encode_length(bytes.len()));
    result.extend_from_slice(bytes);
    Some(result)
}

/// Encodes a UTC time string in "YYMMDDHHMMSSZ" format.
/// Returns None if the format is invalid.
pub fn encode_utc_time(datetime: &str) -> Option<Vec<u8>> {
    if !datetime.ends_with('Z') || datetime.len() != 13 {
        return None; // Must be in "YYMMDDHHMMSSZ" format
    }

    let bytes = datetime.as_bytes();
    let mut result = vec![Tag::UtcTime.into()];
    result.extend(encode_length(bytes.len()));
    result.extend_from_slice(bytes);
    Some(result)
}

/// Encodes a DER NULL value.
pub fn encode_null() -> Vec<u8> {
    vec![Tag::Null.into(), 0x00]
}

/// Encodes a sequence of DER-encoded elements using the SEQUENCE tag.
pub fn encode_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    encode_inner(elements, Tag::Sequence.into())
}

/// Encodes a sequence of DER-encoded elements using a context-specific tag.
pub fn encode_context_tag(tag_number: u8, elements: &[Vec<u8>]) -> Vec<u8> {
    encode_inner(elements, Tag::Context(tag_number))
}

fn encode_inner(elements: &[Vec<u8>], tag: Tag) -> Vec<u8> {
    match tag {
        Tag::Sequence | Tag::Context(_) => {}
        _ => panic!("Invalid tag for sequence encoding"),
    }

    let mut content: Vec<u8> = vec![];
    for el in elements {
        content.extend(el);
    }

    let mut result = vec![tag.into()];
    result.extend(encode_length(content.len()));
    result.extend(content);
    result
}

/// Encodes a set of DER-encoded elements using the SET tag.
/// Elements are sorted lexicographically for DER compliance.
/// In DER, elements in a SET must be sorted by their encoded byte values (lexicographically).
/// So for full DER compliance, you should sort the encoded elements before combining them:
pub fn encode_set(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut content: Vec<u8> = vec![];
    let mut sorted_elements = elements.to_vec();
    sorted_elements.sort(); // Lexicographic sort
    for el in sorted_elements {
        content.extend(el);
    }
    let mut result = vec![Tag::Set.into()];
    result.extend(encode_length(content.len()));
    result.extend(content);
    result
}

/// Converts a `DecodedValue` enum into its corresponding DER-encoded byte vector.
/// Returns `None` if the value cannot be encoded (e.g., invalid OID or time format)
pub fn create_der_from_decoded_value(value: &DecodedValue) -> Option<Vec<u8>> {
    match value {
        DecodedValue::Integer(i) => Some(encode_integer(&BigInt::from(*i))),
        DecodedValue::BigInteger(i) => Some(encode_integer(i)),
        DecodedValue::Boolean(b) => Some(encode_boolean(*b)),
        DecodedValue::Utf8String(s) => Some(encode_utf8_string(s.clone())),
        DecodedValue::PrintableString(s) => Some(encode_printable_string(s.clone())),
        DecodedValue::OctetString(data) => Some(encode_octet_string(data)),
        DecodedValue::BitString { unused_bits, data } => {
            Some(encode_bit_string(data, *unused_bits))
        }
        DecodedValue::ObjectIdentifier(oid) => encode_object_identifier(oid),
        DecodedValue::Null => Some(encode_null()),
        DecodedValue::GeneralizedTime(dt) => encode_generalized_time(dt),
        DecodedValue::UtcTime(dt) => encode_utc_time(dt),
        DecodedValue::Sequence(elements) => {
            let encoded_elements: Option<Vec<Vec<u8>>> =
                elements.iter().map(create_der_from_decoded_value).collect();
            encoded_elements.map(|els| encode_sequence(&els))
        }

        DecodedValue::Context(n, elements) => {
            let encoded_elements: Option<Vec<Vec<u8>>> =
                elements.iter().map(create_der_from_decoded_value).collect();
            encoded_elements.map(|els| encode_context_tag(*n, &els))
        }

        DecodedValue::Set(elements) => {
            let encoded_elements: Option<Vec<Vec<u8>>> =
                elements.iter().map(create_der_from_decoded_value).collect();
            encoded_elements.map(|els| encode_set(&els))
        }
        DecodedValue::Unknown(tag, data) => {
            let mut result = vec![*tag];
            result.extend(encode_length(data.len()));
            result.extend(data);
            Some(result)
        }
    }
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
        assert_eq!(
            encode_integer(&BigInt::from(300)),
            vec![Tag::Integer.into(), 0x02, 0x01, 0x2C]
        );
    }

    #[test]
    fn test_encode_integer_zero() {
        assert_eq!(
            encode_integer(&BigInt::from(0)),
            vec![Tag::Integer.into(), 0x01, 0x00]
        );
    }

    #[test]
    fn test_encode_boolean_true() {
        assert_eq!(encode_boolean(true), vec![Tag::Boolean.into(), 0x01, 0xFF]);
    }

    #[test]
    fn test_encode_boolean_false() {
        assert_eq!(encode_boolean(false), vec![Tag::Boolean.into(), 0x01, 0x00]);
    }

    #[test]
    fn test_encode_bit_string() {
        let bits = vec![0b10101010];
        assert_eq!(
            encode_bit_string(&bits, 3),
            vec![Tag::BitString.into(), 0x02, 0x03, 0b10101010]
        );
    }

    #[test]
    fn test_encode_octet_string() {
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(
            encode_octet_string(&data),
            vec![Tag::OctetString.into(), 0x04, 0xDE, 0xAD, 0xBE, 0xEF]
        );
    }

    #[test]
    fn test_encode_utf8_string() {
        let s = "hello".to_string();
        assert_eq!(
            encode_utf8_string(s),
            vec![Tag::Utf8String.into(), 0x05, b'h', b'e', b'l', b'l', b'o']
        );
    }

    #[test]
    fn test_encode_printable_string() {
        let s = "world".to_string();
        assert_eq!(
            encode_printable_string(s),
            vec![
                Tag::PrintableString.into(),
                0x05,
                b'w',
                b'o',
                b'r',
                b'l',
                b'd'
            ]
        );
    }

    #[test]
    fn test_encode_object_identifier_valid() {
        let oid = "1.2.840.113549";
        assert_eq!(
            encode_object_identifier(oid),
            Some(vec![
                Tag::ObjectIdentifier.into(),
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
                Tag::ObjectIdentifier.into(),
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
                Tag::GeneralizedTime.into(),
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
                Tag::UtcTime.into(),
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
        assert_eq!(encode_null(), vec![Tag::Null.into(), 0x00]);
    }

    #[test]
    fn test_encode_sequence() {
        let el1 = encode_integer(&BigInt::from(1));
        let el2 = encode_boolean(true);
        let seq = encode_sequence(&[el1.clone(), el2.clone()]);
        assert_eq!(seq[0], Tag::Sequence.into());
        assert!(seq.ends_with(&[0x01, 0xFF]));
    }

    #[test]
    fn test_encode_set_sorted() {
        let el1 = encode_integer(&BigInt::from(2));
        let el2 = encode_integer(&BigInt::from(1));
        let set = encode_set(&[el1, el2]);
        assert_eq!(set[0], Tag::Set.into());
    }

    #[test]
    fn test_encode_integer() {
        let value = DecodedValue::Integer(42);
        let encoded = create_der_from_decoded_value(&value).unwrap();
        assert_eq!(encoded, encode_integer(&BigInt::from(42)));
    }

    #[test]
    fn test_encode_decode_boolean_true() {
        let value = DecodedValue::Boolean(true);
        let encoded = create_der_from_decoded_value(&value).unwrap();
        assert_eq!(encoded, encode_boolean(true));
    }

    #[test]
    fn test_encode_decode_utf8_string() {
        let value = DecodedValue::Utf8String("Hello".to_string());
        let encoded = create_der_from_decoded_value(&value).unwrap();
        assert_eq!(encoded, encode_utf8_string("Hello".to_string()));
    }

    #[test]
    fn test_encode_decode_object_identifier() {
        let value = DecodedValue::ObjectIdentifier("1.2.840.113549".to_string());
        let encoded = create_der_from_decoded_value(&value).unwrap();
        let expected = encode_object_identifier("1.2.840.113549").unwrap();
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_encode_decode_sequence() {
        let value =
            DecodedValue::Sequence(vec![DecodedValue::Integer(1), DecodedValue::Boolean(false)]);
        let encoded = create_der_from_decoded_value(&value).unwrap();

        let expected = encode_sequence(&[encode_integer(&BigInt::from(1)), encode_boolean(false)]);
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_encode_set() {
        let value = DecodedValue::Set(vec![DecodedValue::Integer(2), DecodedValue::Integer(1)]);
        let encoded = create_der_from_decoded_value(&value).unwrap();

        let expected = encode_set(&[
            encode_integer(&BigInt::from(2)),
            encode_integer(&BigInt::from(1)),
        ]);
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_encode_decode_null() {
        let value = DecodedValue::Null;
        let encoded = create_der_from_decoded_value(&value).unwrap();
        assert_eq!(encoded, encode_null());
    }
}
