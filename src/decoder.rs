#![allow(dead_code)]
use crate::types::*;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::collections::HashMap;
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
    // Interpret as signed big-endian
    let bigint = BigInt::from_signed_bytes_be(bytes);

    // Try converting to i64 if possible
    if let Some(value) = bigint.to_i64() {
        Some(DecodedValue::Integer(value))
    } else {
        Some(DecodedValue::BigInteger(bigint))
    }
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

    let tag_byte = data[0];
    let (length, len_len) = decode_length(&data[1..])?;
    let start = 1 + len_len;
    let end = start + length;
    if end > data.len() {
        return None;
    }

    let value_bytes = &data[start..end];
    let tag = Tag::try_from(tag_byte);

    let decoded = match tag {
        Ok(Tag::Integer) => decode_integer_value(value_bytes),
        Ok(Tag::OctetString) => decode_octet_string_value(value_bytes),
        Ok(Tag::ContextSpecific0) => {
            decode_sequence_with_variant(value_bytes, DecodedValue::ContextSequence0)
        }
        Ok(Tag::ContextSpecific3) => {
            decode_sequence_with_variant(value_bytes, DecodedValue::ContextSequence3)
        }
        Ok(Tag::Sequence) => decode_sequence_with_variant(value_bytes, DecodedValue::Sequence),
        Ok(Tag::Set) => decode_set_value(value_bytes),
        Ok(Tag::Boolean) => decode_boolean_value(value_bytes),
        Ok(Tag::Utf8String) => decode_utf8_string_value(value_bytes),
        Ok(Tag::BitString) => decode_bit_string_value(value_bytes),
        Ok(Tag::ObjectIdentifier) => decode_object_identifier_value(value_bytes),
        Ok(Tag::GeneralizedTime) => decode_generalized_time_value(value_bytes),
        Ok(Tag::UtcTime) => decode_utc_time_value(value_bytes),
        Ok(Tag::Null) => decode_null_value(value_bytes),
        Ok(Tag::PrintableString) => decode_printable_string_value(value_bytes),
        _ => Some(DecodedValue::Unknown(tag_byte, value_bytes.to_vec())),
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
    let oid_map = get_oid_map();
    print_decoded_value_private(value, indent, &oid_map);
}

fn print_decoded_value_private(value: &DecodedValue, indent: usize, oid_map: &HashMap<&str, &str>) {
    let indent_str = " ".repeat(indent);

    match value {
        DecodedValue::Integer(i) => println!("{indent_str}Integer({})", i),
        DecodedValue::BigInteger(i) => {
            println!("{indent_str}BigInteger({})", format_bigint_as_hex(i))
        }
        DecodedValue::Boolean(b) => println!("{indent_str}Boolean({})", b),
        DecodedValue::Utf8String(s) => println!("{indent_str}Utf8String({})", s),
        DecodedValue::PrintableString(s) => println!("{indent_str}PrintableString({})", s),
        DecodedValue::GeneralizedTime(s) => println!("{indent_str}GeneralizedTime({})", s),
        DecodedValue::UtcTime(s) => println!("{indent_str}UtcTime({})", s),
        DecodedValue::ObjectIdentifier(oid) => {
            let oid_name = oid_map.get(oid.as_str()).unwrap_or(&"not_found_in_oid_map");
            println!("{indent_str}ObjectIdentifier({} = {})", oid, oid_name)
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
                print_decoded_value_private(item, indent + 4, oid_map);
            }
            println!("{indent_str}]");
        }
        DecodedValue::ContextSequence0(seq) => {
            println!("{indent_str}Sequence0 [");
            for item in seq {
                print_decoded_value_private(item, indent + 4, oid_map);
            }
            println!("{indent_str}]");
        }
        DecodedValue::ContextSequence3(seq) => {
            println!("{indent_str}Sequence3 [");
            for item in seq {
                print_decoded_value_private(item, indent + 4, oid_map);
            }
            println!("{indent_str}]");
        }

        DecodedValue::Set(set) => {
            println!("{indent_str}Set [");
            for item in set {
                print_decoded_value_private(item, indent + 4, oid_map);
            }
            println!("{indent_str}]");
        }
    }
}

fn format_bigint_as_hex(i: &BigInt) -> String {
    let bytes = i.to_signed_bytes_be(); // Big-endian byte array
    bytes
        .iter()
        .map(|b| format!("{:02X}", b)) // Format each byte as two-digit hex
        .collect::<Vec<_>>()
        .join(":")
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

pub fn get_oid_map() -> HashMap<&'static str, &'static str> {
    let mut oid_map = HashMap::new();

    // Subject and Issuer fields
    oid_map.insert("2.5.4.3", "commonName");
    oid_map.insert("2.5.4.6", "countryName");
    oid_map.insert("2.5.4.10", "organizationName");
    oid_map.insert("2.5.4.11", "organizationalUnitName");
    oid_map.insert("2.5.4.7", "localityName");
    oid_map.insert("2.5.4.8", "stateOrProvinceName");
    oid_map.insert("2.5.4.9", "streetAddress");
    oid_map.insert("2.5.4.5", "serialNumber");

    // Key identifiers and constraints
    oid_map.insert("2.5.29.14", "subjectKeyIdentifier");
    oid_map.insert("2.5.29.35", "authorityKeyIdentifier");
    oid_map.insert("2.5.29.19", "basicConstraints");
    oid_map.insert("2.5.29.15", "keyUsage");
    oid_map.insert("2.5.29.37", "extendedKeyUsage");

    // Alternative names
    oid_map.insert("2.5.29.17", "subjectAltName");
    oid_map.insert("2.5.29.18", "issuerAltName");

    // Certificate Revocation List (CRL) extensions
    oid_map.insert("2.5.29.20", "CRLNumber");
    oid_map.insert("2.5.29.27", "DeltaCRLIndicator");
    oid_map.insert("2.5.29.28", "IssuingDistributionPoint");
    oid_map.insert("2.5.29.46", "FreshestCRL");
    oid_map.insert("2.5.29.21", "ReasonCode");
    oid_map.insert("2.5.29.24", "InvalidityDate");
    oid_map.insert("2.5.29.29", "CertificateIssuer");

    // Signature algorithms (RSA, DSA, ECDSA)
    oid_map.insert("1.2.840.113549.1.1.5", "sha1WithRSAEncryption");
    oid_map.insert("1.2.840.113549.1.1.11", "sha256WithRSAEncryption");
    oid_map.insert("1.2.840.113549.1.1.12", "sha384WithRSAEncryption");
    oid_map.insert("1.2.840.113549.1.1.13", "sha512WithRSAEncryption");
    oid_map.insert("1.2.840.10040.4.3", "dsaWithSHA1");
    oid_map.insert("2.16.840.1.101.3.4.3.1", "dsaWithSHA224");
    oid_map.insert("2.16.840.1.101.3.4.3.2", "dsaWithSHA256");
    oid_map.insert("1.2.840.10045.4.3.1", "ecdsaWithSHA224");
    oid_map.insert("1.2.840.10045.4.3.2", "ecdsaWithSHA256");
    oid_map.insert("1.2.840.10045.4.3.3", "ecdsaWithSHA384");
    oid_map.insert("1.2.840.10045.4.3.4", "ecdsaWithSHA512");

    // Public key algorithms
    oid_map.insert("1.2.840.113549.1.1.1", "rsaEncryption");
    oid_map.insert("1.2.840.10040.4.1", "dsa");
    oid_map.insert("1.2.840.10045.2.1", "ecPublicKey");

    // Named elliptic curves
    oid_map.insert("1.3.132.0.33", "secp224r1");
    oid_map.insert("1.3.132.0.34", "secp384r1");
    oid_map.insert("1.3.132.0.35", "secp521r1");
    oid_map.insert("1.2.840.10045.3.1.7", "prime256v1");

    // Extended key usages
    oid_map.insert("1.3.6.1.5.5.7.3.1", "serverAuth");
    oid_map.insert("1.3.6.1.5.5.7.3.2", "clientAuth");

    // Authority info and policies
    oid_map.insert("1.3.6.1.5.5.7.1.1", "authorityInfoAccess");
    oid_map.insert("2.5.29.31", "cRLDistributionPoints");
    oid_map.insert("2.5.29.32", "certificatePolicies");

    oid_map
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
        let encoded = vec![Tag::Integer.into(), 0x02, 0x01, 0x2C];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::Integer(300));
    }

    #[test]
    fn test_decode_boolean_true() {
        let encoded = vec![Tag::Boolean.into(), 0x01, 0xFF];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::Boolean(true));
    }

    #[test]
    fn test_decode_boolean_false() {
        let encoded = vec![Tag::Boolean.into(), 0x01, 0x00];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::Boolean(false));
    }

    #[test]
    fn test_decode_octet_string() {
        let encoded = vec![Tag::OctetString.into(), 0x04, 0xDE, 0xAD, 0xBE, 0xEF];
        let decoded = decode(encoded).unwrap();
        assert_eq!(
            decoded,
            DecodedValue::OctetString(vec![0xDE, 0xAD, 0xBE, 0xEF])
        );
    }

    #[test]
    fn test_decode_utf8_string() {
        let encoded = vec![Tag::Utf8String.into(), 0x05, b'h', b'e', b'l', b'l', b'o'];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::Utf8String("hello".to_string()));
    }

    #[test]
    fn test_decode_printable_string() {
        let encoded = vec![
            Tag::PrintableString.into(),
            0x05,
            b'w',
            b'o',
            b'r',
            b'l',
            b'd',
        ];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::PrintableString("world".to_string()));
    }

    #[test]
    fn test_decode_bit_string() {
        let encoded = vec![Tag::BitString.into(), 0x02, 0x03, 0b10101010];
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
            Tag::ObjectIdentifier.into(),
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
            Tag::ObjectIdentifier.into(),
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
            b'Z',
        ];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::UtcTime("250101000000Z".to_string()));
    }

    #[test]
    fn test_decode_null() {
        let encoded = vec![Tag::Null.into(), 0x00];
        let decoded = decode(encoded).unwrap();
        assert_eq!(decoded, DecodedValue::Null);
    }

    #[test]
    fn test_decode_sequence() {
        let el1 = vec![Tag::Integer.into(), 0x01, 0x01];
        let el2 = vec![Tag::Boolean.into(), 0x01, 0xFF];
        let content = [el1.clone(), el2.clone()].concat();
        let encoded = vec![Tag::Sequence.into(), content.len() as u8];
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
        let el1 = vec![Tag::Integer.into(), 0x01, 0x02];
        let el2 = vec![Tag::Integer.into(), 0x01, 0x01];
        let content = [el1.clone(), el2.clone()].concat();
        let encoded = vec![Tag::Set.into(), content.len() as u8];
        let mut full = encoded.clone();
        full.extend(content);
        let decoded = decode(full).unwrap();
        assert_eq!(
            decoded,
            DecodedValue::Set(vec![DecodedValue::Integer(2), DecodedValue::Integer(1)])
        );
    }
}
