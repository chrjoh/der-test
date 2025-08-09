#![allow(dead_code)]
use crate::types::*;
#[derive(Debug)]
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
    Set(Vec<DecodedValue>),
    Unknown(u8, Vec<u8>),
}
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
// 0x82 means the length is in long form, and the next 2 bytes (0x01F4) encode the length.
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
fn decode_object_identifier_value(bytes: &[u8]) -> Option<DecodedValue> {
    if bytes.is_empty() {
        return None;
    }

    let first_byte = bytes[0];
    let first = (first_byte / 40) as u32;
    let second = (first_byte % 40) as u32;

    let mut parts = vec![first, second];
    let mut value: u32 = 0;

    for &byte in &bytes[1..] {
        value = (value << 7) | (byte & 0x7F) as u32;
        if byte & 0x80 == 0 {
            parts.push(value);
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

fn decode_sequence_value(bytes: &[u8]) -> Option<DecodedValue> {
    let mut elements = vec![];
    let mut cursor = 0;
    while cursor < bytes.len() {
        let (element, consumed) = decode_element(&bytes[cursor..])?;
        elements.push(element);
        cursor += consumed;
    }
    Some(DecodedValue::Sequence(elements))
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
        SEQUENCE_TAG => decode_sequence_value(value_bytes),
        SET_TAG => decode_set_value(value_bytes),
        BOOLEAN_TAG => decode_boolean_value(value_bytes),
        UTF8STRING_TAG => decode_utf8_string_value(value_bytes),
        BIT_STRING_TAG => decode_bit_string_value(value_bytes),
        OBJECT_IDENTIFIER_TAG => decode_object_identifier_value(value_bytes),
        GENERALIZED_TIME_TAG => decode_generalized_time_value(value_bytes),
        UTC_TIME_TAG => decode_utc_time_value(value_bytes),
        NULL_TAG => decode_null_value(value_bytes),
        PRINTABLE_STRING_TAG => decode_printable_string_value(value_bytes),
        CONTEXT_SPECIFIC_0_TAG => decode_sequence_value(value_bytes),
        CONTEXT_SPECIFIC_3_TAG => decode_sequence_value(value_bytes),
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
