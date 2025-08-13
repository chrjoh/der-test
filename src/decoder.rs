#![allow(dead_code)]
use crate::types::*;
use num_bigint::BigInt;
use num_traits::ToPrimitive;
use std::collections::HashMap;
//encoding
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
fn decode_object_identifier_value(bytes: &[u8]) -> Option<DecodedValue> {
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

fn decode_context_with_variant<F>(bytes: &[u8], wrap: F) -> Option<DecodedValue>
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

fn decode_sequence(bytes: &[u8]) -> Option<DecodedValue> {
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

/// Decodes a single DER-encoded ASN.1 element from the given byte slice.
///
/// This function attempts to parse the first ASN.1 element in the input data,
/// including its tag, length, and value. It supports a variety of standard
/// ASN.1 types such as Integer, Sequence, Set, Boolean, BitString, and more.
///
/// # Arguments
///
/// * `data` - A byte slice containing DER-encoded ASN.1 data.
///
/// # Returns
///
/// * `Some((DecodedValue, usize))` - The decoded value and the number of bytes consumed.
/// * `None` - If the data is invalid or incomplete.
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
        Ok(tag) => match tag {
            Tag::Integer => decode_integer_value(value_bytes),
            Tag::OctetString => decode_octet_string_value(value_bytes),
            Tag::Context(n) => decode_context_with_variant(value_bytes, |elements| {
                DecodedValue::Context(n, elements)
            }),
            Tag::Sequence => decode_sequence(value_bytes),
            Tag::Set => decode_set_value(value_bytes),
            Tag::Boolean => decode_boolean_value(value_bytes),
            Tag::Utf8String => decode_utf8_string_value(value_bytes),
            Tag::BitString => decode_bit_string_value(value_bytes),
            Tag::ObjectIdentifier => decode_object_identifier_value(value_bytes),
            Tag::GeneralizedTime => decode_generalized_time_value(value_bytes),
            Tag::UtcTime => decode_utc_time_value(value_bytes),
            Tag::Null => decode_null_value(value_bytes),
            Tag::PrintableString => decode_printable_string_value(value_bytes),
        },
        Err(_) => Some(DecodedValue::Unknown(tag_byte, value_bytes.to_vec())),
    }?;

    Some((decoded, end))
}
/// Decodes a complete DER-encoded ASN.1 structure from a byte vector.
///
/// This is a high-level wrapper around `decode_element` that returns a
/// `Result` instead of an `Option`, making it more convenient for error handling.
///
/// # Arguments
///
/// * `data` - A `Vec<u8>` containing the DER-encoded ASN.1 structure.
///
/// # Returns
///
/// * `Ok(DecodedValue)` - The successfully decoded ASN.1 value.
/// * `Err(String)` - An error message if decoding fails.
pub fn decode(data: Vec<u8>) -> Result<DecodedValue, String> {
    match decode_element(&data) {
        Some((value, _)) => Ok(value),
        None => Err("Failed to decode DER structure".to_string()),
    }
}

/// Prints a decoded ASN.1 value with indentation for readability.
///
/// This is the public entry point for printing a `DecodedValue`. It initializes
/// the OID (Object Identifier) map and delegates the actual printing to a
/// private helper function.
///
/// # Arguments
///
/// * `value` - A reference to the decoded ASN.1 value to print.
/// * `indent` - The number of spaces to use for indentation (typically 0).
pub fn print_decoded_value(value: &DecodedValue, indent: usize) {
    let oid_map = get_oid_map();
    print_decoded_value_private(value, indent, &oid_map);
}

/// Recursively prints a decoded ASN.1 value with indentation and OID resolution.
///
/// This function handles all supported ASN.1 types and prints them in a
/// human-readable format. It uses indentation to represent nested structures
/// like sequences and sets. For object identifiers, it attempts to resolve
/// them to human-friendly names using the provided OID map.
///
/// # Arguments
///
/// * `value` - A reference to the decoded ASN.1 value to print.
/// * `indent` - The current indentation level (in spaces).
/// * `oid_map` - A map of known OID strings to their human-readable names.
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

        DecodedValue::Context(tag_num, seq) => {
            println!("{indent_str}Tag[{}] [", tag_num);
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
    let bytes = i.to_signed_bytes_be();
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
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

fn get_oid_map() -> HashMap<&'static str, &'static str> {
    let mut oid_map = HashMap::new();

    oid_map.insert("2.5.29.9", "subjectDirectoryAttributes");
    oid_map.insert("2.5.29.14", "subjectKeyIdentifier");
    oid_map.insert("2.5.29.15", "keyUsage");
    oid_map.insert("2.5.29.16", "privateKeyUsagePeriod");
    oid_map.insert("2.5.29.17", "subjectAltName");
    oid_map.insert("2.5.29.18", "issuerAltName");
    oid_map.insert("2.5.29.19", "basicConstraints");
    oid_map.insert("2.5.29.20", "cRLNumber");
    oid_map.insert("2.5.29.21", "reasonCode");
    oid_map.insert("2.5.29.23", "instructionCode");
    oid_map.insert("2.5.29.24", "invalidityDate");
    oid_map.insert("2.5.29.27", "deltaCRLIndicator");
    oid_map.insert("2.5.29.28", "issuingDistributionPoint");
    oid_map.insert("2.5.29.29", "certificateIssuer");
    oid_map.insert("2.5.29.30", "nameConstraints");
    oid_map.insert("2.5.29.31", "cRLDistributionPoints");
    oid_map.insert("2.5.29.32", "certificatePolicies");
    oid_map.insert("2.5.29.33", "policyMappings");
    oid_map.insert("2.5.29.35", "authorityKeyIdentifier");
    oid_map.insert("2.5.29.36", "policyConstraints");
    oid_map.insert("2.5.29.37", "extKeyUsage");
    oid_map.insert("2.5.29.46", "freshestCRL");
    oid_map.insert("2.5.29.54", "inhibitAnyPolicy");
    oid_map.insert("2.5.4.3", "commonName");
    oid_map.insert("2.5.4.5", "serialNumber");
    oid_map.insert("2.5.4.6", "countryName");
    oid_map.insert("2.5.4.7", "localityName");
    oid_map.insert("2.5.4.8", "stateOrProvinceName");
    oid_map.insert("2.5.4.9", "streetAddress");
    oid_map.insert("2.5.4.10", "organizationName");
    oid_map.insert("2.5.4.11", "organizationUnitName");
    oid_map.insert("2.5.4.12", "title");
    oid_map.insert("2.5.4.17", "postalCode");
    oid_map.insert("2.5.29.32.0", "anyPolicy");
    oid_map.insert("2.5.29.37.0", "anyExtendedKeyUsage");

    oid_map.insert("2.23.140.1.2.1", "domain-validated");
    oid_map.insert("2.23.140.1.2.2", "organization-validated");
    oid_map.insert("2.23.140.1.2.3", "individual-validated");

    oid_map.insert("1.3.6.1.4.1.11129.2.4.2", "embeddedSCTList");
    oid_map.insert("1.3.6.1.4.1.11129.2.4.3", "ctPoison");
    oid_map.insert("1.3.6.1.4.1.11129.2.4.4", "ctPrecertificateSigning");
    oid_map.insert("1.3.6.1.4.1.11129.2.4.5", "ocspSCTList");
    oid_map.insert("1.3.6.1.5.5.7.1.29", "autonomousSysIds-v2");
    oid_map.insert("1.3.6.1.5.5.7.1.1", "authorityInfoAccess");
    oid_map.insert("1.3.6.1.5.5.7.1.7", "ipAddrBlocks");
    oid_map.insert("1.3.6.1.5.5.7.1.8", "autonomousSysIds");
    oid_map.insert("1.3.6.1.5.5.7.1.11", "subjectInfoAccess");
    oid_map.insert("1.3.6.1.5.5.7.1.28", "ipAddrBlocks-v2");
    oid_map.insert("1.3.6.1.5.5.7.3.1", "serverAuth");
    oid_map.insert("1.3.6.1.5.5.7.3.2", "clientAuth");
    oid_map.insert("1.3.6.1.5.5.7.3.3", "codeSigning");
    oid_map.insert("1.3.6.1.5.5.7.3.4", "emailProtection");
    oid_map.insert("1.3.6.1.5.5.7.3.8", "timeStamping");
    oid_map.insert("1.3.6.1.5.5.7.3.9", "OCSPSigning");
    oid_map.insert("1.3.6.1.5.5.7.3.30", "bgpsec-router");
    oid_map.insert("1.3.6.1.5.5.7.2.2", "unotice");
    oid_map.insert("1.3.6.1.5.5.7.14.2", "ipAddr-asNumber");
    oid_map.insert("1.3.6.1.5.5.7.14.3", "ipAddr-asNumber-v2");
    oid_map.insert("1.3.6.1.5.5.7.48.1", "ocsp");
    oid_map.insert("1.3.6.1.5.5.7.48.2", "caIssuers");
    oid_map.insert("1.3.6.1.5.5.7.48.5", "caRepository");
    oid_map.insert("1.3.6.1.5.5.7.48.10", "rpkiManifest");
    oid_map.insert("1.3.6.1.5.5.7.48.11", "signedObject");
    oid_map.insert("1.3.6.1.5.5.7.48.13", "rpkiNotify");

    oid_map.insert("1.2.840.113549.1.9.16.2.1", "receiptRequest");
    oid_map.insert("1.2.840.113549.1.9.16.2.2", "securityLabel");
    oid_map.insert("1.2.840.113549.1.9.16.2.3", "mlExpandHistory");
    oid_map.insert("1.2.840.113549.1.9.16.2.4", "contentHint");
    oid_map.insert("1.2.840.113549.1.9.16.2.5", "msgSigDigest");
    oid_map.insert("1.2.840.113549.1.9.16.2.7", "contentIdentifier");
    oid_map.insert("1.2.840.113549.1.9.16.2.9", "equivalentLabels");
    oid_map.insert("1.2.840.113549.1.9.16.2.10", "contentReference");
    oid_map.insert("1.2.840.113549.1.9.16.2.11", "encrypKeyPref");
    oid_map.insert("1.2.840.113549.1.9.16.2.12", "signingCertificate");
    oid_map.insert("1.2.840.113549.1.9.16.11.1", "preferBinaryInside");
    oid_map.insert("1.2.840.113549.1.7.1", "data");
    oid_map.insert("1.2.840.113549.1.7.2", "signedData");
    oid_map.insert("1.2.840.113549.1.7.3", "envelopedData");
    oid_map.insert("1.2.840.113549.1.7.4", "signedAndEnvelopedData");
    oid_map.insert("1.2.840.113549.1.7.5", "digestedData");
    oid_map.insert("1.2.840.113549.1.7.6", "encryptedData");
    oid_map.insert("1.2.840.113549.1.9.16.1.1", "receipt");
    oid_map.insert("1.2.840.113549.1.9.16.1.2", "authData");
    oid_map.insert("1.2.840.113549.1.9.16.1.6", "contentInfo");
    oid_map.insert("1.2.840.113549.1.9.16.1.24", "routeOriginAuthz");
    oid_map.insert("1.2.840.113549.1.9.16.1.26", "rpkiManifest");
    oid_map.insert("1.2.840.113549.1.9.16.1.35", "rpkiGhostbusters");
    oid_map.insert("1.2.840.113549.1.9.16.1.47", "geofeedCSVwithCRLF");
    oid_map.insert("1.2.840.113549.1.9.16.1.48", "signedChecklist");
    oid_map.insert("1.2.840.113549.1.9.16.1.49", "ASPA");
    oid_map.insert("1.2.840.113549.1.9.16.1.50", "signedTAL");
    oid_map.insert("1.2.840.113549.1.12.10.1.1", "keyBag");
    oid_map.insert("1.2.840.113549.1.12.10.1.2", "pkcs-8ShroudedKeyBag");
    oid_map.insert("1.2.840.113549.1.12.10.1.3", "certBag");
    oid_map.insert("1.2.840.113549.1.12.10.1.4", "crlBag");
    oid_map.insert("1.2.840.113549.1.12.10.1.5", "secretBag");
    oid_map.insert("1.2.840.113549.1.12.10.1.6", "safeContentsBag");
    oid_map.insert("1.2.840.113549.1.12.1.1", "pbeWithSHAAnd128BitRC4");
    oid_map.insert("1.2.840.113549.1.12.1.2", "pbeWithSHAAnd40BitRC4");
    oid_map.insert("1.2.840.113549.1.12.1.3", "pbeWithSHAAnd3-KeyTripleDES-CBC");
    oid_map.insert("1.2.840.113549.1.12.1.4", "pbeWithSHAAnd2-KeyTripleDES-CBC");
    oid_map.insert("1.2.840.113549.1.12.1.5", "pbeWithSHAAnd128BitRC2-CBC");
    oid_map.insert("1.2.840.113549.1.12.1.6", "pbewithSHAAnd40BitRC2-CBC");
    oid_map.insert("1.2.840.113549.1.1.2", "md2WithRSAEncryption");
    oid_map.insert("1.2.840.113549.1.1.3", "md4WithRSAEncryption");
    oid_map.insert("1.2.840.113549.1.1.4", "md5WithRSAEncryption");
    oid_map.insert("1.2.840.113549.1.1.5", "sha1WithRSAEncryption");
    oid_map.insert("1.2.840.113549.1.1.14", "sha224WithRSAEncryption");
    oid_map.insert("1.2.840.113549.1.1.11", "sha256WithRSAEncryption");
    oid_map.insert("1.2.840.113549.1.1.12", "sha384WithRSAEncryption");
    oid_map.insert("1.2.840.113549.1.1.13", "sha512WithRSAEncryption");
    oid_map.insert("1.2.840.10040.4.3", "dsa-with-sha1");
    oid_map.insert("1.2.840.113549.1.5.1", "pbeWithMD2AndDES-CBC");
    oid_map.insert("1.2.840.113549.1.5.3", "pbeWithMD5AndDES-CBC");
    oid_map.insert("1.2.840.113549.1.5.4", "pbeWithMD2AndRC2-CBC");
    oid_map.insert("1.2.840.113549.1.5.6", "pbeWithMD5AndRC2-CBC");
    oid_map.insert("1.2.840.113549.1.5.10", "pbeWithSHA1AndDES-CBC");
    oid_map.insert("1.2.840.113549.1.5.11", "pbeWithSHA1AndRC2-CBC");
    oid_map.insert("1.2.840.113549.1.5.12", "PBKDF2");
    oid_map.insert("1.2.840.113549.1.5.13", "PBES2");
    oid_map.insert("1.2.840.113549.1.5.14", "PBMAC1");
    oid_map.insert("1.2.840.113549.2.7", "hmacWithSHA1");
    oid_map.insert("1.2.840.113549.2.8", "hmacWithSHA224");
    oid_map.insert("1.2.840.113549.2.9", "hmacWithSHA256");
    oid_map.insert("1.2.840.113549.2.10", "hmacWithSHA384");
    oid_map.insert("1.2.840.113549.2.11", "hmacWithSHA512");
    oid_map.insert("1.2.840.113549.3.2", "RC2-CBC");
    oid_map.insert("1.2.840.113549.3.7", "DES-EDE3-CBC");
    oid_map.insert("1.2.840.113549.3.9", "RC5-CBC-Pad");
    oid_map.insert("1.2.840.113549.1.9.1", "emailAddress");
    oid_map.insert("1.2.840.113549.1.9.2", "unstructuredName");
    oid_map.insert("1.2.840.113549.1.9.3", "contentType");
    oid_map.insert("1.2.840.113549.1.9.4", "messageDigest");
    oid_map.insert("1.2.840.113549.1.9.5", "signingTime");
    oid_map.insert("1.2.840.113549.1.9.6", "counterSignature");
    oid_map.insert("1.2.840.113549.1.9.7", "challengePassword");
    oid_map.insert("1.2.840.113549.1.9.8", "unstructuredAddress");
    oid_map.insert("1.2.840.113549.1.9.9", "extendedCertificateAttributes");
    oid_map.insert("1.2.840.113549.1.9.10", "issuerAndSerialNumber");
    oid_map.insert("1.2.840.113549.1.9.11", "passwordCheck");
    oid_map.insert("1.2.840.113549.1.9.12", "publicKey");
    oid_map.insert("1.2.840.113549.1.9.13", "signingDescription");
    oid_map.insert("1.2.840.113549.1.9.14", "extensionRequest");
    oid_map.insert("1.2.840.113549.1.9.15", "smimeCapabilities");
    oid_map.insert("1.2.840.113549.1.9.20", "friendlyName");
    oid_map.insert("1.2.840.113549.1.9.21", "localKeyId");
    oid_map.insert("1.2.840.113549.1.1.8", "mgf1");
    oid_map.insert("1.2.840.113549.1.1.1", "rsaEncryption");
    oid_map.insert("1.2.840.113549.1.1.10", "rsassa-pss");
    oid_map.insert("1.2.840.10045.2.1", "ecPublicKey");
    oid_map.insert("1.2.840.10040.4.1", "dsa");
    oid_map.insert("1.2.840.10045.1.1", "prime-field");
    oid_map.insert("1.2.840.10045.1.2", "characteristic-two-field");
    oid_map.insert("1.2.840.10045.1.2.3.1", "gnBasis");
    oid_map.insert("1.2.840.10045.1.2.3.2", "tpBasis");
    oid_map.insert("1.2.840.10045.1.2.3.3", "ppBasis");
    oid_map.insert("1.2.840.113549.2.2", "md2");
    oid_map.insert("1.2.840.113549.2.4", "md4");
    oid_map.insert("1.2.840.113549.2.5", "md5");
    oid_map.insert("1.2.840.10045.4.1", "ecdsa-with-SHA1");
    oid_map.insert("1.2.840.10045.4.3.1", "ecdsa-with-SHA224");
    oid_map.insert("1.2.840.10045.4.3.2", "ecdsa-with-SHA256");
    oid_map.insert("1.2.840.10045.4.3.3", "ecdsa-with-SHA384");
    oid_map.insert("1.2.840.10045.4.3.4", "ecdsa-with-SHA512");
    oid_map.insert("1.2.840.10045.3.1.7", "secp256r1");

    oid_map.insert("1.3.132.0.33", "secp224r1");
    oid_map.insert("1.3.132.0.34", "secp384r1");
    oid_map.insert("1.3.132.0.35", "secp521r1");
    oid_map.insert("1.3.14.3.2.26", "sha1");
    oid_map.insert("1.3.101.110", "x25519");
    oid_map.insert("1.3.101.111", "x448");
    oid_map.insert("1.3.101.112", "ed25519");
    oid_map.insert("1.3.101.113", "ed448");

    oid_map.insert("2.16.840.1.101.3.4.2.4", "sha224");
    oid_map.insert("2.16.840.1.101.3.4.2.1", "sha256");
    oid_map.insert("2.16.840.1.101.3.4.2.2", "sha384");
    oid_map.insert("2.16.840.1.101.3.4.2.3", "sha512");
    oid_map.insert("2.16.840.1.101.3.4.1.2", "AES-128-CBC");
    oid_map.insert("2.16.840.1.101.3.4.1.22", "AES-192-CBC");
    oid_map.insert("2.16.840.1.101.3.4.1.42", "AES-256-CBC");
    oid_map.insert("2.16.840.1.101.3.4.3.1", "dsa-with-sha224");
    oid_map.insert("2.16.840.1.101.3.4.3.2", "dsa-with-sha256");

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
