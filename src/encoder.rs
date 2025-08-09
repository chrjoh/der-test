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
            len_bytes.insert(0, (temp & 0xFF) as u8);
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

pub fn encode_object_identifier(oid: &str) -> Option<Vec<u8>> {
    let parts: Vec<u32> = oid.split('.').filter_map(|s| s.parse().ok()).collect();
    if parts.len() < 2 {
        return None; // OID must have at least two components
    }

    let mut encoded: Vec<u8> = Vec::new();
    encoded.push((parts[0] * 40 + parts[1]) as u8); // First byte

    for &part in &parts[2..] {
        let mut stack = Vec::new();
        let mut value = part;

        // Takes the lowest 7 bits of the value and pushes it to the stack.
        // This is the last byte of the base-128 encoding (MSB = 0).
        stack.push((value & 0x7F) as u8);
        // Shifts the value right by 7 bits to process the next 7-bit chunk.
        value >>= 7;

        // Continues extracting 7-bit chunks from the value.
        // Each chunk is pushed with the MSB set to 1 (| 0x80) to indicate continuation.
        while value > 0 {
            stack.push(((value & 0x7F) as u8) | 0x80);
            value >>= 7;
        }
        // The stack is reversed because the most significant chunks were added last.
        encoded.extend(stack.iter().rev());
    }

    let mut result = vec![OBJECT_IDENTIFIER_TAG];
    result.extend(encode_length(encoded.len()));
    result.extend(encoded);
    Some(result)
}

pub fn encode_sequence(elements: &[Vec<u8>]) -> Vec<u8> {
    let mut content: Vec<u8> = vec![];
    for el in elements {
        content.extend(el);
    }

    let mut result = vec![SEQUENCE_TAG];
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
