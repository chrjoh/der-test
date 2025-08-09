mod decoder;
mod encoder;
mod types;

use crate::decoder::decode;
use crate::encoder::{
    encode_bit_string, encode_boolean, encode_integer, encode_object_identifier,
    encode_octet_string, encode_sequence, encode_set, encode_utf8_string,
};
fn main() {
    let bit_data = vec![0b10101010, 0b11000000]; // 2 bytes of bit data
    let unused_bits = 6; // Last byte has only 2 meaningful bits
    let bit_encoded = encode_bit_string(&bit_data, unused_bits);
    let int_encoded = encode_integer(42);
    let str_encoded = encode_octet_string(b"hello");
    let seq_encoded1 = encode_sequence(&[int_encoded, str_encoded]);
    let seq_encoded2 = encode_sequence(&[encode_boolean(true), encode_octet_string(b"world")]);

    let oid = "1.2.840.113549";
    let oid_encoded = encode_object_identifier(oid).unwrap();

    let set_encoded = encode_set(&[
        seq_encoded1,
        seq_encoded2,
        encode_set(&[encode_utf8_string("my encoder".to_string())]),
        bit_encoded,
        oid_encoded,
    ]);

    println!("DER-encoded SEQUENCE: {:?}", set_encoded);
    println!(
        "DER-encoded SEQUENCE IN HEX: {}",
        set_encoded
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(":")
    );

    match decode(set_encoded) {
        Ok(decoded) => println!("Decoded: {:#?}", decoded),
        Err(e) => eprintln!("Error: {}", e),
    }
}
