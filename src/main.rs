#![allow(dead_code)]
mod decoder;
mod encoder;
mod types;
use crate::decoder::{decode, print_decoded_value};
use crate::encoder::{
    create_der_from_decoded_value, encode_bit_string, encode_boolean, encode_integer,
    encode_object_identifier, encode_octet_string, encode_sequence, encode_set, encode_utf8_string,
};

use clap::{Parser, Subcommand};
use std::fs;
use std::path::Path;

use base64::{Engine, engine::general_purpose};

#[derive(Parser)]
#[command(name = "DER Tool", version, about = "Run DER encoding/decoding tests")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run test using a specific DER file
    File {
        /// Path to the DER file
        #[arg(short, long)]
        path: String,
    },
    /// Run test using hardcoded CRL fixture
    Crl,
    /// Run test using hardcoded certificate fixture
    Cert,
    /// Run test using synthetic data
    Data,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::File { path }) => run_test_file(path),
        Some(Commands::Crl) => run_test_data_crl(),
        Some(Commands::Cert) => run_test_data_cert(),
        Some(Commands::Data) => run_test_data(),
        None => {
            println!("No command provided. Running default: `data`");
            run_test_data();
        }
    }
}
fn run_test_file<P: AsRef<Path>>(file: P) {
    let result = fs::read(file).expect("Failed to read der data");
    match decode(result) {
        Ok(decoded) => print_decoded_value(&decoded, 1),
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn run_test_data_crl() {
    let result = fs::read("./fixtures/crl.der").expect("Failed to read der data");
    match decode(result) {
        Ok(decoded) => {
            print_decoded_value(&decoded, 1);
            match create_der_from_decoded_value(&decoded) {
                Some(encoded) => println!("{}", der_to_pem(&encoded, "CRL")),
                None => eprintln!("Error: re encoding"),
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn run_test_data_cert() {
    let result = fs::read("./fixtures/leaf_cert.der").expect("Failed to read der data");
    match decode(result) {
        Ok(decoded) => {
            print_decoded_value(&decoded, 1);
            match create_der_from_decoded_value(&decoded) {
                Some(encoded) => println!("{}", der_to_pem(&encoded, "CERTIFICATE")),
                None => eprintln!("Error: re encoding"),
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}
fn run_test_data() {
    let bit_data = vec![0b10101010, 0b11000000]; // 2 bytes of bit data
    let unused_bits = 6; // Last byte has only 2 meaningful bits
    let bit_encoded = encode_bit_string(&bit_data, unused_bits);
    let int_encoded = encode_integer(42);
    let str_encoded = encode_octet_string(b"hello");
    let seq_encoded1 = encode_sequence(&[int_encoded, str_encoded]);
    let seq_encoded2 = encode_sequence(&[encode_boolean(true), encode_octet_string(b"world")]);

    let oid = "2.200.840.113549";
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
        Ok(decoded) => {
            print_decoded_value(&decoded, 1);
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}

fn der_to_pem(der: &[u8], label: &str) -> String {
    let base64_encoded = general_purpose::STANDARD.encode(der);
    let mut pem = format!("-----BEGIN {}-----\n", label);

    for chunk in base64_encoded.as_bytes().chunks(64) {
        pem.push_str(&String::from_utf8_lossy(chunk));
        pem.push('\n');
    }

    pem.push_str(&format!("-----END {}-----\n", label));
    pem
}
