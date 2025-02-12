use hex;
use base64::prelude::*;
use std::fs;
use openssl::symm::{decrypt, Cipher};

use crate::utils::{letter_frequency, hamming_distance, file_to_lines, base64_file_decode};

fn hex_to_base64(input: &str) -> String {
    let bytes: Vec<u8> = hex::decode(input)
        .expect("Invalid input string");
    let result: String = BASE64_STANDARD.encode(&bytes);
    result
}

fn fixed_xor(input: &str, target: &str) -> String {
    let target_bytes: Vec<u8> = hex::decode(target)
        .expect("Invalid input string");
    let input_bytes: Vec<u8> = hex::decode(input)
        .expect("Invalid input string");

    if input_bytes.len() != target_bytes.len() { panic!("Inputs should have the same length") }

    let mut result: Vec<u8> = vec![];

    for (x, y) in input_bytes.iter().enumerate() {
        result.push(y ^ target_bytes[x]);
    }

    hex::encode(result)
}

fn single_byte_xor(input: &str) -> Option<(char, String, f64)> {
    let input_bytes: Vec<u8> = hex::decode(input)
        .expect("Invalid input string");

    let scores: Vec<(u8, f64)> = letter_frequency(&input_bytes);
    let mut result: Vec<char> = vec![];

    if let Some(max_tuple) = scores.iter().max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap()) {
        let (max_int, max_float) = max_tuple;
        input_bytes.iter().for_each(|c| {
            result.push((c ^ max_int) as char);
        });
        Some((*max_int as char, result.iter().collect(), *max_float))
    } else { None }
}

fn detect_single_byte_xor(input: &str, file: bool) -> (char, String, f64) {
    let mut results: Vec<(char, String, f64)> = Vec::new();

    let lines: Vec<String> = if file {
        file_to_lines(input)
    } else {
        vec![input.to_string()]
    };

    lines.iter().for_each(|line| {
        results.push(single_byte_xor(line).unwrap_or((' ', "".to_string(), 0.)));
    });

    if let Some(max) = results.iter().max_by(|a, b| a.2.partial_cmp(&b.2).unwrap()) {
        max.clone()
    } else {
        (' ', "".to_string(), 0.)
    }
}

fn repeating_key_xor(input: &str, key: &str, test: bool) -> String {
    let data: Vec<u8> = if !test {
        match fs::read(input) {
            Ok(data) => data,
            Err(error) => panic!("Problem opening file: {error:?}")
        }
    } else {
        input.as_bytes().to_vec()
    };

    let key_bytes: &[u8] = key.as_bytes();
    let mut result: Vec<u8> = Vec::new();

    for i in 0..data.len() {
        let key_byte: u8 = key_bytes[i % key_bytes.len()];
        result.push(data[i] ^ key_byte);
    }

    hex::encode(result)
}

fn break_repeating_key_xor(input: &str) {
    let data: Vec<u8> = base64_file_decode(input);

    let mut distances: Vec<(usize, f32)> = Vec::new();

    for k in 2..=40 {
        let a: &[u8] = &data[0..k];
        let b: &[u8] = &data[k..(k * 2)];
        let c: &[u8] = &data[(k * 2)..(k * 3)];
        let d: &[u8] = &data[(k * 3)..(k * 4)];

        let a_b: f32 = hamming_distance(a, b) as f32 / k as f32;
        let b_c: f32 = hamming_distance(b, c) as f32 / k as f32;
        let c_d: f32 = hamming_distance(c, d) as f32 / k as f32;

        distances.push((k, (a_b + b_c + c_d) / 3.0));
    }

    distances.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    let blocks: Vec<&[u8]> = data.chunks(29).collect::<Vec<_>>();

    let mut new_blocks: Vec<String> = Vec::new();

    let attempt: usize = distances[2].0;

    for i in 0..attempt {
        let mut block: Vec<u8> = Vec::new();
        blocks.iter().for_each(|b| {
            if i < b.len() {
                block.push(b[i]);
            }
        });
        new_blocks.push(hex::encode(block));
    }

    let mut key: String = String::new();

    for block in new_blocks {
        key.push_str(&detect_single_byte_xor(&block, false).0.to_string());
    }

    println!("Key: {}", key);

    let result: String = String::from_utf8(hex::decode(
        repeating_key_xor(String::from_utf8(data).unwrap().as_str(), &key, true)
    ).unwrap()).unwrap();

    println!("Result: {}", result);
}

fn aes_ecb(input: &str, key: &str) -> String {
    let data: Vec<u8> = base64_file_decode(input);
    let key_bytes: &[u8] = key.as_bytes();
    let cipher: Cipher = Cipher::aes_128_ecb();

    let result: Vec<u8> = decrypt(cipher, key_bytes, None, &data).unwrap();

    String::from_utf8(result).unwrap()
}

pub fn set_1(part: &str, input: &str) {
    println!("Input: {input}");
    match part {
        "1" => {
            println!("Base 64: {}", hex_to_base64(input));
        },
        "2" => {
            // Should be rewritten to allow target to be inputted using the CLI
            let target = "686974207468652062756c6c277320657965";
            println!("Target: {target}");
            println!("XOR Result: {}", fixed_xor(input, target));
        },
        "3" => {
            let result: (char, String, f64) = single_byte_xor(input).unwrap_or((' ', "".to_string(), 0.));
            println!("Found: {:?}", result);
        },
        "4" => {
            let result: (char, String, f64) = detect_single_byte_xor(input, true);
            println!("Found: {}", result.1.trim_end());
            println!("Key: {} Score: {}", result.0, result.2);
        },
        "5" => {
            let result: String = repeating_key_xor(input, "ICE", false);
            println!("Result: {}", result);
        },
        "6" => {
            break_repeating_key_xor(input);
        },
        "7" => {
            let result: String = aes_ecb(input, "YELLOW SUBMARINE");
            println!("Result: {}", result);
        }
        _ => println!("wah")
    }
}

#[cfg(test)]
mod tests {
    use crate::set1::{hex_to_base64, fixed_xor, single_byte_xor, repeating_key_xor};

    #[test]
    fn test_1() {
        let input: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(expected, hex_to_base64(input));
    }

    #[test]
    fn test_2() {
        let input: &str = "1c0111001f010100061a024b53535009181c";
        let target: &str = "686974207468652062756c6c277320657965";
        let expected: &str = "746865206b696420646f6e277420706c6179";
        assert_eq!(expected, fixed_xor(input, target));
    }

    #[test]
    fn test_3() {
        let input: &str = "0429202023606c3824253f6c253f6c2d6c38293f38";
        let expected: (char, String, f64) = ('L', "Hello, this is a test".to_string(), 111.393);
        let output: (char, String, f64) = single_byte_xor(input).unwrap_or((' ', "".to_string(), 0.));
        assert_eq!(expected, output);
    }
    /* I'm not sure what to write for a test here
    #[test]
    fn test_4() {

    }*/

    #[test]
    fn test_5() {
        let input: &str = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
        let key: &str = "ICE";
        let expected: &str = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
        assert_eq!(expected, repeating_key_xor(input, key, true));
    }
}