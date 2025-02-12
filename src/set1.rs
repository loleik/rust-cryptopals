use hex;
use base64::{Engine as _, engine::general_purpose};
use std::fs;

use crate::utils::{self, letter_frequency};

#[cfg(test)]
mod tests {
    use crate::set1::{part_1, part_2, part_3, part_5};

    #[test]
    fn test_1() {
        let input: &str = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected: &str = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(expected, part_1(input));
    }

    #[test]
    fn test_2() {
        let input: &str = "1c0111001f010100061a024b53535009181c";
        let target: &str = "686974207468652062756c6c277320657965";
        let expected: &str = "746865206b696420646f6e277420706c6179";
        assert_eq!(expected, part_2(input, target));
    }

    #[test]
    fn test_3() {
        let input: &str = "0429202023606c3824253f6c253f6c2d6c38293f38";
        let expected: (char, String, f64) = ('L', "Hello, this is a test".to_string(), 111.393);
        let output: (char, String, f64) = part_3(input).unwrap_or((' ', "".to_string(), 0.));
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
        assert_eq!(expected, part_5(input, key, true));
    }
}

fn part_1(input: &str) -> String {
    let bytes: Vec<u8> = hex::decode(input)
        .expect("Invalid input string");
    let result: String = general_purpose::STANDARD.encode(bytes);
    result
}

fn part_2(input: &str, target: &str) -> String {
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

fn part_3(input: &str) -> Option<(char, String, f64)> {
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

fn part_4(input: &str) -> (char, String, f64) {
    let mut results: Vec<(char, String, f64)> = Vec::new();

    let lines: Vec<String> = utils::file_to_lines(input);
    lines.iter().for_each(|line| {
        results.push(part_3(line).unwrap_or((' ', "".to_string(), 0.)));
    });

    if let Some(max) = results.iter().max_by(|a, b| a.2.partial_cmp(&b.2).unwrap()) {
        max.clone()
    } else {
        (' ', "".to_string(), 0.)
    }
}

fn part_5(input: &str, key: &str, test: bool) -> String {
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

pub fn set_1(part: &str, input: &str) {
    println!("Input: {input}");
    match part {
        "1" => {
            println!("Base 64: {}", part_1(input));
        },
        "2" => {
            // Should be rewritten to allow target to be inputted using the CLI
            let target = "686974207468652062756c6c277320657965";
            println!("Target: {target}");
            println!("XOR Result: {}", part_2(input, target));
        },
        "3" => {
            let result: (char, String, f64) = part_3(input).unwrap_or((' ', "".to_string(), 0.));
            println!("Found: {:?}", result);
        },
        "4" => {
            let result: (char, String, f64) = part_4(input);
            println!("Found: {}", result.1.trim_end());
            println!("Key: {} Score: {}", result.0, result.2);
        },
        "5" => {
            part_5(input, "ICE", false);
        }
        _ => println!("wah")
    }
}