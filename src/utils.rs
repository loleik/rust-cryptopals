use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use base64::prelude::*;
use rand::prelude::*;
use std::collections::HashSet;

#[cfg(test)]
mod tests {
    use crate::utils::hamming_distance;

    #[test]
    fn hamming_test() {
        let a: &[u8] = "this is a test".as_bytes();
        let b: &[u8] = "wokka wokka!!!".as_bytes();
        assert_eq!(37, hamming_distance(a, b));
    }
}

pub fn file_to_lines(path: &str) -> Vec<String> {
    let mut output = Vec::new();

    if let Ok(lines) = read_lines(path) {
        for line in lines.map_while(Result::ok) {
            output.push(line);
        }
    }
    
    fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path>, {
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    }

    output
}

pub fn base64_file_decode(path: &str) -> Vec<u8> {
    let raw_text = file_to_lines(path).join("");

    let data = BASE64_STANDARD.decode(raw_text.as_bytes()).expect("Invalid base64 string");

    data
}

pub fn letter_frequency(data: &Vec<u8>) -> Vec<(u8, f64)> {
    let mut scores: Vec<(u8, f64)> = Vec::new();

    for i in 0..=127 {
        let mut score: f64 = 0.000;
        data.iter().for_each(|c| {
            score += match c ^ i {
                b'A' | b'a' => 8.167, b'B' | b'b' => 1.492, b'C' | b'c' => 2.782,
                b'D' | b'd' => 4.253, b'E' | b'e' => 12.70, b'F' | b'f' => 2.228,
                b'G' | b'g' => 2.015, b'H' | b'h' => 6.094, b'I' | b'i' => 6.966,
                b'J' | b'j' => 0.153, b'K' | b'k' => 0.772, b'L' | b'l' => 4.025,
                b'M' | b'm' => 2.406, b'N' | b'n' => 6.749, b'O' | b'o' => 7.507,
                b'P' | b'p' => 1.929, b'Q' | b'q' => 0.095, b'R' | b'r' => 5.987,
                b'S' | b's' => 6.327, b'T' | b't' => 9.056, b'U' | b'u' => 2.758,
                b'V' | b'v' => 0.978, b'W' | b'w' => 2.361, b'X' | b'x' => 0.150,
                b'Y' | b'y' => 1.974, b'Z' | b'z' => 0.074, b' ' => 0.,
                _ => -10.,
            }
        });
        scores.push((i, score));
    };

    scores
}

pub fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    let mut distance: u32 = 0;

    for i in 0..a.len() {
        let mut xor: u8 = a[i] ^ b[i];
        while xor > 0 {
            distance += (xor & 1) as u32;
            xor >>= 1;
        }
    }

    distance
}

pub fn random_key(size: usize) -> Vec<u8> {
    let mut rng: ThreadRng = rand::rng();
    let mut key: Vec<u8> = Vec::new();

    for _ in 0..size {
        key.push(rng.random());
    }

    key
}

pub fn test_ecb(ctxt: Vec<u8>) -> bool {
    let test_blocks: Vec<&[u8]> = ctxt.chunks(16).collect();

    let unique: HashSet<&[u8]> = test_blocks.iter().cloned().collect();
    let identical: usize = test_blocks.len() - unique.len();

    if identical > 0 { true } else { false }
}

// Doesn't validate padding. It was written for an earlier challenge.
pub fn strip_pkcs7_padding(data: Vec<u8>) -> Vec<u8> {
    let mut output: Vec<u8> = data.clone();

    let padding: u8 = *output.last().unwrap();
    output.truncate(output.len() - padding as usize);

    output
}

pub fn detect_single_byte_xor(input: &[u8]) -> (u8, Vec<u8>, f64) {
    let freq_table = |b: u8| match b.to_ascii_lowercase() {
        b'a' => 8.167, b'b' => 1.492, b'c' => 2.782,
        b'd' => 4.253, b'e' => 12.70, b'f' => 2.228,
        b'g' => 2.015, b'h' => 6.094, b'i' => 6.966,
        b'j' => 0.153, b'k' => 0.772, b'l' => 4.025,
        b'm' => 2.406, b'n' => 6.749, b'o' => 7.507,
        b'p' => 1.929, b'q' => 0.095, b'r' => 5.987,
        b's' => 6.327, b't' => 9.056, b'u' => 2.758,
        b'v' => 0.978, b'w' => 2.361, b'x' => 0.150,
        b'y' => 1.974, b'z' => 0.074, b' ' => 13.0,
        b'\n' | b'.' | b',' | b'\'' | b'"' | b'!' | b'?' => 1.0,
        _ => -5.0,
    };

    let mut best_score = f64::MIN;
    let mut best_key = 0;
    let mut best_plain = vec![];

    for key in 0u8..=255 {
        let decoded: Vec<u8> = input.iter().map(|&b| b ^ key).collect();
        let score: f64 = decoded.iter().map(|&b| freq_table(b)).sum();

        if score > best_score {
            best_score = score;
            best_key = key;
            best_plain = decoded;
        }
    }

    (best_key, best_plain, best_score)
}
