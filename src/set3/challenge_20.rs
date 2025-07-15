use base64::prelude::*;
use std::sync::OnceLock;

use crate::set3::challenge_18::aes_ctr;
use crate::utils::{file_to_lines, random_key, detect_single_byte_xor};

static KEY: OnceLock<Vec<u8>> = OnceLock::new();

fn gen_key() -> &'static Vec<u8> {
    KEY.get_or_init(|| random_key(16))
}

fn ctr_encrypt(lines: Vec<String>) -> Vec<Vec<u8>> {
    let mut ctxts: Vec<Vec<u8>> = Vec::new();

    for l in 0..lines.len() {
        let input: Vec<u8> = BASE64_STANDARD.decode(lines[l].as_bytes()).unwrap();
        
        ctxts.push(aes_ctr(&input, gen_key(), 0))
    }

    ctxts
}

// Copy-pasted for now cause i'm tired
fn break_fixed_nonce_ctr(ctxts: &Vec<Vec<u8>>) {
    let min_len: usize = 128;  

    let truncated: Vec<Vec<u8>> = ctxts
                .iter()
                .map(|c| c.iter().take(min_len).cloned().collect())
                .collect();

    let transposed: Vec<Vec<u8>> = transpose(&truncated);
    let mut keystream: Vec<u8> = Vec::new();

    for i in 0..transposed.len() {
        let result: (u8, Vec<u8>, f64) = detect_single_byte_xor(&transposed[i]);
        keystream.push(result.0 as u8);
    }

    for i in 0..ctxts.len() {
        let ptxt: Vec<u8> = ctxts[i].iter()
            .zip(keystream.iter())
            .map(|(&c, &k)| c ^ k)
            .collect();

        println!(
            "{:?}",
            String::from_utf8(ptxt).unwrap()
        )
    }

    fn transpose(ctxts: &Vec<Vec<u8>>) -> Vec<Vec<u8>> {
        if ctxts.is_empty() {
            return Vec::new();
        }
    
        let max_len = ctxts.iter().map(|v| v.len()).max().unwrap_or(0);
    
        (0..max_len).map(|i| {
                    ctxts.iter()
                         .filter_map(|c| c.get(i)) // skip if c[i] doesn't exist
                         .cloned() // copy the u8
                         .collect::<Vec<u8>>()
            }).collect()
    }
}

// Again, the keystream isn't fully recovered, but I can get the full plaintext from the results easily.
pub fn challenge_20(input: &str) {
    let lines: Vec<String> = file_to_lines(input);
    let ctxts: Vec<Vec<u8>> = ctr_encrypt(lines);
    break_fixed_nonce_ctr(&ctxts);
}