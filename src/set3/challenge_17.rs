use base64::prelude::*;
use std::sync::OnceLock;

use crate::set2::{aes_cbc_decrypt, aes_cbc_encrypt, validate_pkcs7};
use crate::utils::{random_key, strip_pkcs7_padding};

static KEY: OnceLock<Vec<u8>> = OnceLock::new();

fn gen_key() -> &'static Vec<u8> {
    KEY.get_or_init(|| random_key(16))
}

fn challenge_17_encrypt() -> (Vec<u8>, Vec<u8>) {
    let strings: Vec<&str> = vec![
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
    ];

    let index: i32 = rand::random_range(0..10);

    let iv: Vec<u8> = random_key(16);

    let ctxt = aes_cbc_encrypt(
        BASE64_STANDARD.decode(strings[index as usize]).unwrap().as_slice(),
        &gen_key(),
        &iv
    );

    //println!("{:?}", pkcs7(BASE64_STANDARD.decode(strings[index as usize]).unwrap(), 16));

    (ctxt, iv)
}

fn cbc_padding_oracle(ctxt: &Vec<u8>, iv: &Vec<u8>) -> bool {
    let ptxt: Vec<u8> = aes_cbc_decrypt(ctxt, gen_key(), &iv);

    if validate_pkcs7(&ptxt) {
        return true
    } else {
        return false
    }
}

fn padding_oracle_attack(ctxt: &Vec<u8>, iv: &Vec<u8>) -> Vec<u8> {
    let blocks: Vec<&[u8]> = ctxt.chunks(16).collect();
    let mut plaintext_blocks: Vec<Vec<u8>> = Vec::new();

    for block_index in (0..blocks.len()).rev() {
        let block = blocks[block_index];
        
        let prev_block = if block_index == 0 {
            iv.as_slice()
        } else {
            blocks[block_index - 1]
        };

        let mut zero_iv = vec![0u8; 16];
        let mut working_iv = prev_block.to_vec();

        for j in (0..16).rev() {
            let pad_val = (16 - j) as u8;

            for k in (j+1)..16 {
                working_iv[k] = zero_iv[k] ^ pad_val;
            }

            for i in 0..=255 {
                working_iv[j] = i;
                if cbc_padding_oracle(&block.to_vec(), &working_iv) {
                    if j == 15 {
                        working_iv[14] ^= 1;
                        let is_valid = cbc_padding_oracle(&block.to_vec(), &working_iv);
                        working_iv[14] ^= 1;
                    
                        if !is_valid {
                            continue;
                        }
                    }
                    zero_iv[j] = i ^ pad_val;
                    break;
                }
            }
        }

        let plaintext_block: Vec<u8> = zero_iv.iter()
            .zip(prev_block.iter())
            .map(|(&intermediate, &prev_byte)| intermediate ^ prev_byte)
            .collect();

        plaintext_blocks.push(plaintext_block);
    }

    plaintext_blocks.reverse();

    let ptxt: Vec<u8> = strip_pkcs7_padding(plaintext_blocks.concat());

    ptxt
}

pub fn challenge_17(input: &str) {
    println!("Not needed sorry: {}", input);
    let (ctxt, iv) = challenge_17_encrypt();

    let ptxt: Vec<u8> = padding_oracle_attack(&ctxt, &iv);
    println!("Plaintext: {:?}", String::from_utf8(ptxt).unwrap())
}