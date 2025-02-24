use base64::prelude::*;
use std::sync::OnceLock;

use crate::set2::{aes_cbc_decrypt, aes_cbc_encrypt, validate_pkcs7};
use crate::utils::random_key;

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

    (ctxt, iv)
}

fn cbc_padding_oracle(ctxt: &Vec<u8>, iv: Vec<u8>) -> bool {
    let ptxt: Vec<u8> = aes_cbc_decrypt(ctxt, gen_key(), &iv);

    println!("{:?}", String::from_utf8(ptxt.clone()).unwrap());

    if validate_pkcs7(&ptxt) {
        println!("Valid padding");
        return true
    } else {
        println!("Invalid padding");
        return false
    }
}

pub fn challenge_17(input: &str) {
    println!("Not used: {}", input);
    let (ctxt, iv) = challenge_17_encrypt();

    println!("{:?}", ctxt);
    println!("{:?}", iv);

    cbc_padding_oracle(&ctxt, iv);
}