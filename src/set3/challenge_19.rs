use base64::prelude::*;
use std::sync::OnceLock;

use crate::set3::challenge_18::aes_ctr;
use crate::utils::{random_key, detect_single_byte_xor};

static KEY: OnceLock<Vec<u8>> = OnceLock::new();

fn gen_key() -> &'static Vec<u8> {
    KEY.get_or_init(|| random_key(16))
}

pub fn encryption_loop() -> Vec<Vec<u8>> {
    let strings: Vec<&'static str> = vec![
        "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==",
        "Q29taW5nIHdpdGggdml2aWQgZmFjZXM=",
        "RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==",
        "RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=",
        "SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk",
        "T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=",
        "UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==",
        "QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=",
        "T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl",
        "VG8gcGxlYXNlIGEgY29tcGFuaW9u",
        "QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==",
        "QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=",
        "QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==",
        "QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=",
        "VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==",
        "SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==",
        "SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==",
        "VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==",
        "V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==",
        "V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==",
        "U2hlIHJvZGUgdG8gaGFycmllcnM/",
        "VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=",
        "QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=",
        "VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=",
        "V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=",
        "SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==",
        "U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==",
        "U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=",
        "VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==",
        "QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu",
        "SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=",
        "VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs",
        "WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=",
        "SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0",
        "SW4gdGhlIGNhc3VhbCBjb21lZHk7",
        "SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=",
        "VHJhbnNmb3JtZWQgdXR0ZXJseTo=",
        "QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4="
    ];

    let mut ctxts: Vec<Vec<u8>> = Vec::new();

    for s in 0..strings.len() {
        let input: Vec<u8> = BASE64_STANDARD.decode(strings[s].as_bytes()).unwrap();
        
        ctxts.push(aes_ctr(&input, gen_key(), 0))
    }

    ctxts
}

fn break_fixed_nonce_ctr(ctxts: &Vec<Vec<u8>>) {
    let min_len: usize = 32; // 

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
            String::from_utf8_lossy(&ptxt)
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

// This shows enough of the plaintext to turn this into a known plaintext attack using hte source.
// Maybe I'll write that part in the future to get the whole keystream.
pub fn challenge_19(_input: &str) {
    let ctxts: Vec<Vec<u8>> = encryption_loop();

    break_fixed_nonce_ctr(&ctxts);
}