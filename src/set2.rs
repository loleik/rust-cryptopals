use std::io::{self, Write};
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use rand::prelude::*;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::OnceLock;
use regex::Regex;

static CHALLENGE_12: OnceLock<Vec<u8>> = OnceLock::new();
static CHALLENGE_14: OnceLock<Vec<u8>> = OnceLock::new();

fn gen_key() -> &'static Vec<u8> {
    CHALLENGE_12.get_or_init(|| random_key(16))
}
fn gen_prefix() -> &'static Vec<u8> {
    CHALLENGE_14.get_or_init(|| random_key(rand::rng().random_range(5..=10)))
}

use crate::utils::{base64_file_decode, random_key, test_ecb, strip_pkcs7_padding};

fn pkcs7(input: Vec<u8>, block_size: usize) -> Vec<u8> {
    let mut padded:Vec<u8> = input.clone();
    let padding: usize = block_size - (input.len() % block_size);

    while padded.len() % block_size != 0 {
        padded.push(padding as u8);
    }

    padded
}

// AES 128 ECB using a different crate. Openssl forces 32 bit buffer size.
fn aes_block_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher_key: &GenericArray<u8, _> = GenericArray::from_slice(key);
    let cipher: Aes128 = Aes128::new(cipher_key);

    let mut encrypted_blocks: Vec<u8> = Vec::new();

    for block in input.chunks(16) {
        let mut block_array: GenericArray<u8, _> = GenericArray::clone_from_slice(block);
        cipher.encrypt_block(&mut block_array);
        encrypted_blocks.extend_from_slice(&block_array);
    }

    encrypted_blocks
}

fn aes_block_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher_key = GenericArray::from_slice(key);
    let cipher = Aes128::new(cipher_key);

    let mut decrypted_blocks: Vec<u8> = Vec::new();

    for block in input.chunks(16) {
        let mut block_array: GenericArray<u8, _> = GenericArray::clone_from_slice(block);
        cipher.decrypt_block(&mut block_array);
        decrypted_blocks.extend_from_slice(&block_array);
    }

    decrypted_blocks
}

fn aes_cbc_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let mut previous_block: Vec<u8> = iv.to_vec();

    let data: Vec<u8> = pkcs7(input.to_vec(), 16);

    for block in data.chunks(16) {
        let decrypted = aes_block_decrypt(block, key);

        let mut xored: Vec<u8> = Vec::new();
        for (i, byte) in decrypted.iter().enumerate() {
            xored.push(byte ^ previous_block[i]);
        }

        output.extend(xored);
        previous_block = block.to_vec();
    }

    output
}

fn aes_cbc_encrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let mut previous_block: Vec<u8> = iv.to_vec();

    let data: Vec<u8> = pkcs7(input.to_vec(), 16);

    for block in data.chunks(16) {
        let mut xored: Vec<u8> = Vec::new();
        for (i, byte) in block.iter().enumerate() {
            xored.push(byte ^ previous_block[i]);
        }

        let encrypted = aes_block_encrypt(&xored, key);

        output.extend(encrypted.clone());
        previous_block = encrypted;
    }

    output
}

fn encryption_oracle(input: &[u8]) -> Vec<u8> {
    let mut rng: ThreadRng = rand::rng();

    let data: Vec<u8> = pkcs7(input.to_vec(), 16);

    let mut encrypted: Vec<u8> = random_key(rng.random_range(5..=10));
    let end: Vec<u8> = random_key(rng.random_range(5..=10));

    let result: Vec<u8> = if rng.random_bool(0.5) {
        aes_cbc_encrypt(
            data.as_slice(),
            random_key(16).as_slice(),
            random_key(16).as_slice()
        )
    } else {
        aes_block_encrypt(
            data.as_slice(),
            random_key(16).as_slice()
        )
    };

    encrypted.extend(result);
    encrypted.extend(end);

    encrypted
}

// This works provided the message is long enough to detect repeated blocks.
// i.e. chosen ciphertext attack.
fn inspect_oracle(input: Vec<u8>) -> String {
    let num_blocks: usize = input.len() / 16;

    let blocks: Vec<&[u8]> = input.chunks(16).take(num_blocks).collect::<Vec<_>>();

    let unique: HashSet<&[u8]> = blocks.iter().cloned().collect();

    let identical: usize = blocks.len() - unique.len();

    if identical > 0 {
        "ECB Mode".to_string()
    } else {
        "CBC Mode".to_string()
    }
}

fn ecb_oracle(input: &[u8]) -> Vec<u8> {
    let key: &[u8] = gen_key().as_slice();

    let mut data: Vec<u8> = input.to_vec();

    data.extend(base64_file_decode("input.txt"));

    data = pkcs7(data, 16);

    let encrypted: Vec<u8> = aes_block_encrypt(
            data.as_slice(),
            key
    );

    encrypted
}

fn inspect_c12(input: &[u8]) -> Vec<u8> {
    let mut i: usize = 0;
    let mut input_mut: Vec<u8> = input.to_vec();
    let mut prev_ctxt: Vec<u8> = Vec::new();
    let block_size: usize;

    loop {
        let ctxt: Vec<u8> = ecb_oracle(&input_mut);

        let try_block: Vec<u8> = ctxt[0..input_mut.len()-1].to_vec();
        let prev_block: Vec<u8> = if i > 0 {
            prev_ctxt[0..input_mut.len()-1].to_vec()
        } else {
            Vec::new()
        };

        if try_block == prev_block && try_block.len() > 0 {
            println!("BLOCK SIZE = {}", try_block.len());
            block_size = try_block.len();
            break;
        } else {
            prev_ctxt = ctxt;
        }

        i += 1;
        input_mut.push(input[0]);
    }

    // Sufficiently long to cause repeated blocks
    let ecb_check: [u8; 32] = [input[0]; 32];
    let test_ctxt: Vec<u8> = ecb_oracle(&ecb_check);
    let size: usize = test_ctxt.len() - 32;

    if test_ecb(test_ctxt) { println!("ECB DETECTED") }

    let mut test_input: Vec<u8> = vec![input[0]; block_size];
    let mut working_block: VecDeque<u8> = VecDeque::from(test_input.clone());
    let mut decrypted: Vec<u8> = Vec::new();
    let mut x: usize = 0;
    let mut blocks_found: usize = 0;

    loop {
        let mut dict: HashMap<Vec<u8>, u8> = HashMap::new();

        for i in 0..=255 {
            test_input[block_size - 1] = i;
            let ctxt: Vec<u8> = ecb_oracle(&test_input);
            dict.insert(ctxt[0..block_size].to_vec(), i);
        }

        let modifier: usize = block_size - (x % block_size) - 1;

        let actual: Vec<u8> = ecb_oracle(
            vec![input[0]; modifier].as_slice()
        );

        let relevant_block: Vec<u8> = actual[blocks_found * block_size..(blocks_found + 1) * block_size].to_vec();

        working_block[0] = *dict.get(&relevant_block).unwrap();
        working_block.push_front(*dict.get(&relevant_block).unwrap());
        working_block.pop_back();

        test_input = working_block.iter().rev().cloned().collect();

        x += 1;

        decrypted.push(*dict.get(&relevant_block).unwrap());

        if x % block_size == 0 {
            blocks_found += 1;
        }

        if x == size - 6 {
            break;
        }
    }

    decrypted
}

fn k_equals_v(input: &str) -> HashMap<String, String> {
    let re: Regex = Regex::new(r"^([a-zA-Z0-9]+=[a-zA-Z0-9@._-]+)(?:&[a-zA-Z0-9]+=[a-zA-Z0-9@._-]+)*$").unwrap();

    if !re.captures(input).is_some() {
        println!("Invalid input: {}", input);
        return HashMap::new()
    } else {
        let mut map: HashMap<String, String> = HashMap::new();

        for pair in input.split('&') {
            let kv: Vec<&str> = pair.split('=').collect();
            map.insert(kv[0].to_string(), kv[1].to_string());
        }

        map
    }
}

fn profile_for(input: &str) -> String {
    let re: Regex = Regex::new(r"^[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z0-9]+$").unwrap();

    if !re.captures(input).is_some() {
        println!("Invalid input");
        return "".to_string()
    } else {
        "email=".to_string() + input + "&uid=10&role=user"
    }
}

fn challenge_13_encrypt(input: &[u8]) -> Vec<u8> {
    let key: &[u8] = gen_key().as_slice();

    let mut data: Vec<u8> = input.to_vec();

    data = pkcs7(data, 16);

    let encrypted: Vec<u8> = aes_block_encrypt(
            data.as_slice(),
            key
    );

    encrypted
}

fn challenge_13_decrypt(input: &[u8]) -> Vec<u8> {
    let key: &[u8] = gen_key().as_slice();

    let decrypted: Vec<u8> = aes_block_decrypt(
        input,
        key
    );

    strip_pkcs7_padding(decrypted)
}

fn ch14_oracle(input: &[u8]) -> Vec<u8> {
    let key: &[u8] = gen_key().as_slice();
    let prefix: &[u8] = gen_prefix().as_slice();

    let mut data: Vec<u8> = prefix.to_vec();
    data.extend(input.to_vec());
    data.extend(base64_file_decode("input.txt"));
    data = pkcs7(data, 16);

    let encrypted: Vec<u8> = aes_block_encrypt(
            data.as_slice(),
            key
    );

    encrypted
}

fn c14_inspect(input: &[u8]) {
    let mut i: usize = 0;
    let mut input_mut: Vec<u8> = input.to_vec();
    let block_size: usize;
    let empty_text: Vec<u8> = ch14_oracle(b"");

    // Determine the block size. We need this to work out the prefix length.
    loop {
        let ctxt: Vec<u8> = ch14_oracle(&input_mut);

        if ctxt.len() > empty_text.len() {
            println!("BLOCK SIZE = {}", ctxt.len() - empty_text.len());
            block_size = ctxt.len() - empty_text.len();
            break;
        }

        i += 1;
        input_mut.push(input[0]);
    }

    assert_eq!(block_size, 16);

    // Now check it si ecb.
    let ecb_check: [u8; 32] = [input[0]; 32];
    let test_ctxt: Vec<u8> = ch14_oracle(&ecb_check);

    if test_ecb(test_ctxt) { println!("ECB DETECTED") }
    
    // Now work out the current prefix length.
    i = 0;
    input_mut = input.to_vec();
    let mut prev_ctxt: Vec<u8> = Vec::new();
    let prefix_size: usize;

    loop {
        let ctxt: Vec<u8> = ch14_oracle(&input_mut);

        let try_block: Vec<u8> = ctxt[0..input_mut.len()-1].to_vec();
        let prev_block: Vec<u8> = if i > 0 {
            prev_ctxt[0..input_mut.len()-1].to_vec()
        } else {
            Vec::new()
        };

        if try_block == prev_block && try_block.len() > 0 {
            prefix_size = block_size - try_block.len();
            println!("PREFIX SIZE = {}", prefix_size);
            break;
        } else {
            prev_ctxt = ctxt;
        }

        i += 1;
        input_mut.push(input[0]);
    }

    let size: usize = empty_text.len() - prefix_size;

    let mut test_input: Vec<u8> = vec![input[0]; block_size];
    let mut working_block: VecDeque<u8> = VecDeque::from(test_input.clone());
    let mut decrypted: Vec<u8> = Vec::new();
    let mut x: usize = 0;
    let mut blocks_found: usize = 0;

    loop {
        let mut dict: HashMap<Vec<u8>, u8> = HashMap::new();

        for i in 0..=255 {
            println!("{} {:?}", i, test_input);
            test_input[block_size - 1] = i;
            let ctxt: Vec<u8> = wrapper_oracle(
                ch14_oracle(&test_input)
                , prefix_size, block_size
            );
            dict.insert(ctxt[0..block_size].to_vec(), i);
        }

        let modifier: usize = block_size - (x % block_size) - 1;

        let actual: Vec<u8> = wrapper_oracle(ch14_oracle(
            vec![input[0]; modifier].as_slice()
        ), prefix_size, block_size);

        let relevant_block: Vec<u8> = actual[blocks_found * block_size..(blocks_found + 1) * block_size].to_vec();

        working_block[0] = *dict.get(&relevant_block).unwrap();
        working_block.push_front(*dict.get(&relevant_block).unwrap());
        working_block.pop_back();

        test_input = working_block.iter().rev().cloned().collect();

        x += 1;

        decrypted.push(*dict.get(&relevant_block).unwrap());

        if x % block_size == 0 {
            blocks_found += 1;
        }

        if x == size - 6 {
            break;
        }
    }
}

// Turns the problem from challenge 14 into a challenge 12 problem.
fn wrapper_oracle(ctxt: Vec<u8>, prefix_size: usize, block_size: usize) -> Vec<u8> {
    let mut new_ctxt: Vec<u8> = pkcs7(ctxt[0..prefix_size].to_vec(), block_size);
    new_ctxt.extend(ctxt[prefix_size..].to_vec());
    new_ctxt = new_ctxt[block_size..].to_vec();
    new_ctxt
}

pub fn set_2(part: &str, input: &str) {
    println!("Input: {} {}", input, input.len());

    match part {
        "1" => {
            loop {
                print!("Enter desired block length: ");

                io::stdout().flush().unwrap();
        
                let mut block_input = String::new();
                io::stdin().read_line(&mut block_input).unwrap();
                let input_vec = block_input.split_whitespace().collect::<Vec<_>>();
        
                if input_vec.len() == 0 { continue }
                else if input_vec.len() > 1 {
                    println!("Please enter only one number");
                    continue
                }

                match input_vec[0].parse::<usize>() {
                    Ok(block_length) => {
                        println!("{:?}", String::from_utf8(pkcs7(input.as_bytes().to_vec(), block_length)).unwrap());
                        break
                    },
                    Err(_) => {
                        println!("Invalid input");
                        continue
                    }
                }
            }
        }
        "2" => {
            let key: &str = "YELLOW SUBMARINE";
            let iv: Vec<u8> = vec![0; 16];
            let data: Vec<u8> = base64_file_decode(input);
            let result: Vec<u8> = aes_cbc_decrypt(
                &data,
                key.as_bytes(), 
                iv.as_slice()
            );

            println!("{:?}", String::from_utf8(result).unwrap());
        }
        "3" => {
            let data: Vec<u8> = pkcs7(input.as_bytes().to_vec(), 16);
            let encrypted: Vec<u8> = encryption_oracle(data.as_slice());
            println!("Orace produced: {:?}", encrypted);
            println!("{}", inspect_oracle(encrypted))
        }
        "4" => {
            let data: &[u8] = input.as_bytes();
            let result: Vec<u8> = inspect_c12(data);

            println!("{:?}", String::from_utf8(result).unwrap());
        }
        "5" => {
            let mut data: Vec<u8> = input.as_bytes().to_vec();

            while data.len() < 29 {
                data.insert(0, 'e' as u8);
            }

            println!("Fake email: {} {}", String::from_utf8(data.clone()).unwrap(), data.len());

            let encrypted: Vec<u8> = challenge_13_encrypt(
                profile_for(
                    String::from_utf8(data).unwrap().as_str()
                ).as_bytes()
            );

            let mut blocks: Vec<&[u8]> = encrypted.chunks(16).collect::<Vec<_>>();

            let admin: Vec<u8> = challenge_13_encrypt("admin".as_bytes());

            blocks.remove(blocks.len() - 1);
            blocks.push(&admin.as_slice());

            let decrypted: Vec<u8> = challenge_13_decrypt(&blocks.concat());

            let profile: HashMap<String, String> = k_equals_v(&String::from_utf8(decrypted).unwrap());

            println!("Admin profile generated:");
            println!("{{");
            println!("    email: {}", profile.get("email").unwrap());
            println!("    uid: {}", profile.get("uid").unwrap());
            println!("    role: {}", profile.get("role").unwrap());
            println!("}}");
        }
        "6" => {
            c14_inspect(input.as_bytes());
        }
        _ => println!("Invalid part number or not implemented yet: {}", part),
    }
}

#[cfg(test)]
mod tests {
    use base64::{prelude::BASE64_STANDARD, Engine};

    use crate::set2::{aes_block_decrypt, aes_block_encrypt, aes_cbc_decrypt, aes_cbc_encrypt, pkcs7};

    #[test]
    fn test_pkcs7() {
        let input: &str = "YELLOW SUBMARINE";
        let padding: usize = 20;
        let expected: String = "YELLOW SUBMARINE\u{4}\u{4}\u{4}\u{4}".to_string();
        assert_eq!(
            expected,
            String::from_utf8(pkcs7(input.as_bytes().to_vec(), padding)).unwrap()
        )
    }

    #[test]
    fn test_block_encrypt() {
        let input: &str = "This is a test?!";
        let key: &str = "YELLOW SUBMARINE";
        let expected: &str = "SsY9vv18Zt6Cf9jSsHFwHg==";

        assert_eq!(
            expected,
            BASE64_STANDARD.encode(aes_block_encrypt(input.as_bytes(), key.as_bytes()))
        )
    }

    #[test]
    fn test_block_decrypt() {
        let input: Vec<u8> = BASE64_STANDARD.decode(
            "SsY9vv18Zt6Cf9jSsHFwHg=="
        ).unwrap();
        let key: &str = "YELLOW SUBMARINE";
        let expected: &str = "This is a test?!";

        assert_eq!(
            expected,
            String::from_utf8(aes_block_decrypt(&input, key.as_bytes())).unwrap()
        )
    }

    #[test]
    fn test_cbc_encrypt() {
        let input: &str = "This is a test?!";
        let key: &str = "YELLOW SUBMARINE";
        let iv: Vec<u8> = vec![0; 16];
        
        let expected: &str = "SsY9vv18Zt6Cf9jSsHFwHg==";

        assert_eq!(
            expected,
            BASE64_STANDARD.encode(aes_cbc_encrypt(input.as_bytes(), key.as_bytes(), iv.as_slice()))
        )
    }

    #[test]
    fn test_cbc_decrypt() {
        let input: Vec<u8> = BASE64_STANDARD.decode(
            "SsY9vv18Zt6Cf9jSsHFwHg=="
        ).unwrap();
        let key: &str = "YELLOW SUBMARINE";
        let expected: &str = "This is a test?!";
        let iv: Vec<u8> = vec![0; 16];

        assert_eq!(
            expected,
            String::from_utf8(aes_cbc_decrypt(&input, key.as_bytes(), iv.as_slice())).unwrap()
        )
    }
}