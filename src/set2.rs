use std::io::{self, Write};
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};

use crate::utils::base64_file_decode;

fn pkcs7(input: Vec<u8>, pad: usize) -> Vec<u8> {
    let mut padded:Vec<u8> = input;

    while padded.len() < pad {
        padded.push(0x04);
    }

    padded
}

// AES 128 ECB using a different crate. Openssl forces 32 bit buffer size.
fn aes_block_encrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher_key = GenericArray::from_slice(key);
    let mut block = *GenericArray::from_slice(input);
    let cipher = Aes128::new(cipher_key);

    cipher.encrypt_block(&mut block);

    block.to_vec()
}

fn aes_block_decrypt(input: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher_key = GenericArray::from_slice(key);
    let mut block = *GenericArray::from_slice(input);
    let cipher = Aes128::new(cipher_key);

    cipher.decrypt_block(&mut block);

    block.to_vec()
}

fn aes_cbc_decrypt(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut output: Vec<u8> = Vec::new();
    let mut previous_block: Vec<u8> = iv.to_vec();

    let mut data = input.to_vec();

    while data.len() % 16 != 0 {
        data.push(0x04);
    }

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

    let mut data = input.to_vec();

    while data.len() % 16 != 0 {
        data.push(0x04);
    }

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

pub fn set_2(part: &str, input: &str) {
    println!("Input: {}", input);

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