use std::io::{self, Write};
use openssl::symm::{encrypt, Cipher};
use std::fs;
use base64::prelude::*;

fn pkcs7(input: &str, pad: usize) -> Vec<u8> {
    let mut padded:Vec<u8> = input.as_bytes().to_vec();

    while padded.len() < pad {
        padded.push(0x04);
    }

    padded
}

fn aes_ecb_encrypt(input: &str, key: &str, test: bool) -> String {
    let data: Vec<u8> = input.as_bytes().to_vec();

    let key_bytes: &[u8] = key.as_bytes();
    let cipher: Cipher = Cipher::aes_128_ecb();

    let result: Vec<u8> = encrypt(cipher, key_bytes, None, &data).unwrap();

    BASE64_STANDARD.encode(result)
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
                        println!("{:?}", String::from_utf8(pkcs7(&input, block_length)).unwrap());
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
            let result: String = aes_ecb_encrypt(input, "YELLOW SUBMARINE", false);
            println!("{}", result);
        }
        _ => println!("Invalid part number or not implemented yet: {}", part),
    }
}

#[cfg(test)]
mod tests {
    use crate::set2::{aes_ecb_encrypt, pkcs7};

    #[test]
    fn test_pkcs7() {
        let input: &str = "YELLOW SUBMARINE";
        let padding: usize = 20;
        let expected: String = "YELLOW SUBMARINE\u{4}\u{4}\u{4}\u{4}".to_string();
        assert_eq!(
            expected,
            String::from_utf8(pkcs7(input, padding)).unwrap()
        )
    }

    #[test]
    fn test_ecb_encrypt() {
        let input: &str = "This is a test";
        let key: &str = "YELLOW SUBMARINE";
        let expected: &str = "7XjKdNGg6sogVoLhXYpEGw==";

        assert_eq!(
            expected,
            aes_ecb_encrypt(input, key, true)
        )
    }
}