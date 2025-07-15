use base64::prelude::*;
use crate::set2::{aes_block_encrypt};

pub fn aes_ctr(input: &Vec<u8>, key: &[u8], nonce: u64) -> Vec<u8> {
    let input_blocks: Vec<&[u8]> = input.chunks(16).collect();
    let mut counter: u64 = 0;

    let mut output_blocks: Vec<u8> = Vec::new();

    for i in 0..input_blocks.len() {
        let mut ctr_block = Vec::new();
        ctr_block.extend_from_slice(&nonce.to_le_bytes());
        ctr_block.extend_from_slice(&counter.to_le_bytes());

        let intermediate: Vec<u8> = aes_block_encrypt(&ctr_block, key);

        let output_block: Vec<u8> = intermediate.iter()
            .zip(input_blocks[i].iter())
            .map(|(&a, &b)| a ^ b)
            .collect();

        output_blocks.extend(output_block);

        counter += 1;
    }

    output_blocks
}

pub fn challenge_18(input: &str) {
    let inp: Vec<u8> = BASE64_STANDARD.decode(input.as_bytes()).unwrap();
    let output: Vec<u8> = aes_ctr(
        &inp, 
        "YELLOW SUBMARINE".as_bytes(), 
        0
    );
    println!("Output: {:?}", BASE64_STANDARD.encode(output))
}

#[cfg(test)]
mod tests {
    use crate::set3::challenge_18::*;

    #[test]
    fn test_ctr_decrypt() {
        let input: &'static str = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==";
        let result: Vec<u8> = aes_ctr(
            &BASE64_STANDARD.decode(input.as_bytes()).unwrap(),
            "YELLOW SUBMARINE".as_bytes(),
            0
        );
        let expected: &'static str = "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby ";
        
        assert_eq!(String::from_utf8(result).unwrap(), expected)
    }
}