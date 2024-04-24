use hex;
use base64::{Engine as _, engine::general_purpose};

#[cfg(test)]
mod tests {
    use crate::set1::{b16_to_b64, fixed_xor, single_byte_xor};

    #[derive(PartialEq, Debug)]
    enum Part3Result { Char(char), String(String) }

    #[test]
    fn part_1() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
        assert_eq!(expected, b16_to_b64(input));
    }

    #[test]
    fn part_2() {
        let input = "1c0111001f010100061a024b53535009181c";
        let target = "686974207468652062756c6c277320657965";
        let expected = "746865206b696420646f6e277420706c6179";
        assert_eq!(expected, fixed_xor(input, target));
    }

    #[test]
    fn part_3() {
        let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
        let expected = vec![
            Part3Result::Char('X'), 
            Part3Result::String("Cooking MC's like a pound of bacon".to_string())
        ];
        let result = vec![
            Part3Result::Char(single_byte_xor(input).unwrap().0), 
            Part3Result::String(single_byte_xor(input).unwrap().1)
        ];
        assert_eq!(expected, result);
    }
}

fn b16_to_b64(input: &str) -> String {
    let bytes = hex::decode(input)
        .expect("Invalid input string");
    let result = general_purpose::STANDARD.encode(bytes);
    result
}

fn fixed_xor(input: &str, target: &str) -> String {
    let target_bytes = hex::decode(target)
        .expect("Invalid input string");
    let input_bytes = hex::decode(input)
        .expect("Invalid input string");

    if input_bytes.len() != target_bytes.len() { panic!("Inputs should have the same length") }

    let mut result = vec![];

    for (x, y) in input_bytes.iter().enumerate() {
        result.push(y ^ target_bytes[x]);
    }

    hex::encode(result)
}

fn single_byte_xor(input: &str) -> Option<(char, String)> {
    let input_bytes = hex::decode(input)
        .expect("Invalid input string");
    let mut scores = vec![];
    let mut result = vec![];

    for i in 0..=127 {
        let mut score = 0.000;
        input_bytes.iter().for_each(|c| {
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
    }
    if let Some(max_tuple) = scores.iter().max_by(|(_, a), (_, b)| a.partial_cmp(b).unwrap()) {
        let (max_int, _max_float) = max_tuple;
        input_bytes.iter().for_each(|c| {
            result.push((c ^ max_int) as char);
        });
        Some((*max_int as char, result.iter().collect()))
    } else { None }
}

pub fn test(part: &str, input: &str) {
    println!("Input: {input}");
    match part {
        "1" => {
            println!("Base 64: {}", b16_to_b64(input));
        },
        "2" => {
            // Should be rewritten to allow target to be inputted using the CLI
            let target = "686974207468652062756c6c277320657965";
            println!("Target: {target}");
            println!("XOR Result: {}", fixed_xor(input, target));
        },
        "3" => {
            println!("Found: {:?}", single_byte_xor(input));
        },
        _ => println!("wah")
    }
}