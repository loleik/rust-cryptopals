use std::io::{self, Write};

fn pkcs7(input: &str, pad: usize) -> Vec<u8> {
    let mut padded:Vec<u8> = input.as_bytes().to_vec();

    while padded.len() < pad {
        padded.push(0x04);
    }

    padded
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
        _ => println!("Invalid part number or not implemented yet: {}", part),
    }
}

#[cfg(test)]
mod tests {
    use crate::set2::pkcs7;

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
}