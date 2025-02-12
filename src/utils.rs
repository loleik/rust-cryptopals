use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub fn file_to_lines(path: &str) -> Vec<String> {
    let mut output = Vec::new();

    // File hosts.txt must exist in the current path
    if let Ok(lines) = read_lines(path) {
        // Consumes the iterator, returns an (Optional) String
        for line in lines.map_while(Result::ok) {
            output.push(line);
        }
    }
    
    // The output is wrapped in a Result to allow matching on errors.
    // Returns an Iterator to the Reader of the lines of the file.
    fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
    where P: AsRef<Path>, {
        let file = File::open(filename)?;
        Ok(io::BufReader::new(file).lines())
    }

    output
}

pub fn letter_frequency(data: &Vec<u8>) -> Vec<(u8, f64)> {
    let mut scores: Vec<(u8, f64)> = Vec::new();

    for i in 0..=127 {
        let mut score: f64 = 0.000;
        data.iter().for_each(|c| {
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
    };

    scores
}