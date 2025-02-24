pub fn set_3(challenge: &usize, input: &str) {
    println!("Input: {input}");

    match challenge {
        17 => {
            println!("challenge 17")
        }
        _ => println!("Invalid challenge number or not implemented yet: {}", challenge),
    }
}