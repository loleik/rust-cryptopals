use std::{thread, time::{self, SystemTime, UNIX_EPOCH}};
use crate::utils::mt19937;

fn run_rng() -> u32 {
    let first_wait: time::Duration = time::Duration::from_secs(
        rand::random_range(40..1001)
    );

    thread::sleep(first_wait);

    let seed: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

    let second_wait: time::Duration = time::Duration::from_secs(
        rand::random_range(40..1001)
    );

    thread::sleep(second_wait);

    mt19937(seed, 2)[0]
}

fn crack_seed(target: u32) -> Option<u64> {
    let now: u64 = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

    for i in 40..1001 {
        let seed: u64 = now - i;
        if mt19937(seed, 2)[0] == target {
            println!("Seed found: {seed}");
            return Some(seed)
        }
    };

    None
}

pub fn challenge_22(input: &str) {
    println!("{input}: Sorry not needed here...");

    let output: u32 = run_rng();

    crack_seed(output);
}