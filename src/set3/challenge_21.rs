#[derive(Debug)]
struct MT19937 {
    w: u16, n: u16, m: u16, r: u16,
    a: u32,
    u: u16, d: u32,
    s: u16, b: u32,
    t: u16, c: u32,
    l: u16,
    f: u32
}

pub fn challenge_21(_input: &str) {
    // These are taken from Wikipedia:
    // https://en.wikipedia.org/wiki/Mersenne_Twister
    let coeffs: MT19937 = MT19937 {
        w: 32, n: 624, m: 397, r: 31,
        a: 0x9908B0DF,
        u: 11, d: 0xFFFFFFFF,
        s: 7, b: 0x9D2C5680,
        t: 15, c: 0xEFC60000,
        l: 18,
        f: 1812433253
    };

    println!("{:?}", coeffs)
}