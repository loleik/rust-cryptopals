#[derive(Debug)]
struct PARAMS {
    w: u32, n: u32, m: u32, r: u32,
    a: u32,
    u: u32, d: u32,
    s: u32, b: u32,
    t: u32, c: u32,
    l: u32,
    f: u32,
    lmask: u32, rmask: u32
}

struct MT19937 {
    state: Vec<u32>,
    index: usize
}

impl MT19937 {
    fn initialize(seed: u32, params: PARAMS) -> MT19937 {
        let mut state_vector: Vec<u32> = vec![seed];
        for i in 1..params.n {
            let prev: u32 = state_vector[i as usize - 1];
            state_vector.push(
                params.f * (prev ^ (prev >> (params.w - 2))) + i
            );
        };

        MT19937 { state: state_vector, index: 0 }
    }
}

pub fn challenge_21(_input: &str) {
    // These are taken from Wikipedia:
    // https://en.wikipedia.org/wiki/Mersenne_Twister
    let params: PARAMS = PARAMS {
        w: 32, n: 624, m: 397, r: 31,
        a: 0x9908B0DF,
        u: 11, d: 0xFFFFFFFF,
        s: 7, b: 0x9D2C5680,
        t: 15, c: 0xEFC60000,
        l: 18,
        f: 1812433253,
        lmask: 0xFFFFFFFF << 31, rmask: 0xFFFFFFFF >> 1
    };

    let seed: u32 = 5489;

    println!("{:?}", params)
}