#[derive(Debug, Copy, Clone)]
struct PARAMS {
    w: u32, n: u32, m: u32, r: u32,
    a: u32,
    u: u32, d: u32,
    s: u32, b: u32,
    t: u32, c: u32,
    l: u32,
    f: u32,
    lmask: u32, hmask: u32
}

#[derive(Debug)]
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
                params.f.wrapping_mul(prev ^ (prev >> 30)).wrapping_add(i)
            );
        };

        MT19937 { state: state_vector, index: 0 }
    }

    fn twist(x: u32, params: PARAMS) -> u32 {
        if x % 2 == 1 { (x >> 1) ^ params.a}
        else { x >> 1 }
    }

    fn compute(mt: &mut MT19937, params: PARAMS) -> u32 {
        let x: u32 = mt.state[params.m as usize] ^ MT19937::twist(
            (mt.state[0] & params.hmask) + (mt.state[1] & params.lmask),
            params,
        );
    
        let mut y = x ^ ((x >> params.u) & params.d);
        y = y ^ ((y << params.s) & params.b);
        y = y ^ ((y << params.t) & params.c);
        let z: u32 = y ^ (y << params.l);

        mt.state.remove(0);
        mt.state.push(x);

        z
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
        lmask: 0xFFFFFFFF >> 1, hmask: 0xFFFFFFFF << 31
    };

    let seed: u32 = 54325;

    let mut mt19937: MT19937 = MT19937::initialize(seed, params);

    for i in 0..6 {
        println!("{}: {}", i, MT19937::compute(&mut mt19937, params))
    }
}