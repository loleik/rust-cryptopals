#[derive(Debug, Copy, Clone)]
struct PARAMS {
    w: u32, n: u32, m: u32,
    a: u32,
    u: u32,
    s: u32, b: u32,
    t: u32, c: u32,
    l: u32,
    f: u32,
    lmask: u32, hmask: u32
}

fn mt_init(seed: u32, params: PARAMS) -> Vec<u32> {
    let mut mt: Vec<u32> = vec![ 0; params.n as usize];
    mt[0] = seed;

    for i in 1..params.n {
        mt[i as usize] = (params.f.overflowing_mul(
            mt[i as usize - 1] ^ (mt[i as usize - 1] >> (params.w - 2))
        ).0 + i) & 0xffffffff;
    }

    mt
}

fn mt_genrand(params: PARAMS, mt: &mut Vec<u32>, mti_in: u32) -> (u32, u32) {
    let mut mti: u32 = mti_in.clone();

    let mag01: Vec<u32> = vec![0x0, params.a];
    
    let mut y: u32;

    if mti >= params.n {
        for kk in 0..(params.n - params.m) {
            y = (
                mt[kk as usize] & params.hmask
            ) | (
                mt[kk as usize + 1] & params.lmask
            );

            mt[kk as usize] = 
                mt[(kk + params.m) as usize] ^ 
                (y >> 1) ^ 
                mag01[y as usize & 0x1];
        }

        for kk in (params.n - params.m)..(params.n - 1) {
            y = (
                mt[kk as usize] & params.hmask
            ) | (
                mt[kk as usize + 1] & params.lmask
            );

            mt[kk as usize] = 
                mt[(kk.overflowing_add(params.m.overflowing_sub(params.n).0)).0 as usize] ^
                (y >> 1) ^
                mag01[y as usize & 0x1];
        }

        y = (
            mt[params.n as usize - 1] & params.hmask
        ) | (
            mt[0] & params.lmask
        );

        mt[params.n as usize - 1] = 
            mt[params.m as usize - 1] ^
            (y >> 1) ^
            mag01[y as usize & 0x1];

        mti = 0; 
    }

    y = mt[mti as usize];
    mti += 1;

    y ^= y >> params.u;
    y ^= (y << params.s) & params.b;
    y ^= (y << params.t) & params.c;
    y ^= y >> params.l;

    (y, mti)
}

pub fn challenge_21(input: &str) {
    let seed: u32 = if !input.parse::<u32>().is_ok() {
        println!("Please enter a valid 32-bit seed value: {input}");
        println!("Using default seed: 5489");
        5489
    } else { input.parse::<u32>().unwrap() };

    // These are taken from Wikipedia:
    // https://en.wikipedia.org/wiki/Mersenne_Twister
    let params: PARAMS = PARAMS {
        w: 32, n: 624, m: 397,
        a: 0x9908B0DF,
        u: 11,
        s: 7, b: 0x9D2C5680,
        t: 15, c: 0xEFC60000,
        l: 18,
        f: 1812433253,
        lmask: 0x7fffffff, hmask: 0x80000000
    };

    let mut mti: u32 = params.n + 1;

    let mut mt: Vec<u32> = mt_init(seed, params);

    for _i in 0..11 {
        let out = mt_genrand(params, &mut mt, mti);
        mti = out.1;
        println!("{}", out.0);
    }
}

#[cfg(test)]
mod tests {
    use crate::set3::challenge_21::{mt_genrand, mt_init, PARAMS};

    #[test]
    fn test_mt19937() {
        let params: PARAMS = PARAMS {
            w: 32, n: 624, m: 397,
            a: 0x9908B0DF,
            u: 11,
            s: 7, b: 0x9D2C5680,
            t: 15, c: 0xEFC60000,
            l: 18,
            f: 1812433253,
            lmask: 0x7fffffff, hmask: 0x80000000
        };
    
        let mut mti: u32 = params.n + 1;
    
        let mut mt: Vec<u32> = mt_init(5489, params);

        let mut output = Vec::new();
    
        for _i in 0..100 {
            let out = mt_genrand(params, &mut mt, mti);
            mti = out.1;
            output.push(out.0)
        }

        // Values taken using code from https://www.guyrutenberg.com/2014/05/03/c-mt19937-example/
        // using https://www.cpp.sh/
        let expected: Vec<u32> = vec![
            3499211612,581869302,3890346734,3586334585,545404204,
            4161255391,3922919429,949333985,2715962298,1323567403,
            418932835,2350294565,1196140740,809094426,2348838239,
            4264392720,4112460519,4279768804,4144164697,4156218106,
            676943009,3117454609,4168664243,4213834039,4111000746,
            471852626,2084672536,3427838553,3437178460,1275731771,
            609397212,20544909,1811450929,483031418,3933054126,
            2747762695,3402504553,3772830893,4120988587,2163214728,
            2816384844,3427077306,153380495,1551745920,3646982597,
            910208076,4011470445,2926416934,2915145307,1712568902,
            3254469058,3181055693,3191729660,2039073006,1684602222,
            1812852786,2815256116,746745227,735241234,1296707006,
            3032444839,3424291161,136721026,1359573808,1189375152,
            3747053250,198304612,640439652,417177801,4269491673,
            3536724425,3530047642,2984266209,537655879,1361931891,
            3280281326,4081172609,2107063880,147944788,2850164008,
            1884392678,540721923,1638781099,902841100,3287869586,
            219972873,3415357582,156513983,802611720,1755486969,
            2103522059,1967048444,1913778154,2094092595,2775893247,
            3410096536,3046698742,3955127111,3241354600,3468319344
        ];

        assert_eq!(output, expected);
    }
}