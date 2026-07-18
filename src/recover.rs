use crate::error::{Error, Result};
use crate::jwt::Token;
use malachite::Natural;
use malachite::base::num::arithmetic::traits::ModPow;
use malachite::base::num::arithmetic::traits::{Gcd, Pow};
use malachite::base::num::conversion::traits::PowerOf2Digits;
use sha2::{Digest, Sha256};

const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

pub fn recover_modulus(a: &Token, b: &Token, e: u32) -> Result<Natural> {
    let ka = multiple_of_n(a, e)?;
    let kb = multiple_of_n(b, e)?;
    let mut n = ka.gcd(kb);

    for d in 2u32..65536 {
        while &n % &Natural::from(d) == 0 {
            n = &n / &Natural::from(d);
        }
    }

    if verifies(a, e, &n)? {
        Ok(n)
    } else {
        Err(Error::UnableToRecoverModulus(
            "could not recover valid modulus".into(),
        ))
    }
}

fn multiple_of_n(token: &Token, e: u32) -> Result<Natural> {
    let signing_input = token.signing_input()?;
    let k = token.signature.len();
    let s = Natural::from_power_of_2_digits_desc(8, token.signature.iter().copied()).unwrap();
    let em = padded_hash(&signing_input, k);
    Ok(s.pow(e as u64) - em)
}

fn padded_hash(signing_input: &str, k: usize) -> Natural {
    let hash = Sha256::digest(signing_input.as_bytes());
    let mut t = SHA256_DIGEST_INFO.to_vec();
    t.extend_from_slice(&hash);

    let ps_len = k - t.len() - 3;

    let mut em = vec![0x00, 0x01];
    em.extend(&vec![0xFF; ps_len]);
    em.push(0x00);
    em.extend_from_slice(&t);

    Natural::from_power_of_2_digits_desc(8, em.iter().copied()).unwrap()
}

fn verifies(token: &Token, e: u32, n: &Natural) -> Result<bool> {
    let signing_input = token.signing_input()?;
    let k = token.signature.len();
    let s = Natural::from_power_of_2_digits_desc(8, token.signature.iter().copied()).unwrap();
    let em = padded_hash(&signing_input, k);
    Ok(s.mod_pow(Natural::from(e), n) == em)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::parse;
    use malachite::base::num::conversion::traits::FromStringBase;

    // Two real RS256 tokens signed with the same 2048-bit RSA key, e = 3.
    // (e = 3 keeps s^e small so the test runs instantly, e = 65537 produces a
    // very big integer causing the test to take longer to run)
    const TOKEN1: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UifQ.SgdsmbG-DOxqEyjuxsMLWypzAge4Rkud8iVASXP6JQ8Q_GNf13KgIp5btGwkGQSoUIRX_DGQmVsizbmn-E-bgGuwwLh4rZ0TKEJsJ-8ToWWhnBZHAl-05HUFSgVdKjhq-SC-gmLCN7CSOxv2xn1FF9-XEvLtPn5s8VWXCn_NoimCbHo_pm93vs4m4SMSf4Kx-2gqTRCVgx-gTuu0VMKW9FmxLXJZy2ILKr172n5vYQH9eUe7Cw5dclJNnHKwFR1qaWarI6HpceN49XhffWNM-sVEVIpHfoyA4W7NqWIr636fYhRSbEm3vKETO5uHbFliHCR3l46pr-eksCed3BeEKA";
    const TOKEN2: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYm9iIn0.Q6-bBQEploMXJ0ufcPMngDKrhAe6V-iUrR4GIHTYGf3mgexOGupAZz2eu3bKbiMFu4CpdfWmwuNNt0rUq4QhxV-cdu3Ch_wGaqZq6FPEKcvl-DJvFPGardrdiT3xAD8fZii_zNDjm33q1Dqbj16JQDwTvcOY4hPJM5ojB-MVqKSE-ziVL4VbLRuGemZmboFO5yNRWU8okKnt7bwS97hPzRwBItKpKhJ5tZ0N-6yEgKfMIs66eYYaWGBovTu7npf9TLuBRzVSvSTMkeH_rmGwMob1x7SgoCnVqyPU7N37KJI6JLRC4QjsAYjEntaSQ4no8lsr0nhra6gNhpDBHZqjZA";
    // The true modulus N of that key, in hex.
    const N_HEX: &str = "62f7e4aa417c7b20c777eeb886b340263a96e29dffaea50db333f7bbef9590cf6a5a83c5d7960340c2baf5b26147e11f12c6f3fbb9886b4d8e64524bef3ed85e7b8286fc5da95b3eb7be977a33b9461e6a6e61fdea820cd72ef8b345a896d9ba79dbbd09e72e93d459725e4260d41c5454d8640dc88540bd4c53ab8c83ee0c62491f358e56ebb72db9abd7583ada9399e2402974b4e592bfa7a890f10f0ce45a203cf64aa7d20020d43fb27480e36df9b3300dec3fb2ca5cd3be3e3ea79233837f81de6375d67aca67ef78662b1247231864a089eec3f3983a6715cf3e28030cb9cd9e328cbd67389e41cfc2ef0d59759bcf3547e347bfcb2285bf4161ba297b";

    #[test]
    fn em_has_correct_shape() {
        let k = 256; // 2048-bit modulus
        let em_num = padded_hash("hello.world", k);
        let bytes: Vec<u8> = em_num.to_power_of_2_digits_desc(8);

        assert_eq!(bytes[0], 0x01);
        assert_eq!(bytes[1], 0xFF);
        assert_eq!(bytes.len(), k - 1);
    }

    #[test]
    fn recovers_modulus_from_two_tokens() {
        let a = parse(TOKEN1).unwrap();
        let b = parse(TOKEN2).unwrap();
        let recovered = recover_modulus(&a, &b, 3).unwrap();
        let expected = Natural::from_string_base(16, N_HEX).unwrap();
        assert_eq!(recovered, expected);
    }

    // Full-size real-world case: e = 65537 (16 MB integers). Ignored by default;
    // run with: cargo test --release -- --ignored
    const T65537_1: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UiLCJhZG1pbiI6ZmFsc2V9.BY1OwTV4e7ywwT70rswyGku73qiULNjLCjlYTCrBGvmVEv32Qv9Yu9MgJn9oWGija-TiM0K6eFjIc7h5gHCuaJSnUOjPyqjb2vtCa3p-3PkWgaFk2bC5_xijYPvaMN8a7ropbInvgof_GA6LjC2cJSQTohwT6nhRLt9yxw_BSSAHwQ8PdlR8yLRWsGxhQ60jAcp5QgwvM1Jh4ZZmRGZQcrHOsXZchIJah9OxJRh8WB4DEqrKvPjRt8FnnBvw1pJQcUCgBbzT1iPhph5ldrZ0Ujhv0v2i-cz8VD6zv6IbO7Wd--rgzZCnkoPlQIoVTVPvcb3TC2enX1zvjx2u1lgmjg";
    const T65537_2: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYm9iIiwiYWRtaW4iOnRydWV9.KDJFqIhHmr_SM8l9IWdKHjda63F9rDaQuqa7HEaAlowahvPbE4a1SlgoeLakY2n-UskSxK0QmSR1DAGmlwY1aJ4VYwEfUBHTcwv57yyFn4lw2LdP5cWvY2E7Rb_5T01JJjonk3g0v4tcRpK1M12qmuZKni2EGm6ftnU10YjG5wBn4WEVZxZ393atY9bRA-KzvdIHmGGBouoiATsC7zJ_YznYakKteS229Xd50AMuRes4EghhYbjOzeyvCkWAkFT0X8fe0h1IJlYDWuxK8GCBS0IAF-XwhBRfe0Qo5Wdy0V-yTAmJFw9Vpe1Y7Qu1QtczG3yuzbi93zNoxKwEc5RCvQ";
    const N65537_HEX: &str = "654070a2fb74767f3fec6b1c7dc2ad1163937126818380428820fcbd5fc4185203d006713ba2c362b1d540abf57bee4d1ad53611c33d7a9919a0e8074e237b9b41b617a9db429f131036019158f8121d2488ecb872173f1cdc8797f318af227a85faa452df7975e4995ba4edae20eab5324b8f88e572638619f67aa68473dfe3c25895aa91896082d88db5618f600355dd5cb4e89fb7c67f5ae2088efee89db3769bd0b13fc12c1292b39d84f3dca3776a728a4e567c3236bc72969de1e604d3f7cd9e5baa694c9b16544735a21ecbbfe115bbde99a5206ca1cd9002ae95fef5792f4407190c1ab64822f55a49315bd05b8d6ec31298c3fff5df5094c4336399";

    #[test]
    #[ignore = "full-size e=65537; run with cargo test --release -- --ignored"]
    fn recovers_modulus_e65537() {
        let a = parse(T65537_1).unwrap();
        let b = parse(T65537_2).unwrap();
        let recovered = recover_modulus(&a, &b, 65537).unwrap();
        let expected = Natural::from_string_base(16, N65537_HEX).unwrap();
        assert_eq!(recovered, expected);
    }
}
