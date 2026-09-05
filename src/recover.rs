use crate::error::{Error, Result};
use crate::jwt::Token;
use base64::Engine;
use malachite::Natural;
use malachite::base::num::arithmetic::traits::ModPow;
use malachite::base::num::arithmetic::traits::{Gcd, Pow};
use malachite::base::num::conversion::traits::PowerOf2Digits;
use sha2::{Digest, Sha256, Sha384, Sha512};

#[derive(Clone, Copy)]
enum ShaKind {
    Sha256,
    Sha384,
    Sha512,
}

const SHA256_DIGEST_INFO: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

const SHA384_DIGEST_INFO: [u8; 19] = [
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
    0x00, 0x04, 0x30,
];

const SHA512_DIGEST_INFO: [u8; 19] = [
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
    0x00, 0x04, 0x40,
];

impl ShaKind {
    fn from_alg(alg: &str) -> Result<Self> {
        match alg {
            "RS256" => Ok(ShaKind::Sha256),
            "RS384" => Ok(ShaKind::Sha384),
            "RS512" => Ok(ShaKind::Sha512),
            other => Err(Error::UnsupportedAlg(format!(
                "Unsupported algorithm for recovery: {other}"
            ))),
        }
    }

    fn digest_info(&self, signing_bytes: &[u8]) -> Vec<u8> {
        match self {
            ShaKind::Sha256 => {
                let hash = Sha256::digest(signing_bytes);
                let mut t = SHA256_DIGEST_INFO.to_vec();
                t.extend_from_slice(&hash);
                t
            }
            ShaKind::Sha384 => {
                let hash = Sha384::digest(signing_bytes);
                let mut t = SHA384_DIGEST_INFO.to_vec();
                t.extend_from_slice(&hash);
                t
            }
            ShaKind::Sha512 => {
                let hash = Sha512::digest(signing_bytes);
                let mut t = SHA512_DIGEST_INFO.to_vec();
                t.extend_from_slice(&hash);
                t
            }
        }
    }
}

pub fn recover_modulus(a: &Token, b: &Token, e: u32) -> Result<Natural> {
    if a.alg() != b.alg() {
        return Err(Error::AlgorithmMismatch(
            "Both token algorithms need to match".into(),
        ));
    }

    let alg = ShaKind::from_alg(a.alg())?;

    let ka = multiple_of_n(a, alg, e)?;
    let kb = multiple_of_n(b, alg, e)?;
    let mut n = ka.gcd(kb);

    for d in 2u32..65536 {
        while &n % &Natural::from(d) == 0 {
            n = &n / &Natural::from(d);
        }
    }

    if verifies(a, alg, e, &n)? {
        Ok(n)
    } else {
        Err(Error::UnableToRecoverModulus(
            "could not recover valid modulus".into(),
        ))
    }
}

fn multiple_of_n(token: &Token, alg: ShaKind, e: u32) -> Result<Natural> {
    let signing_input = token.signing_input()?;
    let k = token.signature.len();
    let s = Natural::from_power_of_2_digits_desc(8, token.signature.iter().copied()).unwrap();
    let em = padded_hash(&signing_input, alg, k)?;
    Ok(s.pow(e as u64) - em)
}

fn padded_hash(signing_input: &str, alg: ShaKind, k: usize) -> Result<Natural> {
    let t = alg.digest_info(signing_input.as_bytes());

    let ps_len = k.checked_sub(t.len() + 3).ok_or_else(|| {
        Error::InvalidToken(format!(
            "signature is {k} bytes, too short to hold a {} byte digest",
            t.len()
        ))
    })?;

    let mut em = vec![0x00, 0x01];
    em.extend(&vec![0xFF; ps_len]);
    em.push(0x00);
    em.extend_from_slice(&t);

    Ok(Natural::from_power_of_2_digits_desc(8, em.iter().copied()).unwrap())
}

fn verifies(token: &Token, alg: ShaKind, e: u32, n: &Natural) -> Result<bool> {
    let signing_input = token.signing_input()?;
    let k = token.signature.len();
    let s = Natural::from_power_of_2_digits_desc(8, token.signature.iter().copied()).unwrap();
    let em = padded_hash(&signing_input, alg, k)?;
    if &s >= n {
        return Ok(false);
    }
    Ok(s.mod_pow(Natural::from(e), n) == em)
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let be = n.to_be_bytes();
    let start = be.iter().position(|&b| b != 0).unwrap();
    let trimmed = &be[start..];
    let mut out = vec![0x80 | trimmed.len() as u8];
    out.extend_from_slice(trimmed);
    out
}

fn der_integer(value: &Natural) -> Vec<u8> {
    let mut content: Vec<u8> = value.to_power_of_2_digits_desc(8);
    if content.first().is_none_or(|&b| b & 0x80 != 0) {
        content.insert(0, 0x00); // keep a high top bit from reading as negative
    }
    let mut out = vec![0x02];
    out.extend(der_len(content.len()));
    out.extend(content);
    out
}

fn der_sequence(elements: &[&[u8]]) -> Vec<u8> {
    let content = elements.concat();
    let mut out = vec![0x30];
    out.extend(der_len(content.len()));
    out.extend(content);
    out
}

fn rsa_public_key_der(n: &Natural, e: u32) -> Vec<u8> {
    let modulus = der_integer(n);
    let exponent = der_integer(&Natural::from(e));
    der_sequence(&[modulus.as_slice(), exponent.as_slice()])
}

// rsaEncryption OID (1.2.840.113549.1.1.1) with NULL parameters
const RSA_ALGORITHM_ID: [u8; 15] = [
    0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00,
];

fn spki_der(n: &Natural, e: u32) -> Vec<u8> {
    let pkcs1 = rsa_public_key_der(n, e);

    let mut bit_string_body = vec![0x00]; // unused-bits count
    bit_string_body.extend_from_slice(&pkcs1);
    let mut bit_string = vec![0x03];
    bit_string.extend(der_len(bit_string_body.len()));
    bit_string.extend(bit_string_body);

    der_sequence(&[RSA_ALGORITHM_ID.as_slice(), bit_string.as_slice()])
}

fn pem_block(der: &[u8], label: &str, wrap: bool) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let body = if wrap {
        b64.as_bytes()
            .chunks(64)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        b64
    };
    format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----")
}

pub fn public_key_pem(n: &Natural, e: u32) -> String {
    format!("{}\n", pem_block(&spki_der(n, e), "PUBLIC KEY", true))
}

pub fn public_key_variants(n: &Natural, e: u32) -> Vec<String> {
    let pkcs1 = rsa_public_key_der(n, e);
    let spki = spki_der(n, e);

    let mut out = Vec::new();
    for (der, label) in [
        (pkcs1.as_slice(), "RSA PUBLIC KEY"),
        (spki.as_slice(), "PUBLIC KEY"),
    ] {
        for wrap in [true, false] {
            let block = pem_block(der, label, wrap);
            out.push(format!("{block}\n"));
            out.push(block);
        }
    }
    out
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
        let alg = ShaKind::Sha256;
        let k = 256; // 2048-bit modulus
        let em_num = padded_hash("hello.world", alg, k).unwrap();
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

    const T384_1: &str = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UifQ.bJuOIfi9u69cV-LNeGNDU1StAyo_ig7ywR_BxjeZcfJvM50N2MaV3RS5s5Waqw4hRiV-WNb0gyeyFNYxAipp3DoP8dKpQuyDqlmmi0hzWwWU9pjqus_v9yUBrbE-SwjNOxPNRp-BhwcbdHNl9-vKVztCktD38TSAewMgXPx2TbF2OFB-xCOnXViwAKSgYVh15sBQvN_JMWXvIzWGDnpMJE_O-M65UhPpdoergpKyI_vGxG8KreXZZF2j8Cdg6XI-FoPuxDAUjFY_iH4uw_cksf_QYsc4mMe7gAYXQSaSBSQ3hagCaVHQtxwAy7Ly2v7JF2p3Mw9_C9ZW-d7wUROBuw";
    const T384_2: &str = "eyJhbGciOiJSUzM4NCIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYm9iIn0.F64c0PnDctHNqUnfX3EZ8zlmsVBbUbuCv1tKoYvahSKFn7BY0FcTlQ2UIqHesExIHa3WHngKGTT-2pMdAAXw5Lnw8lHt8cXHLHHKOP3OtYndZIrRHHowAN_IXOvqQoaMkZO9PFIgZBMp4q350E_JBOxyfauj2g6L0wODe1a1btHCVy-510sl0bKo5OzO2a3sQ5DbFpHJAMCGoHInZ78uVxamERououGiJRKGD1a5OEKDrwwDyLPk9mBRof2gfvGADFx1RBPjefSC5QvDfgoWcQ-YBMQrbzAM9SnHmDYa22KThPh4ekOiDEyb2sP207JMsFyVR4i4Z-Dva6WrgHkP3Q";
    const N384_HEX: &str = "e2bc36e6416dc7e17e9a35885f3932d3e59de0d4deebcb157dd9b29db9814e4d2b9ccdcac4b7d61afb5abdf089a44f116c2d19aae629892f55ef016f2570babd6a0940d4c23fbf438246b409b29752016934b3d703d39f7acce28b838f46ad6c1c506b4a085f6ef2aed0a29560ceb831f78fa3c016fac12c3f1567e3bfbe0c91a6d6668ba814ad47c9bffcdf5a27dba963cdb8edf74ffa363f0521658e34ca456f6a833a76b1fd0e3ecfff00e77f34a42f4421eca22fb08bafd02fad24e7af15ae529e897b86492e1ed6abf7cb0c6d3013fe7b9bbb4ff275a8cd749ea42c57d539a1f2c0a40312ed593a2f4c2b156ef8c08384523176a5c88a6e79f18ffd26e5";

    const T512_1: &str = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWxpY2UifQ.DYeX6qyu0SaD_MyRR4SihhltdxNO2_9o29oUmPYVLb0fMSMxVkyMU7PcguproYBz1UZVWw2Rhh8Dmg2wFkI2Jx7PM-EY0AU1O495ArgPxSvfq_0lPCidBsU8FIfEAFaFHwSxWCJD3tWlEkSSZXII8r_QiztC5lwnPP8Pj8PwgZsr6ypoU9q80cAMY-jrzbbg9h2KCgWSDvoy8Ny7QWm3QXyAQaYhK5vSa_s3ZC-XlANHaC5n84JdWHdsv0bHSquwSSUqIBKNWNjP1PZDLDMffh8GUMOA38ecbJns6_8s6EPUGUVk6bn7KreE1Fco5P18NwiGnxf31ao5hvvNCwinng";
    const T512_2: &str = "eyJhbGciOiJSUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYm9iIn0.N0cv_FZBM5k5yONueZBqxDGmIFhRMbLXn6MNUkWN2xEuzjac8LrZIw69ckAs2l1ziMstDh-4wRdd75fQKwo_Idu7wb60hL3kATgLRuWTcuLye2oruDbkinbTJR6ydxD6XnLa9qQ-TkMuG3jtvpTYd8Vf0fVGpo3Nwm479KYDrOTwwCBFpFATTjtAOLUmrR7eDnXiEk628GxDUgF3La3r7MMZnfUXfCVzHDeR7qiqQ2rkwRgLGVzCj4ce8NR3fE39hA9QpqVAYwCRi8C4t8FfjnU1v_lNVKEKMRfwWFcAb3yLy9l2JwlP0wBOVaPH4YXrCpNH25FqZpUPKfZZmUdFLQ";
    const N512_HEX: &str = "cb9eb50fb27abd7adf5a644fb88005977d0a93b98ab3492e3256581532b6f7456de5b3ddc4be64fe8593939ae275fddf9792de08dc7b6e882638a94b3fe0b75e06e54f913195a464e0c37b3aed0ad705b6c661a4204bdaa9854eba42fc84132835d6f97557c81dd7c63d1ebad0869bcec7bb7259d33f1e029938d0ceae117fa58b63d0b4a1b00a47d75e646aacb4d62fe7cac8d989f90264b98d4fa073dd208837b90e854d23428ba488cbeb02de1ae082c1a5a68504f47f566405817db3665bb5fb0b9ea4fde454f2424670bf156f56a8a5e18a67fb01ac5bebe1624023d81391dc4b8182f689fbfba6eb28dc669b6f7cf284e5b88ee36c9cc54f027e624adf";

    #[test]
    fn recovers_modulus_from_rs384_tokens() {
        let a = parse(T384_1).unwrap();
        let b = parse(T384_2).unwrap();
        let recovered = recover_modulus(&a, &b, 3).unwrap();
        let expected = Natural::from_string_base(16, N384_HEX).unwrap();
        assert_eq!(recovered, expected);
    }

    #[test]
    fn recovers_modulus_from_rs512_tokens() {
        let a = parse(T512_1).unwrap();
        let b = parse(T512_2).unwrap();
        let recovered = recover_modulus(&a, &b, 3).unwrap();
        let expected = Natural::from_string_base(16, N512_HEX).unwrap();
        assert_eq!(recovered, expected);
    }

    #[test]
    fn rejects_mismatched_algorithms() {
        let a = parse(T384_1).unwrap();
        let b = parse(T512_2).unwrap();
        assert!(recover_modulus(&a, &b, 3).is_err());
    }

    #[test]
    fn from_alg_accepts_rsa_family() {
        assert!(ShaKind::from_alg("RS256").is_ok());
        assert!(ShaKind::from_alg("RS384").is_ok());
        assert!(ShaKind::from_alg("RS512").is_ok());
    }

    #[test]
    fn from_alg_rejects_unsupported() {
        assert!(ShaKind::from_alg("HS256").is_err());
        assert!(ShaKind::from_alg("ES256").is_err());
        assert!(ShaKind::from_alg("none").is_err());
        assert!(ShaKind::from_alg("").is_err());
    }

    #[test]
    fn digest_info_has_correct_length() {
        assert_eq!(ShaKind::Sha256.digest_info(b"hello.world").len(), 51);
        assert_eq!(ShaKind::Sha384.digest_info(b"hello.world").len(), 67);
        assert_eq!(ShaKind::Sha512.digest_info(b"hello.world").len(), 83);
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

    #[test]
    fn der_len_short_and_long_form() {
        assert_eq!(der_len(2), vec![0x02]);
        assert_eq!(der_len(127), vec![0x7f]);
        assert_eq!(der_len(128), vec![0x81, 0x80]);
        assert_eq!(der_len(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn der_integer_pads_when_high_bit_set() {
        // 0x80 has its top bit set, so it needs a 0x00 sign pad.
        assert_eq!(
            der_integer(&Natural::from(0x80u32)),
            vec![0x02, 0x02, 0x00, 0x80]
        );
        // 0x7f does not.
        assert_eq!(der_integer(&Natural::from(0x7fu32)), vec![0x02, 0x01, 0x7f]);
    }

    #[test]
    fn spki_pem_has_armor() {
        let n = Natural::from_string_base(16, N_HEX).unwrap();
        let pem = public_key_pem(&n, 65537);
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert!(pem.trim_end().ends_with("-----END PUBLIC KEY-----"));
        assert!(pem.ends_with('\n'));
    }

    #[test]
    fn variants_are_byte_distinct() {
        let n = Natural::from_string_base(16, N_HEX).unwrap();
        let variants = public_key_variants(&n, 65537);
        assert_eq!(variants.len(), 8);
        let unique: std::collections::HashSet<_> = variants.iter().collect();
        assert_eq!(unique.len(), 8);
    }

    #[test]
    fn padded_hash_rejects_short_signature() {
        assert!(padded_hash("hello.world", ShaKind::Sha512, 64).is_err());
    }
}
