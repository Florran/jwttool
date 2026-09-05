use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha384, Sha512};

use crate::error::{Error, Result};

type HmacSha256 = Hmac<Sha256>; // a type alias: "HMAC using SHA-256"
type HmacSha384 = Hmac<Sha384>;
type HmacSha512 = Hmac<Sha512>;

const ALGORITHMS: &[&str] = &["none", "HS256", "HS384", "HS512"];

pub struct Token {
    pub header: serde_json::Value,
    pub payload: serde_json::Value,
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy)]
pub enum HmacKind {
    HS256,
    HS384,
    HS512,
}

impl HmacKind {
    pub fn from_alg(alg: &str) -> Result<Self> {
        match alg {
            "HS256" => Ok(HmacKind::HS256),
            "HS384" => Ok(HmacKind::HS384),
            "HS512" => Ok(HmacKind::HS512),
            other => Err(Error::UnsupportedAlg(format!(
                "Unsupported algorithm for HMAC: {other}"
            ))),
        }
    }

    fn mac(&self, signing_input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        match self {
            HmacKind::HS256 => {
                let mut mac = HmacSha256::new_from_slice(key)?;
                mac.update(signing_input);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            HmacKind::HS384 => {
                let mut mac = HmacSha384::new_from_slice(key)?;
                mac.update(signing_input);
                Ok(mac.finalize().into_bytes().to_vec())
            }
            HmacKind::HS512 => {
                let mut mac = HmacSha512::new_from_slice(key)?;
                mac.update(signing_input);
                Ok(mac.finalize().into_bytes().to_vec())
            }
        }
    }
}

pub fn parse(encoded: &str) -> Result<Token> {
    let parts: Vec<&str> = encoded.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::InvalidToken("JWT has to be 3 parts!".into()));
    }

    let decoded_header_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
    let decoded_header = String::from_utf8(decoded_header_bytes)?;

    let decoded_payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
    let decoded_payload = String::from_utf8(decoded_payload_bytes)?;

    let token = Token {
        header: serde_json::from_str(&decoded_header)?,
        payload: serde_json::from_str(&decoded_payload)?,
        signature: URL_SAFE_NO_PAD.decode(parts[2])?,
    };

    Ok(token)
}

impl Token {
    pub fn encode(&self) -> Result<String> {
        let signing_input = self.signing_input()?;
        let encoded_signature = URL_SAFE_NO_PAD.encode(&self.signature);

        let encoded_token = [signing_input, encoded_signature].join(".");
        Ok(encoded_token)
    }

    pub fn alg(&self) -> &str {
        self.header["alg"].as_str().unwrap_or("")
    }

    pub fn set_alg(&mut self, alg: &str) -> Result<()> {
        if !ALGORITHMS.contains(&alg) {
            return Err(Error::InvalidAlgorithm("invalid alg".into()));
        }
        self.header["alg"] = serde_json::Value::from(alg);
        Ok(())
    }

    pub fn set_claim(&mut self, key: &str, value: serde_json::Value) {
        self.payload[key] = value;
    }

    pub fn set_header(&mut self, key: &str, value: serde_json::Value) {
        self.header[key] = value;
    }

    pub fn clear_signature(&mut self) {
        self.signature.clear();
    }

    pub fn signing_input(&self) -> Result<String> {
        let decoded_header_bytes = serde_json::to_vec(&self.header)?;
        let decoded_payload_bytes = serde_json::to_vec(&self.payload)?;

        let encoded_header = URL_SAFE_NO_PAD.encode(decoded_header_bytes);
        let encoded_payload = URL_SAFE_NO_PAD.encode(decoded_payload_bytes);

        let signing_input = [encoded_header, encoded_payload].join(".");

        Ok(signing_input)
    }

    pub fn sign_hmac(&mut self, alg: HmacKind, key: &[u8]) -> Result<()> {
        self.signature = alg.mac(self.signing_input()?.as_bytes(), key)?;
        Ok(())
    }

    pub fn verify_hmac(&self, alg: HmacKind, key: &[u8]) -> Result<bool> {
        Ok(hmac_matches(
            &self.signing_input()?,
            alg,
            key,
            &self.signature,
        ))
    }
}

pub fn hmac_matches(signing_input: &str, alg: HmacKind, key: &[u8], expected: &[u8]) -> bool {
    let mac = match alg.mac(signing_input.as_bytes(), key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    expected == mac
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    const VALID_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
    const INVALID_BASE64_TOKEN: &str = "@@@.@@@.@@@";
    const TOO_SHORT_TOKEN: &str = "one.two";
    const INVALID_JSON_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCI.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
    const PADDED_BASE64_TOKEN: &str = "ewogICJhbGciOiAiSFMyNTYiLAogICJ0eXAiOiAiSldUCn0=.CiAgInN1YiI6ICIxMjM0NTY3ODkwIiwKICAibmFtZSI6ICJKb2huIERvZSIsCiAgImFkbWluIjogdHJ1ZSwKICAiaWF0IjogMTUxNjIzOTAyMgp9.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";

    #[test]
    fn parses_valid_token() {
        let token = parse(VALID_TOKEN).unwrap();

        assert_eq!(token.header["typ"], "JWT");
        assert_eq!(token.payload["admin"], true);
        assert!(!token.signature.is_empty());
    }

    #[test]
    fn parses_invalid_base64_token() {
        let token = parse(INVALID_BASE64_TOKEN);
        assert!(token.is_err());
    }

    #[test]
    fn parses_short_token() {
        let token = parse(TOO_SHORT_TOKEN);
        assert!(token.is_err());
    }

    #[test]
    fn parses_invalid_json_token() {
        let token = parse(INVALID_JSON_TOKEN);
        assert!(token.is_err());
    }

    #[test]
    fn rejects_padded_base64() {
        let token = parse(PADDED_BASE64_TOKEN);
        assert!(token.is_err());
    }

    #[test]
    fn round_trips() {
        let token = parse(VALID_TOKEN).unwrap();
        let reencoded = token.encode().unwrap();
        let round_trip_token = parse(&reencoded).unwrap();

        assert_eq!(token.header["typ"], round_trip_token.header["typ"]);
        assert_eq!(token.payload["admin"], round_trip_token.payload["admin"]);
        assert_eq!(token.signature, round_trip_token.signature);
    }

    #[test]
    fn set_alg_sets_alg() {
        let mut token = parse(VALID_TOKEN).unwrap();
        token.set_alg("none").unwrap();
        assert_eq!(token.header["alg"], "none");
    }

    #[test]
    fn set_invalid_alg_errors() {
        let mut token = parse(VALID_TOKEN).unwrap();
        let result = token.set_alg("fakeAlg");
        assert!(result.is_err());
    }

    #[test]
    fn clears_signature() {
        let mut token = parse(VALID_TOKEN).unwrap();
        token.clear_signature();
        assert!(token.signature.is_empty());
    }

    #[test]
    fn set_claim_updates_field() {
        let mut token = parse(VALID_TOKEN).unwrap();
        token.set_claim("admin", json!(false));
        assert_eq!(token.payload["admin"], json!(false));
    }

    #[test]
    fn set_claim_creates_new_value() {
        let mut token = parse(VALID_TOKEN).unwrap();
        token.set_claim("testing", json!("teststring"));
        assert_eq!(token.payload["testing"], json!("teststring"));
    }

    #[test]
    fn signing_input_is_header_dot_payload() {
        let token = parse(VALID_TOKEN).unwrap();
        let valid_signing_input = VALID_TOKEN.rsplit_once('.').unwrap().0;

        let signing_input = token.signing_input().unwrap();

        assert_eq!(signing_input, valid_signing_input);
    }

    #[test]
    fn sign_hs256_valid_signature_length() {
        let mut token = parse(VALID_TOKEN).unwrap();
        token.sign_hmac(HmacKind::HS256, b"secret").unwrap();

        assert_eq!(token.signature.len(), 32);
    }

    #[test]
    fn sign_hs256_reproduces_twice() {
        let mut token = parse(VALID_TOKEN).unwrap();
        token.sign_hmac(HmacKind::HS256, b"secret").unwrap();

        let mut token2 = parse(VALID_TOKEN).unwrap();
        token2.sign_hmac(HmacKind::HS256, b"secret").unwrap();

        assert_eq!(token.signature, token2.signature);
    }

    #[test]
    fn sign_hs256_different_secret_different_signature() {
        let mut token = parse(VALID_TOKEN).unwrap();
        token.sign_hmac(HmacKind::HS256, b"secret").unwrap();

        let mut token2 = parse(VALID_TOKEN).unwrap();
        token2.sign_hmac(HmacKind::HS256, b"secret2").unwrap();

        assert_ne!(token.signature, token2.signature);
    }

    #[test]
    fn verify_hs256_verifies_correctly() {
        let mut token = parse(VALID_TOKEN).unwrap();
        token.sign_hmac(HmacKind::HS256, b"secret").unwrap();
        assert!(token.verify_hmac(HmacKind::HS256, b"secret").unwrap());
        assert!(!token.verify_hmac(HmacKind::HS256, b"notmysecret").unwrap());
    }

    #[test]
    fn from_alg_maps_to_matching_hash_size() {
        for (alg, len) in [("HS256", 32), ("HS384", 48), ("HS512", 64)] {
            let kind = HmacKind::from_alg(alg).unwrap();
            let mut token = parse(VALID_TOKEN).unwrap();
            token.sign_hmac(kind, b"secret").unwrap();

            assert_eq!(token.signature.len(), len, "{alg}");
        }
    }

    #[test]
    fn verify_hmac_round_trips_for_every_algorithm() {
        for alg in ["HS256", "HS384", "HS512"] {
            let kind = HmacKind::from_alg(alg).unwrap();
            let mut token = parse(VALID_TOKEN).unwrap();
            token.sign_hmac(kind, b"secret").unwrap();

            assert!(token.verify_hmac(kind, b"secret").unwrap(), "{alg}");
            assert!(!token.verify_hmac(kind, b"notmysecret").unwrap(), "{alg}");
        }
    }

    #[test]
    fn from_alg_rejects_unsupported() {
        assert!(HmacKind::from_alg("RS256").is_err());
        assert!(HmacKind::from_alg("ES256").is_err());
        assert!(HmacKind::from_alg("none").is_err());
        assert!(HmacKind::from_alg("").is_err());
    }
}
