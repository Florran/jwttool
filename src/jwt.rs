use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>; // a type alias: "HMAC using SHA-256"

const ALGORITHMS: &[&str] = &["none", "HS256"];

pub struct Token {
    pub header: serde_json::Value,
    pub payload: serde_json::Value,
    pub signature: Vec<u8>,
}

pub fn parse(encoded: &str) -> Result<Token, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = encoded.split('.').collect();
    if parts.len() != 3 {
        return Err("JWT has to be 3 parts!".into());
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
    pub fn encode(&self) -> Result<String, Box<dyn std::error::Error>> {
        let signing_input = self.signing_input()?;
        let encoded_signature = URL_SAFE_NO_PAD.encode(&self.signature);

        let encoded_token = [signing_input, encoded_signature].join(".");
        Ok(encoded_token)
    }

    pub fn set_alg(&mut self, alg: &str) -> Result<(), Box<dyn std::error::Error>> {
        if !ALGORITHMS.contains(&alg) {
            return Err("invalid alg".into());
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

    pub fn signing_input(&self) -> Result<String, Box<dyn std::error::Error>> {
        let decoded_header_bytes = serde_json::to_vec(&self.header)?;
        let decoded_payload_bytes = serde_json::to_vec(&self.payload)?;

        let encoded_header = URL_SAFE_NO_PAD.encode(decoded_header_bytes);
        let encoded_payload = URL_SAFE_NO_PAD.encode(decoded_payload_bytes);

        let signing_input = [encoded_header, encoded_payload].join(".");

        Ok(signing_input)
    }

    pub fn sign_hs256(&mut self, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
        let mut mac = HmacSha256::new_from_slice(key)?;
        mac.update(self.signing_input()?.as_bytes());
        let result = mac.finalize().into_bytes();
        self.signature = result.to_vec();
        Ok(())
    }

    pub fn verify_hs256(&self, key: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        let signing_input = self.signing_input()?;
        Ok(hmac_sha256_matches(&signing_input, key, &self.signature))
    }
}

pub fn hmac_sha256_matches(signing_input: &str, key: &[u8], expected: &[u8]) -> bool {
    let mut mac = match HmacSha256::new_from_slice(key) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(signing_input.as_bytes());
    mac.verify_slice(expected).is_ok()
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
        token.sign_hs256(b"secret").unwrap();

        assert_eq!(token.signature.len(), 32);
    }

    #[test]
    fn sign_hs256_reproduces_twice() {
        let mut token = parse(VALID_TOKEN).unwrap();
        token.sign_hs256(b"secret").unwrap();

        let mut token2 = parse(VALID_TOKEN).unwrap();
        token2.sign_hs256(b"secret").unwrap();

        assert_eq!(token.signature, token2.signature);
    }

    #[test]
    fn sign_hs256_different_secret_different_signature() {
        let mut token = parse(VALID_TOKEN).unwrap();
        token.sign_hs256(b"secret").unwrap();

        let mut token2 = parse(VALID_TOKEN).unwrap();
        token2.sign_hs256(b"secret2").unwrap();

        assert_ne!(token.signature, token2.signature);
    }

    #[test]
    fn verify_hs256_verifies_correctly() {
        let mut token = parse(VALID_TOKEN).unwrap();
        token.sign_hs256(b"secret").unwrap();
        assert!(token.verify_hs256(b"secret").unwrap());
        assert!(!token.verify_hs256(b"notmysecret").unwrap());
    }
}
