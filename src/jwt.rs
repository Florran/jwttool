use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

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

    return Ok(token);
}

impl Token {
    pub fn encode(&self) -> Result<String, Box<dyn std::error::Error>> {
        let decoded_header_bytes = serde_json::to_vec(&self.header)?;
        let decoded_payload_bytes = serde_json::to_vec(&self.payload)?;

        let encoded_header = URL_SAFE_NO_PAD.encode(decoded_header_bytes);
        let encoded_payload = URL_SAFE_NO_PAD.encode(decoded_payload_bytes);
        let encoded_signature = URL_SAFE_NO_PAD.encode(&self.signature);

        let encoded_token = [encoded_header, encoded_payload, encoded_signature].join(".");
        return Ok(encoded_token);
    }

    pub fn set_alg(&mut self, alg: &str) -> Result<(), Box<dyn std::error::Error>> {
        if !ALGORITHMS.contains(&alg) {
            return Err("invalid alg".into());
        }
        self.header["alg"] = serde_json::Value::from(alg);
        Ok(())
    }

    pub fn clear_signature(&mut self) {
        self.signature.clear();
    }
}

#[cfg(test)]
mod tests {
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
        assert_eq!(token.payload["admin"], round_trip_token.payload["admin"])
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
}
