use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

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

#[cfg(test)]
mod tests {
    use super::*;

    const ENCODED_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
    const INVALID_BASE64_TOKEN: &str = "@@@.@@@.@@@";
    const TOO_SHORT_TOKEN: &str = "one.two";
    const INVALID_JSON_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCI.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
    const PADDED_BASE64_TOKEN: &str = "ewogICJhbGciOiAiSFMyNTYiLAogICJ0eXAiOiAiSldUCn0=.CiAgInN1YiI6ICIxMjM0NTY3ODkwIiwKICAibmFtZSI6ICJKb2huIERvZSIsCiAgImFkbWluIjogdHJ1ZSwKICAiaWF0IjogMTUxNjIzOTAyMgp9.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";

    #[test]
    fn parses_valid_token() {
        let token = parse(ENCODED_TOKEN).unwrap();

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
}
