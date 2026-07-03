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
