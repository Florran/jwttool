use crate::jwt::Token;

pub fn alg_none(token: &mut Token) -> Result<(), Box<dyn std::error::Error>> {
    token.set_alg("none")?;
    token.clear_signature();
    return Ok(());
}
