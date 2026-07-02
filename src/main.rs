use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser;

/// JWT tampering tool for security testing
#[derive(Parser)]
struct Cli {
    /// The JWT to operate on
    #[arg(short = 't', long = "token")]
    token: String,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let parts: Vec<&str> = cli.token.split(".").collect();
    if parts.len() != 3 {
        return Err("JWT has to be 3 parts!".into());
    }

    //let header_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;

    let decoded_header_bytes = URL_SAFE_NO_PAD.decode(parts[0])?;
    let decoded_header = String::from_utf8(decoded_header_bytes)?;

    let decoded_payload_bytes = URL_SAFE_NO_PAD.decode(parts[1])?;
    let decoded_payload = String::from_utf8(decoded_payload_bytes)?;

    let header_json: serde_json::Value = serde_json::from_str(&decoded_header)?;
    let payload_json: serde_json::Value = serde_json::from_str(&decoded_payload)?;

    println!("{}", serde_json::to_string_pretty(&header_json)?);
    println!("{}", serde_json::to_string_pretty(&payload_json)?);

    Ok(())
}
