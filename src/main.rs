mod jwt;

use clap::{Parser, Subcommand};

/// Subcommand to use
#[derive(Subcommand)]
enum Command {
    /// Decode a JWT
    Decode {
        /// The JWT to operate on
        #[arg(short = 't', long = "token")]
        token: String,

        /// File path for output file
        #[arg(short = 'o', long = "out-file")]
        out: Option<String>,

        /// Decode the JWTs header
        #[arg(long)]
        header: bool,

        /// Decode the JWTs payload
        #[arg(long)]
        payload: bool,
    },
}

/// JWT tampering tool for security testing
#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Decode {
            token,
            header,
            payload,
            out,
        } => {
            let token = jwt::parse(&token)?;

            let show_both = !header && !payload;
            let show_header = header || show_both;
            let show_payload = payload || show_both;

            if let Some(path) = &out {
                let mut obj = serde_json::Map::new();
                if show_header {
                    obj.insert("header".to_string(), token.header);
                }
                if show_payload {
                    obj.insert("payload".to_string(), token.payload);
                }
                let value = serde_json::Value::Object(obj);
                write_json(path, &value)?;
            } else {
                if show_header {
                    println!("Header:\n{}", serde_json::to_string_pretty(&token.header)?);
                }
                if show_payload {
                    println!(
                        "Payload:\n{}",
                        serde_json::to_string_pretty(&token.payload)?
                    );
                }
            }
        }
    }

    Ok(())
}

fn write_json(path: &str, value: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let pretty_string: String = serde_json::to_string_pretty(value)?;
    std::fs::write(path, pretty_string)?;
    Ok(())
}
