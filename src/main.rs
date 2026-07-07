mod attack;
mod jwt;

use clap::{Args, Parser, Subcommand};

#[derive(Args)]
struct CommonArgs {
    /// The JWT to operate on
    #[arg(short = 't', long = "token")]
    token: String,

    /// File path for output file
    #[arg(short = 'o', long = "out-file")]
    out: Option<String>,
}

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

    /// Execute JWT attacks
    Attack {
        #[command(subcommand)]
        mode: AttackMode,
    },
}

#[derive(Subcommand)]
enum AttackMode {
    /// Set alg to none and strip the signature
    #[command(name = "none")]
    AlgNone {
        #[command(flatten)]
        common: CommonArgs,
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
        Command::Attack { mode } => match mode {
            AttackMode::AlgNone { common } => {
                let mut token = jwt::parse(&common.token)?;
                attack::alg_none(&mut token)?;
                let encoded_token = token.encode()?;

                if let Some(path) = &common.out {
                    let value = serde_json::json!({"jwt": encoded_token});
                    write_json(path, &value)?;
                } else {
                    println!("{}", encoded_token)
                }
            }
        },
    }

    Ok(())
}

fn write_json(path: &str, value: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let pretty_string: String = serde_json::to_string_pretty(value)?;
    std::fs::write(path, pretty_string)?;
    Ok(())
}
