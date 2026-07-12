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
        #[command(flatten)]
        common: CommonArgs,

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

        #[arg(long = "set", value_parser = parse_key_val)]
        pairs: Vec<(String, serde_json::Value)>,
    },

    #[command(name = "alg-confusion")]
    AlgConfusion {
        #[command(flatten)]
        common: CommonArgs,

        /// Claim to set/modify (key=value)
        #[arg(long = "set", value_parser = parse_key_val)]
        pairs: Vec<(String, serde_json::Value)>,

        /// Public key to sign with
        #[arg(long = "key")]
        key: String,
    },

    #[command(name = "kid-injection")]
    KidInjection {
        #[command(flatten)]
        common: CommonArgs,

        /// Claim to set/modify (key=value)
        #[arg(long = "set", value_parser = parse_key_val)]
        pairs: Vec<(String, serde_json::Value)>,

        /// Value to set kid to
        #[arg(long)]
        kid: String,

        /// Public key to sign with
        #[arg(long = "key")]
        key: String,
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
            common,
            header,
            payload,
        } => {
            let token = jwt::parse(&common.token)?;

            let show_both = !header && !payload;
            let show_header = header || show_both;
            let show_payload = payload || show_both;

            if let Some(path) = &common.out {
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
            AttackMode::AlgNone { common, pairs } => run_attack(&common, pairs, attack::alg_none)?,

            AttackMode::AlgConfusion { common, pairs, key } => {
                run_attack(&common, pairs, |token| {
                    attack::alg_confusion(token, key.as_bytes())
                })?
            }

            AttackMode::KidInjection {
                common,
                pairs,
                kid,
                key,
            } => run_attack(&common, pairs, |token| {
                attack::kid_injection(
                    token,
                    serde_json::Value::String(kid.to_string()),
                    key.as_bytes(),
                )
            })?,
        },
    }

    Ok(())
}

fn write_json(path: &str, value: &serde_json::Value) -> Result<(), Box<dyn std::error::Error>> {
    let pretty_string: String = serde_json::to_string_pretty(value)?;
    std::fs::write(path, pretty_string)?;
    Ok(())
}

fn run_attack(
    common: &CommonArgs,
    pairs: Vec<(String, serde_json::Value)>,
    attack: impl FnOnce(&mut jwt::Token) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut token = jwt::parse(&common.token)?;
    for (k, v) in pairs {
        token.set_claim(&k, v);
    }

    attack(&mut token)?;
    let encoded_token = token.encode()?;

    if let Some(path) = &common.out {
        let value = serde_json::json!({"jwt": encoded_token});
        write_json(path, &value)?;
    } else {
        println!("{}", encoded_token)
    }
    Ok(())
}

fn parse_key_val(s: &str) -> Result<(String, serde_json::Value), String> {
    match s.split_once('=') {
        Some((key, value)) if !key.is_empty() => {
            let parsed = serde_json::from_str(value)
                .unwrap_or_else(|_| serde_json::Value::String(value.to_string()));
            Ok((key.to_string(), parsed))
        }
        _ => Err(format!("expected key=value, got {s}")),
    }
}
