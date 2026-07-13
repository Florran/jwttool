use jwttool::{attack, dictionary, jwt};

use std::fs::File;
use std::io::{BufRead, BufReader};

use clap::{Args, Parser, Subcommand};

use jwttool::error::Error;

#[derive(Args)]
struct CommonArgs {
    /// The JWT to operate on
    #[arg(short = 't', long = "token")]
    token: String,

    /// Write the result as JSON to this file instead of stdout
    #[arg(short = 'o', long = "out-file")]
    out: Option<String>,
}

/// The action to run
#[derive(Subcommand)]
enum Command {
    /// Decode and print a token's header and payload
    Decode {
        #[command(flatten)]
        common: CommonArgs,

        /// Show only the header
        #[arg(long)]
        header: bool,

        /// Show only the payload
        #[arg(long)]
        payload: bool,
    },

    /// Tamper with a token using a chosen attack
    Attack {
        #[command(subcommand)]
        mode: AttackMode,
    },

    /// Crack an HS256 secret using a wordlist
    Dictionary {
        /// The JWT to operate on
        #[arg(short = 't', long = "token")]
        token: String,

        /// Path to the wordlist file
        #[arg(long = "wordlist", short = 'w')]
        wordlist: String,
    },

    /// Check whether a key produces the token's signature
    Verify {
        /// The JWT to operate on
        #[arg(short = 't', long = "token")]
        token: String,

        /// The secret key to verify against
        #[arg(long = "key")]
        key: String,
    },
}

#[derive(Subcommand)]
enum AttackMode {
    /// Set alg to none and remove the signature
    #[command(name = "none")]
    AlgNone {
        #[command(flatten)]
        common: CommonArgs,

        /// Set a payload claim (key=value)
        #[arg(long = "set", value_parser = parse_key_val)]
        pairs: Vec<(String, serde_json::Value)>,
    },

    /// Re-sign an RS256 token as HS256 using a chosen key
    #[command(name = "alg-confusion")]
    AlgConfusion {
        #[command(flatten)]
        common: CommonArgs,

        /// Set a payload claim (key=value)
        #[arg(long = "set", value_parser = parse_key_val)]
        pairs: Vec<(String, serde_json::Value)>,

        /// Key to sign with
        #[arg(long = "key")]
        key: String,
    },

    /// Inject a kid header and sign with a chosen key
    #[command(name = "kid-injection")]
    KidInjection {
        #[command(flatten)]
        common: CommonArgs,

        /// Set a payload claim (key=value)
        #[arg(long = "set", value_parser = parse_key_val)]
        pairs: Vec<(String, serde_json::Value)>,

        /// Value to set the kid header to
        #[arg(long)]
        kid: String,

        /// Key to sign with
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
fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Error> {
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
                    println!("header:\n{}", serde_json::to_string_pretty(&token.header)?);
                }
                if show_payload {
                    println!("payload:\n{}", serde_json::to_string_pretty(&token.payload)?);
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
        Command::Dictionary { token, wordlist } => {
            let token = jwt::parse(&token)?;
            let lines: Vec<String> = BufReader::new(File::open(&wordlist)?)
                .lines()
                .collect::<Result<_, _>>()?;

            match dictionary::crack(&token, &lines)? {
                Some(secret) => println!("secret found: {secret}"),
                None => println!("no secret found"),
            }
        }
        Command::Verify { token, key } => {
            let token = jwt::parse(&token)?;
            if token.header["alg"] != "HS256" {
                return Err(Error::UnsupportedAlg(
                    "verify only supports HS256 tokens".into(),
                ));
            }
            let result = token.verify_hs256(key.as_bytes())?;
            if result {
                println!("key matches signature");
            } else {
                println!("key does not match signature");
            }
        }
    }

    Ok(())
}

fn write_json(path: &str, value: &serde_json::Value) -> Result<(), Error> {
    let pretty_string: String = serde_json::to_string_pretty(value)?;
    std::fs::write(path, pretty_string)?;
    Ok(())
}

fn run_attack(
    common: &CommonArgs,
    pairs: Vec<(String, serde_json::Value)>,
    attack: impl FnOnce(&mut jwt::Token) -> Result<(), Error>,
) -> Result<(), Error> {
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
