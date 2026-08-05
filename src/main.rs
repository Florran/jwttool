use jwttool::recover;
use jwttool::{attack, dictionary, jwt};

use std::fs::File;
use std::io::{BufRead, BufReader};

use clap::{Args, Parser, Subcommand};

use jwttool::error::Error;

#[derive(Args)]
struct TokenArgs {
    /// The JWT to operate on
    #[arg(short = 't', long = "token")]
    token: String,
}

#[derive(Args)]
struct OutputArgs {
    /// Path to output file
    #[arg(short = 'o', long = "output", value_name = "FILE")]
    out: Option<String>,

    /// Output in json format
    #[arg(long = "json")]
    json: bool,
}

/// The action to run
#[derive(Subcommand)]
enum Command {
    /// Decode and print a token's header and payload
    Decode {
        #[command(flatten)]
        input: TokenArgs,

        #[command(flatten)]
        output: OutputArgs,

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
        #[command(flatten)]
        input: TokenArgs,

        #[command(flatten)]
        output: OutputArgs,

        /// Path to the wordlist file
        #[arg(long = "wordlist", short = 'w')]
        wordlist: String,
    },

    /// Check whether a key produces the token's signature
    Verify {
        #[command(flatten)]
        input: TokenArgs,

        #[command(flatten)]
        output: OutputArgs,

        /// The secret key to verify against
        #[arg(long = "key")]
        key: String,
    },

    /// Derive RSA public key from two different tokens signed with the same private key
    RecoverKey {
        /// First JWT to use for the public key recovery
        #[arg(short = 'a')]
        token_a: String,

        /// Second JWT to use for the public key recovery
        #[arg(short = 'b')]
        token_b: String,

        #[command(flatten)]
        output: OutputArgs,

        /// Output the raw modulus N in hex instead of a PEM key
        #[arg(long)]
        raw: bool,

        /// Output every byte-distinct PEM serialization to try against a target
        #[arg(long)]
        variants: bool,
    },
}

#[derive(Subcommand)]
enum AttackMode {
    /// Set alg to none and remove the signature
    #[command(name = "none")]
    AlgNone {
        #[command(flatten)]
        input: TokenArgs,

        #[command(flatten)]
        output: OutputArgs,

        /// Set a payload claim (key=value)
        #[arg(long = "set", value_parser = parse_key_val)]
        pairs: Vec<(String, serde_json::Value)>,
    },

    /// Re-sign an RS256 token as HS256 using a chosen key
    #[command(name = "alg-confusion")]
    AlgConfusion {
        #[command(flatten)]
        input: TokenArgs,

        #[command(flatten)]
        output: OutputArgs,

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
        input: TokenArgs,

        #[command(flatten)]
        output: OutputArgs,

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
            input,
            header,
            payload,
            output,
        } => {
            let token = jwt::parse(&input.token)?;

            let show_both = !header && !payload;
            let show_header = header || show_both;
            let show_payload = payload || show_both;

            let mut parts: Vec<String> = Vec::new();
            let mut obj = serde_json::Map::new();

            if show_header {
                parts.push(format!(
                    "header:\n{}",
                    serde_json::to_string_pretty(&token.header)?
                ));
                obj.insert("header".to_string(), token.header);
            }
            if show_payload {
                parts.push(format!(
                    "payload:\n{}",
                    serde_json::to_string_pretty(&token.payload)?
                ));
                obj.insert("payload".to_string(), token.payload);
            }
            emit(&parts.join("\n"), serde_json::Value::Object(obj), &output)?;
        }
        Command::Attack { mode } => match mode {
            AttackMode::AlgNone {
                input,
                pairs,
                output,
            } => run_attack(&input, &output, pairs, attack::alg_none)?,

            AttackMode::AlgConfusion {
                input,
                pairs,
                key,
                output,
            } => run_attack(&input, &output, pairs, |token| {
                attack::alg_confusion(token, key.as_bytes())
            })?,

            AttackMode::KidInjection {
                input,
                pairs,
                kid,
                key,
                output,
            } => run_attack(&input, &output, pairs, |token| {
                attack::kid_injection(
                    token,
                    serde_json::Value::String(kid.to_string()),
                    key.as_bytes(),
                )
            })?,
        },
        Command::Dictionary {
            input,
            wordlist,
            output,
        } => {
            let token = jwt::parse(&input.token)?;
            let lines: Vec<String> = BufReader::new(File::open(&wordlist)?)
                .lines()
                .collect::<Result<_, _>>()?;

            let secret = dictionary::crack(&token, &lines)?;

            let text = match &secret {
                Some(s) => format!("secret found: {s}"),
                None => "no secret found".to_string(),
            };
            emit(
                &text,
                serde_json::json!({"success": secret.is_some(), "secret": secret }),
                &output,
            )?;
        }
        Command::Verify { input, key, output } => {
            let token = jwt::parse(&input.token)?;
            if token.header["alg"] != "HS256" {
                return Err(Error::UnsupportedAlg(
                    "verify only supports HS256 tokens".into(),
                ));
            }
            let result = token.verify_hs256(key.as_bytes())?;
            emit(
                if result {
                    "key matches signature"
                } else {
                    "key does not match signature"
                },
                serde_json::json!({"success":result}),
                &output,
            )?;
        }
        Command::RecoverKey {
            token_a,
            token_b,
            raw,
            variants,
            output,
        } => {
            let a = jwt::parse(&token_a)?;
            let b = jwt::parse(&token_b)?;
            let (n, e) = recover::recover_modulus(&a, &b, 65537)
                .map(|n| (n, 65537))
                .or_else(|_| recover::recover_modulus(&a, &b, 3).map(|n| (n, 3)))?;

            if raw {
                let hex = format!("{n:x}");
                emit(&hex, serde_json::json!({ "modulus_hex": &hex }), &output)?;
            } else if variants {
                let list = recover::public_key_variants(&n, e);
                let text = list
                    .iter()
                    .enumerate()
                    .map(|(i, pem)| format!("# variant {}\n{}", i + 1, pem.trim_end()))
                    .collect::<Vec<String>>()
                    .join("\n\n");
                emit(&text, serde_json::json!({ "variants": &list }), &output)?;
            } else {
                let pem = recover::public_key_pem(&n, e);
                emit(pem.trim_end(), serde_json::json!({ "pem": &pem }), &output)?;
            }
        }
    }

    Ok(())
}

fn emit(text: &str, json: serde_json::Value, opts: &OutputArgs) -> Result<(), Error> {
    let as_json = opts.out.is_some() || opts.json;

    let body = if as_json {
        serde_json::to_string_pretty(&json)?
    } else {
        text.to_string()
    };

    match &opts.out {
        Some(path) => {
            std::fs::write(path, format!("{body}\n"))?;
        }
        None => {
            println!("{}", body);
        }
    }

    Ok(())
}

fn run_attack(
    input: &TokenArgs,
    output: &OutputArgs,
    pairs: Vec<(String, serde_json::Value)>,
    attack: impl FnOnce(&mut jwt::Token) -> Result<(), Error>,
) -> Result<(), Error> {
    let mut token = jwt::parse(&input.token)?;
    for (k, v) in pairs {
        token.set_claim(&k, v);
    }

    attack(&mut token)?;
    let encoded_token = token.encode()?;

    emit(
        &encoded_token,
        serde_json::json!({"jwt": encoded_token}),
        output,
    )?;
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
