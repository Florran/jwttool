use crate::jwt::Token;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

pub fn crack(
    token: &Token,
    candidates: &[String],
) -> Result<Option<String>, Box<dyn std::error::Error>> {
    if token.header["alg"] != "HS256" {
        return Err("dictionary only supports HS256 tokens".into());
    }

    let n = std::thread::available_parallelism()?.get(); // get core count, for thread count
    let chunk_size = (candidates.len().div_ceil(n)).max(1);

    let signing_input = token.signing_input()?;
    let signing_input = &signing_input; // This is done so a reference gets moved, not the string

    let expected = &token.signature;

    let found = AtomicBool::new(false);
    let found = &found;

    let result = Mutex::new(None);
    let result = &result;

    type HmacSha256 = Hmac<Sha256>; // a type alias: "HMAC using SHA-256"

    std::thread::scope(|s| {
        for chunk in candidates.chunks(chunk_size) {
            s.spawn(move || {
                for candidate in chunk {
                    if found.load(Ordering::Relaxed) {
                        break;
                    }
                    let mut mac = HmacSha256::new_from_slice(candidate.as_bytes()).unwrap();
                    mac.update(signing_input.as_bytes());
                    if mac.verify_slice(expected).is_ok() {
                        found.store(true, Ordering::Relaxed);
                        *result.lock().unwrap() = Some(candidate.clone());
                    }
                }
            });
        }
    });
    Ok(result.lock().unwrap().take())
}
