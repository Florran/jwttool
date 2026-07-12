use crate::jwt::Token;

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

    std::thread::scope(|s| {
        for chunk in candidates.chunks(chunk_size) {
            s.spawn(move || {
                for candidate in chunk {
                    if found.load(Ordering::Relaxed) {
                        break;
                    }
                    if crate::jwt::hmac_sha256_matches(
                        signing_input,
                        candidate.as_bytes(),
                        expected,
                    ) {
                        found.store(true, Ordering::Relaxed);
                        *result.lock().unwrap() = Some(candidate.clone());
                        break;
                    }
                }
            });
        }
    });
    Ok(result.lock().unwrap().take())
}
