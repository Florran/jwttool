use std::process::Command;

const VALID_TOKEN: &str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.KMUFsIDTnFmyG3nMiGM6H9FNFUROf3wh7SmqJp-QV30";
const HS384_TOKEN: &str = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiYWRtaW4iOnRydWV9.c_Z41--BMkLUOK_WNPD0sx0r0PelmqngK4rnwMaSiCNr7M9CANDXhgTCqWZkP-Ql";
const RS256_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.NHVaYe26MbtOYhSKkoKYdFVomg4i8ZJd8_-RU8VNbftc4TSMb4bXP3l3YlNWACwyXPGffz5aXHc6lty1Y2t4SWRqGteragsVdZufDn5BlnJl9pdR_kdVFUsra2rWKEofkZeIC4yWytE58sMIihvo9H1ScmmVwBcQP6XETqYd0aSHp1gOa9RdUPDvoXQ5oqygTqVtxaDr6wUFKrKItgBMzWIdNZ6y7O9E0DhEPTbE9rfBo6KTFsHAZnMg4k68CDp2woYIaXbmYTWcvbzIuHO7_37GT79XdIwkm95QJ7hYC9RiwrV7mesbY4PAahERJawntho0my942XheVLmGwLMBkQ";

#[test]
fn decode_prints_header_and_payload() {
    let output = Command::new(env!("CARGO_BIN_EXE_jwttool"))
        .args(["decode", "-t", VALID_TOKEN])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("HS256"));
}

#[test]
fn verify_rejects_non_hmac() {
    let output = Command::new(env!("CARGO_BIN_EXE_jwttool"))
        .args(["verify", "-t", RS256_TOKEN, "--key", "whatever"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).unwrap();
    assert!(stderr.to_lowercase().contains("unsupported"));
    assert!(stderr.contains("RS256"));
}

#[test]
fn verify_accepts_hs384() {
    let output = Command::new(env!("CARGO_BIN_EXE_jwttool"))
        .args(["verify", "-t", HS384_TOKEN, "--key", "secret"])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("key matches signature"));
}

#[test]
fn verify_rejects_wrong_key_for_hs384() {
    let output = Command::new(env!("CARGO_BIN_EXE_jwttool"))
        .args(["verify", "-t", HS384_TOKEN, "--key", "notmysecret"])
        .output()
        .unwrap();

    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("key does not match signature"));
}
