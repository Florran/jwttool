pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    InvalidToken(String),
    UnsupportedAlg(String),
    InvalidAlgorithm(String),
    UnableToRecoverModulus(String),
    Base64(base64::DecodeError),
    Utf8(std::string::FromUtf8Error),
    Json(serde_json::Error),
    Io(std::io::Error),
    InvalidLength(hmac::digest::InvalidLength),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Error::InvalidToken(msg) => write!(f, "invalid token: {msg}"),
            Error::UnsupportedAlg(msg) => write!(f, "{msg}"),
            Error::InvalidAlgorithm(msg) => write!(f, "{msg}"),
            Error::UnableToRecoverModulus(msg) => write!(f, "{msg}"),
            Error::Base64(e) => write!(f, "base64 decode failed: {e}"),
            Error::Utf8(e) => write!(f, "invalid UTF-8: {e}"),
            Error::Json(e) => write!(f, "JSON error: {e}"),
            Error::Io(e) => write!(f, "IO error: {e}"),
            Error::InvalidLength(e) => write!(f, "invalid key length: {e}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<base64::DecodeError> for Error {
    fn from(e: base64::DecodeError) -> Self {
        Error::Base64(e)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(e: std::string::FromUtf8Error) -> Self {
        Error::Utf8(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<hmac::digest::InvalidLength> for Error {
    fn from(e: hmac::digest::InvalidLength) -> Self {
        Error::InvalidLength(e)
    }
}
