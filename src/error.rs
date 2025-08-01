use thiserror::Error;

#[derive(Error, Debug)]
pub enum WebIdentityError {
    #[error("URL parsing failed: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("UProtocol '{0}' is not supported. Please use https:// or http://.")]
    UnsupportedProtocol(String),

    #[error("The required 'identity:public-key' meta tag was not found.")]
    MissingPublicKey,

    #[error("Public key format is invalid: {0}")]
    InvalidPublicKeyFormat(String),

    #[error("Could not find a display name from any fallback source.")]
    MissingDisplayName,

    #[error("Signature verification failed: {0}")]
    Signature(#[from] SignatureError),

    #[error("Cryptography error: {0}")]
    Crypto(String),
}

#[derive(Error, Debug)]
pub enum SignatureError {
    #[error("Missing required header: {0}")]
    MissingHeader(String),

    #[error("The timestamp '{0}' is invalid.")]
    InvalidTimestamp(String),

    #[error("The request timestamp is too old.")]
    TimestampExpired,

    #[error("The provided signature does not match the request.")]
    SignatureMismatch,
}
