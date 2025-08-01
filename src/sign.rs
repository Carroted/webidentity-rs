use super::error::{SignatureError, WebIdentityError};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub trait HeaderProvider {
    fn get_header(&self, name: &str) -> Option<&str>;
}

/// A simple HashMap implementation of `HeaderProvider`
pub type SimpleHeaderProvider = HashMap<String, String>;
impl HeaderProvider for SimpleHeaderProvider {
    fn get_header(&self, name: &str) -> Option<&str> {
        self.get(name).map(|s| s.as_str())
    }
}

/// Verifies a signed request against a public key.
///
/// # Errors
/// Returns `Err` if any header is missing, the timestamp is invalid/expired,
/// or the signature is incorrect.
pub fn verify_request(
    http_method: &str,
    host: &str,
    path: &str,
    body: &[u8],
    headers: &impl HeaderProvider,
    public_key_bytes: &[u8],
    max_age: Duration,
) -> Result<(), WebIdentityError> {
    // Get headers
    let location = headers
        .get_header("WebIdentity-Location")
        .ok_or_else(|| SignatureError::MissingHeader("WebIdentity-Location".to_string()))?;
    let timestamp_str = headers
        .get_header("WebIdentity-Timestamp")
        .ok_or_else(|| SignatureError::MissingHeader("WebIdentity-Timestamp".to_string()))?;
    let signature_hex = headers
        .get_header("WebIdentity-Signature")
        .ok_or_else(|| SignatureError::MissingHeader("WebIdentity-Signature".to_string()))?;

    let timestamp = timestamp_str
        .parse::<u64>()
        .map_err(|_| SignatureError::InvalidTimestamp(timestamp_str.to_string()))?;

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    if now.saturating_sub(timestamp) > max_age.as_secs() {
        return Err(SignatureError::TimestampExpired.into());
    }

    let body_hash = hash_body(body);
    let canonical_string =
        build_canonical_string(http_method, host, path, &body_hash, location, timestamp_str);

    let signature_bytes =
        hex::decode(signature_hex).map_err(|_| SignatureError::SignatureMismatch)?;

    verify_signature(
        public_key_bytes,
        canonical_string.as_bytes(),
        &signature_bytes,
    )
}

// This is taken from rust std, since it is still unstable library feature, but is useful here
pub(crate) fn as_array<T, const N: usize>(vec: &[T]) -> Option<&[T; N]> {
    if vec.len() == N {
        let ptr = vec.as_ptr() as *const [T; N];

        // SAFETY: The underlying array of a slice can be reinterpreted as an actual array `[T; N]` if `N` is not greater than the slice's length.
        let me = unsafe { &*ptr };
        Some(me)
    } else {
        None
    }
}

/// Creates the three `WebIdentity-*` headers for making a signed request.
pub fn create_signed_headers(
    location: &str,
    http_method: &str,
    host: &str,
    path: &str,
    body: &[u8],
    signing_key: &SigningKey,
) -> Result<HashMap<String, String>, WebIdentityError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let body_hash = hash_body(body);

    let canonical_string =
        build_canonical_string(http_method, host, path, &body_hash, location, &timestamp);

    let signature = signing_key.sign(canonical_string.as_bytes());
    let signature_hex = hex::encode(signature.to_bytes());

    let mut headers = HashMap::new();
    headers.insert("WebIdentity-Location".to_string(), location.to_string());
    headers.insert("WebIdentity-Timestamp".to_string(), timestamp);
    headers.insert("WebIdentity-Signature".to_string(), signature_hex);

    Ok(headers)
}

/// Helper function to sign with `ed25519-dalek`
pub fn sign_bytes(signing_key: &[u8], bytes: &[u8]) -> Result<[u8; 64], WebIdentityError> {
    let signing_key = SigningKey::from_bytes(
        as_array::<u8, 32>(signing_key).ok_or(SignatureError::SignatureMismatch)?,
    );
    let signature = signing_key.sign(bytes);
    Ok(signature.to_bytes())
}

/// Helper function to verify a signature with `ed25519-dalek`
pub fn verify_signature(
    public_key: &[u8],
    original_bytes: &[u8],
    signature: &[u8],
) -> Result<(), WebIdentityError> {
    let public_key = VerifyingKey::from_bytes(
        as_array::<u8, 32>(public_key).ok_or(SignatureError::SignatureMismatch)?,
    )
    .map_err(|_| SignatureError::SignatureMismatch)?;

    let signature_bytes = as_array::<u8, 64>(signature).ok_or(SignatureError::SignatureMismatch)?;
    let signature = Signature::from_bytes(&signature_bytes);

    if public_key.verify(original_bytes, &signature).is_ok() {
        Ok(())
    } else {
        Err(SignatureError::SignatureMismatch.into())
    }
}

fn hash_body(body: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(body);
    hex::encode(hasher.finalize())
}

fn build_canonical_string(
    method: &str,
    host: &str,
    path: &str,
    body_hash: &str,
    location: &str,
    timestamp: &str,
) -> String {
    let clean_path = if path != "/" {
        path.trim_end_matches('/')
    } else {
        path
    };

    format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_uppercase(),
        host,
        clean_path,
        body_hash,
        location,
        timestamp
    )
}
