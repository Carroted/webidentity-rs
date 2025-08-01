use super::error::WebIdentityError;
use url::Url;

/// Resolves a location string into a full HTTPS or HTTP URL.
///
/// It prepends "https://" if no protocol is specified.
///
/// # Errors
/// Returns `Err` if the protocol is not `http` or `https`, or if the URL is invalid.
pub fn resolve_location_url(location: &str) -> Result<Url, WebIdentityError> {
    if location.contains("://") {
        let scheme = location.split("://").next().unwrap_or("");
        if scheme == "http" || scheme == "https" {
            Url::parse(location).map_err(WebIdentityError::from)
        } else {
            Err(WebIdentityError::UnsupportedProtocol(scheme.to_string()))
        }
    } else {
        let full_url = format!("https://{}", location);
        Url::parse(&full_url).map_err(WebIdentityError::from)
    }
}
