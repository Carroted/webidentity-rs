//! A library for resolving, parsing, and verifying WebIdentity documents.
//!
//! WebIdentity allows users to use a web page they control as their decentralized identity,
//! using a public key in it to allow verifying their signatures. This library provides
//! the tools to work with this standard.

mod error;
mod identity;
mod resolve;
mod sign;

pub use error::WebIdentityError;
pub use identity::{get_identity, Identity};
pub use resolve::resolve_location_url;
pub use sign::{create_signed_headers, verify_request, HeaderProvider, SimpleHeaderProvider};
