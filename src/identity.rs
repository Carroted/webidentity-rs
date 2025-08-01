use crate::sign::as_array;

use super::error::WebIdentityError;
use ed25519_dalek::VerifyingKey;
use lol_html::{element, HtmlRewriter, Settings};
use sha2::{Digest, Sha256};
use std::cell::RefCell;
use std::rc::Rc;
use url::Url;

const PK_PREFIX: &str = "ed25519-pub:";

#[derive(Debug, Clone)]
pub struct Identity {
    pub id: String,
    pub public_key: Vec<u8>,
    pub display_name: String,
    pub avatar: Option<Url>,
    pub description: Option<String>,
    pub location_url: Url,
    pub location: String,
}

#[derive(Default, Debug)]
struct RawIdentityData {
    public_key: Option<String>,
    display_name: Option<String>,
    author: Option<String>,
    og_author: Option<String>,
    og_title: Option<String>,
    avatar: Option<String>,
    og_image: Option<String>,
    favicon: Option<String>,
    description: Option<String>,
    og_description: Option<String>,
}

pub fn get_identity(source_url: &Url, content: &str) -> Result<Identity, WebIdentityError> {
    let raw_data = Rc::new(RefCell::new(RawIdentityData::default()));

    let element_content_handlers = vec![
        element!("meta", |el| {
            let name = el.get_attribute("name");
            let property = el.get_attribute("property");
            let content = el.get_attribute("content");

            if let Some(content) = content {
                // Prioritize property for OG tags, then fall back to name
                let key = property.or(name);
                if let Some(key) = key {
                    let mut data = raw_data.borrow_mut();
                    match key.as_str() {
                        "identity:public-key" => data.public_key = Some(content),
                        "identity:display-name" => data.display_name = Some(content),
                        "identity:avatar" => data.avatar = Some(content),
                        "identity:description" => data.description = Some(content),
                        "author" => data.author = Some(content),
                        "og:author" => data.og_author = Some(content),
                        "og:title" => data.og_title = Some(content),
                        "og:image" => data.og_image = Some(content),
                        "og:description" => data.og_description = Some(content),
                        "description" => data.description = Some(content),
                        _ => {}
                    }
                }
            }
            Ok(())
        }),
        element!("link", |el| {
            if let Some(rel) = el.get_attribute("rel") {
                if rel == "icon" || rel == "shortcut icon" {
                    if let Some(href) = el.get_attribute("href") {
                        raw_data.borrow_mut().favicon = Some(href);
                    }
                }
            }
            Ok(())
        }),
    ];

    let mut rewriter = HtmlRewriter::new(
        Settings {
            element_content_handlers,
            ..Settings::default()
        },
        |_: &[u8]| {},
    );
    rewriter.write(content.as_bytes()).unwrap();
    rewriter.end().unwrap();

    let data = Rc::try_unwrap(raw_data).unwrap().into_inner();

    // Public key (the only mandatory value)
    let pk_hex = data.public_key.ok_or(WebIdentityError::MissingPublicKey)?;
    if !pk_hex.starts_with(PK_PREFIX) {
        return Err(WebIdentityError::InvalidPublicKeyFormat(format!(
            "This server only supports keys that start with '{}'.",
            PK_PREFIX
        )));
    }
    let public_key_bytes: Vec<u8> = hex::decode(&pk_hex[PK_PREFIX.len()..])
        .map_err(|_| WebIdentityError::InvalidPublicKeyFormat("Invalid hex encoding.".into()))?;

    let bytes = as_array::<u8, 32>(&public_key_bytes).ok_or(
        WebIdentityError::InvalidPublicKeyFormat("Wrong key size".into()),
    )?;

    VerifyingKey::from_bytes(bytes).map_err(|_| {
        WebIdentityError::InvalidPublicKeyFormat("Not a valid Ed25519 public key.".into())
    })?;

    // ID is derived from the public key
    let mut hasher = Sha256::new();
    hasher.update(&public_key_bytes);
    let id_hash = hasher.finalize();
    let id = hex::encode(&id_hash);

    let location = {
        let mut host = source_url.host_str().unwrap_or("").to_string();
        host.push_str(source_url.path());
        host.trim_end_matches('/').to_string()
    };

    let display_name = data
        .display_name
        .or(data.author)
        .or(data.og_author)
        .or(data.og_title)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| location.clone());

    let avatar_str = data.avatar.or(data.og_image).or(data.favicon);
    let avatar = if let Some(href) = avatar_str {
        source_url.join(&href).ok()
    } else {
        None
    };

    let description = data.description.or(data.og_description);

    Ok(Identity {
        id,
        public_key: public_key_bytes,
        display_name,
        avatar,
        description,
        location_url: source_url.clone(),
        location,
    })
}
