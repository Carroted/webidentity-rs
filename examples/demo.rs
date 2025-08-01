use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::time::Duration;

use webidentity::{
    create_signed_headers, get_identity, resolve_location_url, verify_request, Identity,
    SimpleHeaderProvider,
};

fn main() {
    println!("Generating user keypair and identity page");

    let mut csprng = OsRng;
    let user_keypair = SigningKey::generate(&mut csprng);
    let binding = user_keypair.verifying_key();
    let user_public_key_bytes = binding.as_bytes();
    let user_public_key_hex = hex::encode(user_public_key_bytes);

    let user_location_string = "amy.carroted.org";

    // In WebIdentity, an identity is stored in meta tags of an HTML page. It also gets fallbacks from OpenGraph, favicon, etc
    let user_identity_page_content = format!(
        r#"
<!DOCTYPE html>
<html lang="en">
<head>
    <title>Amy Website</title>
    <meta name="identity:public-key" content="ed25519-pub:{}">
    <meta name="identity:display-name" content="Amy">
    <meta name="identity:description" content="Hello, I'm Amy!">

    <link rel="icon" href="/icon.svg" />
</head>
<body>
    <h1>Welcome</h1>
    <p>This is my website</p>
</body>
</html>
    "#,
        user_public_key_hex
    );

    println!("Simulating a client making a signed request");
    let http_method = "POST";
    let service_host = "example.com";
    let request_path = "/v1/messages";
    let request_body = r#"{"message":"Hello, world!"}"#.as_bytes();

    let signed_headers = create_signed_headers(
        user_location_string,
        http_method,
        service_host,
        request_path,
        request_body,
        &user_keypair,
    )
    .expect("Failed to create signed headers");

    println!("Simulating a server verifying the request\n");
    let received_headers: SimpleHeaderProvider = signed_headers.into_iter().collect();

    let location = received_headers.get("WebIdentity-Location").unwrap();
    let identity_url = resolve_location_url(location).unwrap();
    let identity: Identity = get_identity(&identity_url, &user_identity_page_content).unwrap();

    println!("  Parsed identity:");
    println!("    ID:           {}", identity.id);
    println!("    Display Name: {}", identity.display_name);
    println!(
        "    Avatar:       {}",
        match identity.avatar {
            Some(url) => url.to_string(),
            None => "None".to_string(),
        }
    );
    println!(
        "    Description:  {}",
        match identity.description {
            Some(description) => description,
            None => "None".to_string(),
        }
    );
    println!("    Location:     {}", identity.location);
    println!("    Location URL: {}", identity.location_url);
    println!(
        "    Public Key:   ed25519-pub:{}... ({} bytes)",
        &hex::encode(&identity.public_key[..4]),
        identity.public_key.len()
    );

    println!("\nVerifying request signature");
    let verification_result = verify_request(
        http_method,
        service_host,
        request_path,
        request_body,
        &received_headers,
        &identity.public_key,
        Duration::from_secs(60),
    );

    match verification_result {
        Ok(()) => println!("\nRequest signature is valid"),
        Err(e) => println!("\nRequest signature is invalid! Reason: {}", e),
    }
}
