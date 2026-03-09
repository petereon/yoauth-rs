use yoauth::{OAuthConfig, SslCerts};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example 1: Generate certificates on the fly
    println!("Example 1: Auto-generating self-signed certificate...");
    let auto_generated_certs = SslCerts::generate()?;
    println!("Certificate generated successfully!");
    println!("Cert size: {} bytes", auto_generated_certs.cert_pem.len());
    println!("Key size: {} bytes\n", auto_generated_certs.key_pem.len());

    // Example 2: Load from files (if they exist)
    println!("Example 2: Loading from files...");
    match SslCerts::from_files("cert.pem", "key.pem") {
        Ok(certs) => {
            println!("Certificates loaded successfully!");
            println!("Cert size: {} bytes", certs.cert_pem.len());
            println!("Key size: {} bytes\n", certs.key_pem.len());
        }
        Err(e) => {
            println!("Could not load certificates from files: {}", e);
            println!("This is expected if cert.pem and key.pem don't exist.\n");
        }
    }

    // Example 3: Using in OAuth flow
    println!("Example 3: OAuth flow with auto-generated certificates...");

    // For demo purposes, we'll use placeholder values
    // In a real scenario, these would be your actual OAuth credentials
    let client_id = std::env::var("CLIENT_ID").unwrap_or_else(|_| {
        println!("CLIENT_ID not set, using placeholder");
        "your_client_id".to_string()
    });

    let client_secret = std::env::var("CLIENT_SECRET").unwrap_or_else(|_| {
        println!("CLIENT_SECRET not set, using placeholder");
        "your_client_secret".to_string()
    });

    let _config = OAuthConfig::new(
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
        client_id,
    )
    .with_client_secret(client_secret)
    .with_scopes(vec!["email".to_string()])
    // Certificates are auto-generated if not provided!
    // You could also explicitly provide them:
    // .with_ssl_certs(SslCerts::generate()?)
    ;

    println!("\nConfiguration ready!");
    println!("When you call get_oauth_token(config), it will:");
    println!("1. Auto-generate a self-signed certificate using rcgen");
    println!("2. Start an HTTPS server with rustls");
    println!("3. Open your browser for OAuth authorization");
    println!("4. Receive the callback and exchange for tokens");

    // Uncomment the following line to actually run the OAuth flow:
    // let token = get_oauth_token(config)?;
    // println!("Access token: {}", token.access_token);

    Ok(())
}
