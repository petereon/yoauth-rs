use yoauth::{get_oauth_token, OAuthConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Replace these with your actual Google OAuth credentials
    let client_id = std::env::var("GOOGLE_CLIENT_ID")
        .expect("GOOGLE_CLIENT_ID environment variable not set");
    let client_secret = std::env::var("GOOGLE_CLIENT_SECRET")
        .expect("GOOGLE_CLIENT_SECRET environment variable not set");

    let config = OAuthConfig::new(
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
        client_id,
    )
    .with_client_secret(client_secret)
    .with_scopes(vec![
        "https://www.googleapis.com/auth/userinfo.email".to_string(),
        "https://www.googleapis.com/auth/userinfo.profile".to_string(),
    ]);

    println!("Starting OAuth2 flow...");
    let token = get_oauth_token(config)?;

    println!("\nSuccess!");
    println!("Access token: {}", token.access_token);

    if let Some(refresh_token) = token.refresh_token {
        println!("Refresh token: {}", refresh_token);
    }

    if let Some(expires_in) = token.expires_in {
        println!("Expires in: {} seconds", expires_in);
    }

    if let Some(token_type) = token.token_type {
        println!("Token type: {}", token_type);
    }

    Ok(())
}
