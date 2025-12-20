use clap::Parser;
use serde::Deserialize;
use std::path::PathBuf;
use yoauth::{get_oauth_token, OAuthConfig, SslCerts};

/// YOAuth - OAuth2 token acquisition made easy
///
/// Get OAuth2 tokens through the authorization code flow with automatic
/// certificate generation and TLS support.
///
/// Configuration priority (highest to lowest):
/// 1. Command line arguments
/// 2. Environment variables (YOAUTH_*)
/// 3. Config file (yoauth.toml or specified via --config)
/// 4. Default values
#[derive(Parser, Debug)]
#[command(name = "yoauth")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// OAuth2 authorization URL (e.g., https://accounts.google.com/o/oauth2/v2/auth)
    #[arg(short = 'a', long, env = "YOAUTH_AUTHORIZATION_URL")]
    authorization_url: Option<String>,

    /// OAuth2 token URL (e.g., https://oauth2.googleapis.com/token)
    #[arg(short = 't', long, env = "YOAUTH_TOKEN_URL")]
    token_url: Option<String>,

    /// OAuth2 client ID
    #[arg(short = 'i', long, env = "YOAUTH_CLIENT_ID")]
    client_id: Option<String>,

    /// OAuth2 client secret
    #[arg(short = 's', long, env = "YOAUTH_CLIENT_SECRET")]
    client_secret: Option<String>,

    /// OAuth2 scopes (comma-separated)
    ///
    /// Example: email,profile,openid
    #[arg(long, env = "YOAUTH_SCOPES", value_delimiter = ',')]
    scopes: Option<Vec<String>>,

    /// Disable TLS/HTTPS (NOT RECOMMENDED - tokens sent in plain text)
    #[arg(long, env = "YOAUTH_DISABLE_TLS")]
    disable_tls: bool,

    /// Path to TLS certificate file (PEM format)
    ///
    /// If not provided, a self-signed certificate will be auto-generated
    #[arg(long, env = "YOAUTH_CERT_FILE")]
    cert_file: Option<PathBuf>,

    /// Path to TLS private key file (PEM format)
    ///
    /// Required if --cert-file is provided
    #[arg(long, env = "YOAUTH_KEY_FILE")]
    key_file: Option<PathBuf>,

    /// Path to TOML configuration file
    ///
    /// Default: ./yoauth.toml (if exists)
    #[arg(short = 'c', long, env = "YOAUTH_CONFIG")]
    config: Option<PathBuf>,

    /// Output format
    #[arg(short = 'o', long, default_value = "json", env = "YOAUTH_OUTPUT_FORMAT")]
    output: OutputFormat,

    /// Show only the access token (shortcut for --output token)
    #[arg(long)]
    token_only: bool,

    /// Enable verbose output
    #[arg(short = 'v', long, env = "YOAUTH_VERBOSE")]
    verbose: bool,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum OutputFormat {
    /// Output full JSON response
    Json,
    /// Output only the access token
    Token,
    /// Output in a human-readable format
    Pretty,
}

#[derive(Debug, Deserialize, Default)]
struct ConfigFile {
    authorization_url: Option<String>,
    token_url: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
    scopes: Option<Vec<String>>,
    disable_tls: Option<bool>,
    cert_file: Option<PathBuf>,
    key_file: Option<PathBuf>,
}

impl ConfigFile {
    fn load(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: ConfigFile = toml::from_str(&content)?;
        Ok(config)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Load config file (priority 3)
    let config_file = if let Some(config_path) = &args.config {
        ConfigFile::load(config_path)?
    } else {
        // Try default location
        let default_config = PathBuf::from("yoauth.toml");
        if default_config.exists() {
            ConfigFile::load(&default_config).unwrap_or_default()
        } else {
            ConfigFile::default()
        }
    };

    // Merge configurations with priority: CLI > Env > Config File
    let authorization_url = args
        .authorization_url
        .or(config_file.authorization_url)
        .ok_or("Authorization URL is required (--authorization-url, YOAUTH_AUTHORIZATION_URL, or config file)")?;

    let token_url = args
        .token_url
        .or(config_file.token_url)
        .ok_or("Token URL is required (--token-url, YOAUTH_TOKEN_URL, or config file)")?;

    let client_id = args
        .client_id
        .or(config_file.client_id)
        .ok_or("Client ID is required (--client-id, YOAUTH_CLIENT_ID, or config file)")?;

    let client_secret = args
        .client_secret
        .or(config_file.client_secret)
        .ok_or("Client secret is required (--client-secret, YOAUTH_CLIENT_SECRET, or config file)")?;

    let scopes = args
        .scopes
        .or(config_file.scopes)
        .unwrap_or_default();

    let require_tls = !args.disable_tls && !config_file.disable_tls.unwrap_or(false);

    // Build OAuth config
    let mut oauth_config = OAuthConfig::new(
        authorization_url,
        token_url,
        client_id,
        client_secret,
    )
    .with_scopes(scopes)
    .with_tls(require_tls)
    .with_verbose(args.verbose);

    // Handle certificates
    if require_tls {
        let cert_file = args.cert_file.or(config_file.cert_file);
        let key_file = args.key_file.or(config_file.key_file);

        match (cert_file, key_file) {
            (Some(cert), Some(key)) => {
                if args.verbose {
                    eprintln!("Loading certificates from files...");
                }
                let ssl_certs = SslCerts::from_files(
                    cert.to_str().ok_or("Invalid certificate file path")?,
                    key.to_str().ok_or("Invalid key file path")?,
                )?;
                oauth_config = oauth_config.with_ssl_certs(ssl_certs);
            }
            (Some(_), None) => {
                return Err("--key-file is required when --cert-file is provided".into());
            }
            (None, Some(_)) => {
                return Err("--cert-file is required when --key-file is provided".into());
            }
            (None, None) => {
                if args.verbose {
                    eprintln!("Auto-generating self-signed certificate...");
                }
                // Will auto-generate when needed
            }
        }
    } else {
        eprintln!("⚠️  WARNING: TLS is disabled. Tokens will be transmitted in plain text!");
    }

    // Execute OAuth flow
    if args.verbose {
        eprintln!("\nStarting OAuth2 flow...");
    }
    let token_response = get_oauth_token(oauth_config)?;

    // Output based on format
    let output_format = if args.token_only {
        OutputFormat::Token
    } else {
        args.output
    };

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&token_response)?);
        }
        OutputFormat::Token => {
            println!("{}", token_response.access_token);
        }
        OutputFormat::Pretty => {
            println!("\n✅ OAuth2 token acquired successfully!\n");
            println!("Access Token: {}", token_response.access_token);

            if let Some(refresh_token) = &token_response.refresh_token {
                println!("Refresh Token: {}", refresh_token);
            }

            if let Some(expires_in) = token_response.expires_in {
                println!("Expires In: {} seconds ({} minutes)",
                    expires_in, expires_in / 60);
            }

            if let Some(token_type) = &token_response.token_type {
                println!("Token Type: {}", token_type);
            }

            if let Some(scope) = &token_response.scope {
                println!("Scope: {}", scope);
            }
        }
    }

    Ok(())
}
