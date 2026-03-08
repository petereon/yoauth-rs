# YOAuth 🔑

Getting a token has never been easier. Rust port of [YOAuth](https://github.com/petereon/yoauth) using `tiny_http`, `rustls`, and `rcgen` for self-signed certificate generation. Now also as a CLI command for all your scripting needs 📜

## Features ✨

- OAuth2 authorization code flow
- PKCE support (S256 / plain) with automatic discovery via `.well-known/openid-configuration`
- TLS support via `rustls`
- Automatic certificate generation using `rcgen`
- Lightweight HTTP server using `tiny_http`
- Automatic browser opening for authorization
- Optional external certificate loading
- Custom success page — bring your own HTML shown after authorization

## Installation 📦

### As a CLI Tool

Download the pre-built binary from the [releases](https://github.com/petereon/yoauth-rs/releases/latest)

Or build from source:

```bash
cargo install --git https://github.com/petereon/yoauth.git
```



### As a Library

Add this to your `Cargo.toml`:

```toml
[dependencies]
yoauth = { git = "https://github.com/petereon/yoauth.git" }
```

## Usage 📖

### CLI Usage

The easiest way to get an OAuth2 token is using the command-line interface:

```bash
yoauth \
  --authorization-url "https://accounts.google.com/o/oauth2/v2/auth" \
  --token-url "https://oauth2.googleapis.com/token" \
  --client-id "YOUR_CLIENT_ID" \
  --client-secret "YOUR_CLIENT_SECRET" \
  --scopes "email,profile"
```

Or using environment variables:

```bash
export YOAUTH_AUTHORIZATION_URL="https://accounts.google.com/o/oauth2/v2/auth"
export YOAUTH_TOKEN_URL="https://oauth2.googleapis.com/token"
export YOAUTH_CLIENT_ID="YOUR_CLIENT_ID"
export YOAUTH_CLIENT_SECRET="YOUR_CLIENT_SECRET"
export YOAUTH_SCOPES="email,profile"

yoauth
```

Or using a config file (recommended):

```bash
# Copy the example config
cp yoauth.toml.example yoauth.toml

# Edit yoauth.toml with your OAuth provider details
# Then run:
yoauth
```

**CLI Options:**

| Flag | Env var | Description |
|------|---------|-------------|
| `-a, --authorization-url <URL>` | `YOAUTH_AUTHORIZATION_URL` | OAuth2 authorization endpoint URL |
| `-t, --token-url <URL>` | `YOAUTH_TOKEN_URL` | OAuth2 token endpoint URL |
| `-i, --client-id <ID>` | `YOAUTH_CLIENT_ID` | OAuth2 client ID |
| `-s, --client-secret <SECRET>` | `YOAUTH_CLIENT_SECRET` | OAuth2 client secret |
| `--scopes <SCOPES>` | `YOAUTH_SCOPES` | Comma-separated list of OAuth2 scopes |
| `-o, --output <FORMAT>` | `YOAUTH_OUTPUT_FORMAT` | Output format: `json`, `token`, or `pretty` (default: `json`) |
| `--token-only` | — | Output only the access token (shortcut for `-o token`) |
| `--challenge-method <METHOD>` | `YOAUTH_CHALLENGE_METHOD` | PKCE method: `s256`, `plain`, or `none` (default: auto-detect) |
| `--success-html-file <PATH>` | `YOAUTH_SUCCESS_HTML_FILE` | Path to an HTML file shown after successful authorization |
| `-c, --config <PATH>` | `YOAUTH_CONFIG` | Path to config file (default: `./yoauth.toml`) |
| `--cert-file <PATH>` | `YOAUTH_CERT_FILE` | Path to TLS certificate file (PEM format) |
| `--key-file <PATH>` | `YOAUTH_KEY_FILE` | Path to TLS private key file (PEM format) |
| `--disable-tls` | `YOAUTH_DISABLE_TLS` | Disable TLS/HTTPS (NOT RECOMMENDED) |
| `-v, --verbose` | `YOAUTH_VERBOSE` | Enable verbose output |
| `-h, --help` | — | Print help information |
| `-V, --version` | — | Print version information |

**Output Formats:**

```bash
# JSON (default) - full token response
yoauth -o json

# Token only - just the access token string
yoauth -o token

# Pretty - human-readable format
yoauth -o pretty
```

**Configuration Priority:**

Settings are loaded in this order (highest priority first):
1. Command line arguments
2. Environment variables (prefixed with `YOAUTH_`)
3. Config file (`yoauth.toml` or specified via `--config`)
4. Default values

### PKCE

PKCE (Proof Key for Code Exchange) hardens the authorization code flow against interception attacks. By default yoauth **auto-detects** the best method by fetching the provider's OIDC discovery document (`/.well-known/openid-configuration`). Use `S256` when available, otherwise fall back to `plain`. Set `--challenge-method none` to opt out entirely.

```bash
# Force S256 (recommended for public clients)
yoauth --challenge-method s256 ...

# Force plain
yoauth --challenge-method plain ...

# Disable PKCE
yoauth --challenge-method none ...
```

Or in `yoauth.toml`:

```toml
challenge_method = "S256"  # "S256" | "plain" | "none"
```

### Custom Success Page

After a successful authorization the user's browser shows a built-in success page. You can replace it with your own HTML file:

```bash
yoauth --success-html-file ./success.html ...
```

Or in `yoauth.toml`:

```toml
success_html_file = "success.html"
```

The repository ships a sample `success.html` with a dark animated theme that you can use directly or customise further.

### Library Usage

#### Basic example with auto-generated certificates (recommended)

```rust
use yoauth::{get_oauth_token, OAuthConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = OAuthConfig::new(
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
        "YOUR_CLIENT_ID",
        "YOUR_CLIENT_SECRET",
    )
    .with_scopes(vec![
        "https://www.googleapis.com/auth/userinfo.email".to_string(),
    ]);

    let token = get_oauth_token(config)?;
    println!("Access token: {}", token.access_token);

    Ok(())
}
```

By default, the library will automatically generate a self-signed certificate using `rcgen` for TLS. This happens transparently - you don't need to provide certificates manually.

#### Using PKCE

```rust
use yoauth::{get_oauth_token, OAuthConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = OAuthConfig::new(
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
        "YOUR_CLIENT_ID",
        "YOUR_CLIENT_SECRET",
    )
    .with_scopes(vec![
        "https://www.googleapis.com/auth/userinfo.email".to_string(),
    ])
    // None  → auto-detect via OIDC discovery (recommended)
    // Some  → force a specific method
    .with_pkce_method(None);

    let token = get_oauth_token(config)?;
    println!("Access token: {}", token.access_token);

    Ok(())
}
```

To force a specific method pass `Some("S256".to_string())`, `Some("plain".to_string())`, or `Some("none".to_string())`.

#### Custom success page

```rust
use yoauth::{get_oauth_token, OAuthConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let success_html = std::fs::read_to_string("success.html").ok();

    let config = OAuthConfig::new(
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
        "YOUR_CLIENT_ID",
        "YOUR_CLIENT_SECRET",
    )
    .with_scopes(vec![
        "https://www.googleapis.com/auth/userinfo.email".to_string(),
    ])
    .with_success_html(success_html);

    let token = get_oauth_token(config)?;
    println!("Access token: {}", token.access_token);

    Ok(())
}
```

Pass `None` to `with_success_html` to use the built-in default page.

#### Using external certificates

If you want to use your own certificates:

```rust
use yoauth::{get_oauth_token, OAuthConfig, SslCerts};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ssl_certs = SslCerts::from_files("cert.pem", "key.pem")?;

    let config = OAuthConfig::new(
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
        "YOUR_CLIENT_ID",
        "YOUR_CLIENT_SECRET",
    )
    .with_scopes(vec![
        "https://www.googleapis.com/auth/userinfo.email".to_string(),
    ])
    .with_ssl_certs(ssl_certs);

    let token = get_oauth_token(config)?;
    println!("Access token: {}", token.access_token);

    Ok(())
}
```

> 📝 For generating external certificates manually, SUSE provides a nice tutorial: https://www.suse.com/support/kb/doc/?id=000018152

#### Disabling TLS (not recommended)

> [!WARNING]
> If you really REALLY trust your network you can disable TLS, but be aware that **tokens** providing access to your potentially expensive cloud resources or sensitive data **will be sent around in plain-text**. This software is distributed under MIT license. The author will not be held responsible for any damages caused by your negligence.

```rust
use yoauth::{get_oauth_token, OAuthConfig};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = OAuthConfig::new(
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://oauth2.googleapis.com/token",
        "YOUR_CLIENT_ID",
        "YOUR_CLIENT_SECRET",
    )
    .with_tls(false);

    let token = get_oauth_token(config)?;
    println!("Access token: {}", token.access_token);

    Ok(())
}
```

## How it works

The `get_oauth_token` function:

1. Opens your system's default web browser with the authorization URL (typically a login page)
2. Creates a short-lived `localhost` web server on a free system-provided port and waits for the authorization redirect
3. The browser automatically redirects after successful login
4. Server receives the authorization code from the redirect and stops serving
5. Sends a request to the token URL with the authorization code and receives the token in response

## License

MIT

## Author

Peter Výboch <pvyboch1@gmail.com>
