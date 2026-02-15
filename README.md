# YOAuth 🔑

Getting a token has never been easier. Rust port of [YOAuth](https://github.com/petereon/yoauth) using `tiny_http`, `rustls`, and `rcgen` for self-signed certificate generation. Now also as a CLI command for all your scripting needs 📜

## Features ✨

- OAuth2 authorization code flow
- Automatic certificate generation using `rcgen`
- TLS support via `rustls`
- Lightweight HTTP server using `tiny_http`
- Automatic browser opening for authorization
- Optional external certificate loading

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

- `-a, --authorization-url <URL>` - OAuth2 authorization endpoint URL
- `-t, --token-url <URL>` - OAuth2 token endpoint URL
- `-i, --client-id <ID>` - OAuth2 client ID
- `-s, --client-secret <SECRET>` - OAuth2 client secret
- `--scopes <SCOPES>` - Comma-separated list of OAuth2 scopes
- `-o, --output <FORMAT>` - Output format: `json`, `token`, or `pretty` (default: `json`)
- `--token-only` - Output only the access token (shortcut for `-o token`)
- `-c, --config <PATH>` - Path to config file (default: `./yoauth.toml`)
- `--cert-file <PATH>` - Path to TLS certificate file (PEM format)
- `--key-file <PATH>` - Path to TLS private key file (PEM format)
- `--disable-tls` - Disable TLS/HTTPS (NOT RECOMMENDED)
- `-v, --verbose` - Enable verbose output
- `-h, --help` - Print help information
- `-V, --version` - Print version information

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
