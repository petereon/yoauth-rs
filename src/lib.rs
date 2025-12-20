use rcgen::generate_simple_self_signed;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::{Arc, Once};
use tiny_http::{Response, Server};
use url::Url;

static INIT_CRYPTO: Once = Once::new();

/// Initialize the rustls crypto provider
fn init_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

#[derive(Debug)]
pub enum OAuthError {
    IoError(std::io::Error),
    CertificateError(String),
    HttpError(String),
    UrlError(url::ParseError),
    JsonError(serde_json::Error),
    RequestError(String),
}

impl From<std::io::Error> for OAuthError {
    fn from(e: std::io::Error) -> Self {
        OAuthError::IoError(e)
    }
}

impl From<url::ParseError> for OAuthError {
    fn from(e: url::ParseError) -> Self {
        OAuthError::UrlError(e)
    }
}

impl From<serde_json::Error> for OAuthError {
    fn from(e: serde_json::Error) -> Self {
        OAuthError::JsonError(e)
    }
}

impl From<Box<dyn std::error::Error>> for OAuthError {
    fn from(e: Box<dyn std::error::Error>) -> Self {
        OAuthError::RequestError(e.to_string())
    }
}

impl std::fmt::Display for OAuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            OAuthError::IoError(e) => write!(f, "IO error: {}", e),
            OAuthError::CertificateError(e) => write!(f, "Certificate error: {}", e),
            OAuthError::HttpError(e) => write!(f, "HTTP error: {}", e),
            OAuthError::UrlError(e) => write!(f, "URL error: {}", e),
            OAuthError::JsonError(e) => write!(f, "JSON error: {}", e),
            OAuthError::RequestError(e) => write!(f, "Request error: {}", e),
        }
    }
}

impl std::error::Error for OAuthError {}

#[derive(Debug, Clone)]
pub struct SslCerts {
    pub cert_pem: Vec<u8>,
    pub key_pem: Vec<u8>,
}

impl SslCerts {
    /// Generate a self-signed certificate
    pub fn generate() -> Result<Self, OAuthError> {
        let subject_alt_names = vec!["localhost".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names)
            .map_err(|e| OAuthError::CertificateError(e.to_string()))?;

        Ok(SslCerts {
            cert_pem: cert.cert.pem().into_bytes(),
            key_pem: cert.key_pair.serialize_pem().into_bytes(),
        })
    }

    /// Load certificates from PEM files
    pub fn from_files(cert_path: &str, key_path: &str) -> Result<Self, OAuthError> {
        let cert_pem = std::fs::read(cert_path)?;
        let key_pem = std::fs::read(key_path)?;
        Ok(SslCerts { cert_pem, key_pem })
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

pub struct OAuthConfig {
    pub authorization_url: String,
    pub token_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Vec<String>,
    pub require_tls: bool,
    pub ssl_certs: Option<SslCerts>,
    pub verbose: bool,
}

impl OAuthConfig {
    pub fn new(
        authorization_url: impl Into<String>,
        token_url: impl Into<String>,
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
    ) -> Self {
        Self {
            authorization_url: authorization_url.into(),
            token_url: token_url.into(),
            client_id: client_id.into(),
            client_secret: client_secret.into(),
            scopes: Vec::new(),
            require_tls: true,
            ssl_certs: None,
            verbose: false,
        }
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes;
        self
    }

    pub fn with_tls(mut self, require_tls: bool) -> Self {
        self.require_tls = require_tls;
        self
    }

    pub fn with_ssl_certs(mut self, ssl_certs: SslCerts) -> Self {
        self.ssl_certs = Some(ssl_certs);
        self
    }

    pub fn with_verbose(mut self, verbose: bool) -> Self {
        self.verbose = verbose;
        self
    }
}

pub fn get_oauth_token(config: OAuthConfig) -> Result<TokenResponse, OAuthError> {
    // Initialize crypto provider for rustls
    init_crypto_provider();

    // Create TCP listener on random available port
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let protocol = if config.require_tls { "https" } else { "http" };
    let redirect_uri = format!("{}://localhost:{}", protocol, port);

    // Build authorization URL
    let mut auth_url = Url::parse(&config.authorization_url)?;
    auth_url
        .query_pairs_mut()
        .append_pair("client_id", &config.client_id)
        .append_pair("redirect_uri", &redirect_uri)
        .append_pair("response_type", "code")
        .append_pair("scope", &config.scopes.join(","));

    // Open browser
    if config.verbose {
        println!("Opening browser to: {}", auth_url);
    }
    if let Err(e) = webbrowser::open(auth_url.as_str()) {
        eprintln!("Warning: Failed to open browser: {}. Please navigate manually.", e);
    }

    // Start server and wait for callback
    let authorization_code = if config.require_tls {
        // Generate or use provided certificates
        let ssl_certs = match config.ssl_certs {
            Some(certs) => certs,
            None => SslCerts::generate()?,
        };

        start_https_server(listener, ssl_certs, config.verbose)?
    } else {
        start_http_server(listener)?
    };

    // Exchange authorization code for token
    let token_request = serde_json::json!({
        "client_id": config.client_id,
        "client_secret": config.client_secret,
        "code": authorization_code,
        "grant_type": "authorization_code",
        "redirect_uri": redirect_uri,
    });

    let response = ureq::post(&config.token_url)
        .send_json(&token_request)
        .map_err(|e| OAuthError::RequestError(e.to_string()))?;

    let token: TokenResponse = response.into_json()?;
    Ok(token)
}

fn start_http_server(listener: TcpListener) -> Result<String, OAuthError> {
    let server = Server::from_listener(listener, None)
        .map_err(|e| OAuthError::HttpError(e.to_string()))?;

    for request in server.incoming_requests() {
        let url = request.url();
        if let Some(code) = extract_code_from_url(url) {
            let html = "<!DOCTYPE html><html><head><title>Authorized</title></head><body><h1>✓ Authorized</h1><p>You can close this window now.</p><script>window.close();</script></body></html>";
            let response = Response::from_string(html).with_header(
                tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"text/html; charset=utf-8"[..]).unwrap()
            );
            let _ = request.respond(response);
            return Ok(code);
        }

        let error_response = Response::from_string("Authorization failed");
        let _ = request.respond(error_response);
    }

    Err(OAuthError::HttpError(
        "Server closed without receiving authorization code".to_string(),
    ))
}

fn start_https_server(listener: TcpListener, ssl_certs: SslCerts, verbose: bool) -> Result<String, OAuthError> {
    // Parse certificates
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut ssl_certs.cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| OAuthError::CertificateError(e.to_string()))?;

    let key = rustls_pemfile::private_key(&mut ssl_certs.key_pem.as_slice())
        .map_err(|e| OAuthError::CertificateError(e.to_string()))?
        .ok_or_else(|| OAuthError::CertificateError("No private key found".to_string()))?;

    // Create TLS configuration
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| OAuthError::CertificateError(e.to_string()))?;

    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let config = Arc::new(config);

    // Accept connections manually with TLS
    if verbose {
        eprintln!("Waiting for OAuth callback. Please accept the certificate warning in your browser...");
    }

    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                if verbose {
                    eprintln!("Connection error: {}. Continuing to wait...", e);
                }
                continue;
            }
        };

        let mut tls_stream = match rustls::ServerConnection::new(config.clone()) {
            Ok(s) => s,
            Err(e) => {
                if verbose {
                    eprintln!("TLS setup error: {}. Continuing to wait...", e);
                }
                continue;
            }
        };

        // TLS handshake
        let handshake_result = loop {
            if tls_stream.is_handshaking() {
                match tls_stream.complete_io(&mut stream) {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => break Err(e),
                }
            } else {
                break Ok(());
            }
        };

        if let Err(e) = handshake_result {
            if verbose {
                eprintln!("TLS handshake failed: {}. Waiting for retry...", e);
            }
            continue;
        }

        // Read HTTP request
        let mut buffer = Vec::new();
        let mut tls_reader = rustls::StreamOwned::new(tls_stream, stream);

        // Read until we have the request line
        let mut temp_buf = [0u8; 1024];
        loop {
            match tls_reader.read(&mut temp_buf) {
                Ok(0) => break,
                Ok(n) => {
                    buffer.extend_from_slice(&temp_buf[..n]);
                    // Check if we have a complete request line
                    if buffer.windows(4).position(|w| w == b"\r\n\r\n").is_some() {
                        break;
                    }
                    if buffer.len() > 8192 { // Prevent DoS
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(_) => break,
            }
        }

        let request_str = String::from_utf8_lossy(&buffer);

        // Parse the request line to get the path
        if let Some(first_line) = request_str.lines().next() {
            let parts: Vec<&str> = first_line.split_whitespace().collect();
            if parts.len() >= 2 {
                let path = parts[1];

                if let Some(code) = extract_code_from_url(path) {
                    let html = "<!DOCTYPE html><html><head><title>Authorized</title></head><body><h1>✓ Authorized</h1><p>You can close this window now.</p><script>window.close();</script></body></html>";
                    let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\r\n{}", html.len(), html);
                    let _ = tls_reader.write_all(response.as_bytes());
                    let _ = tls_reader.flush();
                    return Ok(code);
                }
            }
        }

        let error_response = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 21\r\n\r\nAuthorization failed";
        let _ = tls_reader.write_all(error_response);
        let _ = tls_reader.flush();
    }

    Err(OAuthError::HttpError(
        "Server closed without receiving authorization code".to_string(),
    ))
}

fn extract_code_from_url(url: &str) -> Option<String> {
    let parsed = Url::parse(&format!("http://localhost{}", url)).ok()?;
    for (key, value) in parsed.query_pairs() {
        if key == "code" {
            return Some(value.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_code() {
        let url = "/?code=test_code_123&state=abc";
        assert_eq!(
            extract_code_from_url(url),
            Some("test_code_123".to_string())
        );
    }

    #[test]
    fn test_generate_certificates() {
        let certs = SslCerts::generate();
        assert!(certs.is_ok());
        let certs = certs.unwrap();
        assert!(!certs.cert_pem.is_empty());
        assert!(!certs.key_pem.is_empty());
    }
}
