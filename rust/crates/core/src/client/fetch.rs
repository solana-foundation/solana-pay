//! Built-in HTTP client using reqwest. No external binary needed.

use std::fs::{self, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use rand::{RngCore, rngs::OsRng};
use reqwest::Method;
use reqwest::blocking::Client;
use tracing::debug;

use crate::client::runner::{self, RunOutcome};
use crate::{ClientApp, Error, Result};

/// Internal header used to preserve no-redirect semantics through Pay's local
/// debugger proxy. The proxy must remove this before forwarding upstream.
pub const DEBUGGER_NO_FOLLOW_HEADER: &str = "x-pay-debugger-no-follow";
pub const DEBUGGER_NO_FOLLOW_HEADER_VALUE: &str = "1";

/// Maximum size of an owned request body, including multipart framing.
pub const MAX_REQUEST_BODY_BYTES: usize = 64 * 1024 * 1024;

/// One file included in a multipart request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MultipartFile {
    pub name: String,
    pub path: PathBuf,
    pub filename: Option<String>,
    pub content_type: Option<String>,
}

/// An owned, replayable HTTP request body.
///
/// Keeping the body owned lets callers reuse the exact same byte snapshot for
/// an initial request and a paid retry without rereading a source file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestBody(bytes::Bytes);

impl RequestBody {
    pub fn text(value: impl Into<String>) -> Self {
        Self(bytes::Bytes::from(value.into()))
    }

    pub fn bytes(value: impl Into<bytes::Bytes>) -> Self {
        Self(value.into())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns a UTF-8 view when the body can participate in JSON/OpenAPI
    /// validation. Binary bodies that are not UTF-8 return `None`.
    pub fn as_text(&self) -> Option<&str> {
        std::str::from_utf8(&self.0).ok()
    }

    /// Snapshot one regular, non-symlink file into a replayable request body.
    pub fn from_file(path: &Path) -> Result<(Self, String)> {
        let bytes = read_request_file(path)?;
        let content_type = mime_guess::from_path(path)
            .first_raw()
            .unwrap_or("application/octet-stream")
            .to_string();
        Ok((Self::bytes(bytes), content_type))
    }

    /// Snapshot files and construct one replayable multipart/form-data body.
    pub fn multipart(
        fields: &[(String, String)],
        files: &[MultipartFile],
    ) -> Result<(Self, String)> {
        if fields.is_empty() && files.is_empty() {
            return Err(Error::RequestValidation(
                "A multipart request needs at least one --form or --form-file value.".to_string(),
            ));
        }
        if files.len() > 16 {
            return Err(Error::RequestValidation(format!(
                "A multipart request can contain at most 16 files; received {}.",
                files.len()
            )));
        }

        for (name, _) in fields {
            validate_disposition_value("form field name", name)?;
        }
        for file in files {
            validate_disposition_value("file field name", &file.name)?;
            if let Some(filename) = &file.filename {
                validate_disposition_value("filename", filename)?;
            }
            if let Some(content_type) = &file.content_type {
                normalize_content_type(content_type)?;
            }
        }

        let snapshots = files
            .iter()
            .map(|file| {
                let bytes = read_request_file(&file.path)?;
                let filename = match &file.filename {
                    Some(filename) => filename.clone(),
                    None => file
                        .path
                        .file_name()
                        .and_then(|name| name.to_str())
                        .map(str::to_string)
                        .ok_or_else(|| {
                            Error::RequestValidation(format!(
                                "Multipart file `{}` needs a UTF-8 filename; rename it or supply an explicit filename.",
                                file.path.display()
                            ))
                        })?,
                };
                validate_disposition_value("filename", &filename)?;
                let content_type = file
                    .content_type
                    .as_deref()
                    .map(normalize_content_type)
                    .transpose()?
                    .unwrap_or_else(|| {
                        mime_guess::from_path(&file.path)
                            .first_raw()
                            .unwrap_or("application/octet-stream")
                            .to_string()
                    });
                Ok((file.name.clone(), filename, content_type, bytes))
            })
            .collect::<Result<Vec<_>>>()?;

        let boundary = multipart_boundary(fields, &snapshots);
        let mut body = Vec::new();
        for (name, value) in fields {
            append_with_limit(&mut body, format!("--{boundary}\r\n").as_bytes())?;
            append_with_limit(
                &mut body,
                format!("Content-Disposition: form-data; name=\"{name}\"\r\n\r\n").as_bytes(),
            )?;
            append_with_limit(&mut body, value.as_bytes())?;
            append_with_limit(&mut body, b"\r\n")?;
        }
        for (name, filename, content_type, bytes) in snapshots {
            append_with_limit(&mut body, format!("--{boundary}\r\n").as_bytes())?;
            append_with_limit(
                &mut body,
                format!(
                    "Content-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\n"
                )
                .as_bytes(),
            )?;
            append_with_limit(
                &mut body,
                format!("Content-Type: {content_type}\r\n\r\n").as_bytes(),
            )?;
            append_with_limit(&mut body, &bytes)?;
            append_with_limit(&mut body, b"\r\n")?;
        }
        append_with_limit(&mut body, format!("--{boundary}--\r\n").as_bytes())?;

        Ok((
            Self::bytes(body),
            format!("multipart/form-data; boundary={boundary}"),
        ))
    }
}

/// Validate and canonicalize an HTTP content type.
pub fn normalize_content_type(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() || value.len() > 1024 {
        return Err(Error::RequestValidation(
            "Content type must be a non-empty MIME type of at most 1024 bytes.".to_string(),
        ));
    }
    let parsed = value.parse::<mime_guess::Mime>().map_err(|_| {
        Error::RequestValidation(format!(
            "Content type `{value}` is invalid; use a MIME type such as `application/json` or `image/png`."
        ))
    })?;
    let canonical = parsed.to_string();
    reqwest::header::HeaderValue::from_str(&canonical).map_err(|_| {
        Error::RequestValidation(format!(
            "Content type `{value}` is not a valid HTTP header value."
        ))
    })?;
    Ok(canonical)
}

fn read_request_file(path: &Path) -> Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        Error::RequestValidation(format!(
            "Could not inspect request body file `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(Error::RequestValidation(format!(
            "Request body file `{}` must not be a symlink.",
            path.display()
        )));
    }
    if !metadata.file_type().is_file() {
        return Err(Error::RequestValidation(format!(
            "Request body source `{}` must be a regular file.",
            path.display()
        )));
    }
    if metadata.len() > MAX_REQUEST_BODY_BYTES as u64 {
        return Err(Error::RequestValidation(format!(
            "Request body file `{}` exceeds the 64 MiB limit.",
            path.display()
        )));
    }

    let file = open_request_file_no_follow(path).map_err(|error| {
        Error::RequestValidation(format!(
            "Could not open request body file `{}`: {error}",
            path.display()
        ))
    })?;
    if !file.metadata()?.file_type().is_file() {
        return Err(Error::RequestValidation(format!(
            "Request body source `{}` must be a regular file.",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_REQUEST_BODY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_REQUEST_BODY_BYTES {
        return Err(Error::RequestValidation(format!(
            "Request body file `{}` exceeds the 64 MiB limit.",
            path.display()
        )));
    }
    Ok(bytes)
}

fn open_request_file_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn validate_disposition_value(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character == '"' || character == '\\' || character.is_control())
    {
        return Err(Error::RequestValidation(format!(
            "Multipart {label} `{value}` must be non-empty and contain no quotes, backslashes, or control characters."
        )));
    }
    Ok(())
}

fn multipart_boundary(
    fields: &[(String, String)],
    files: &[(String, String, String, Vec<u8>)],
) -> String {
    loop {
        let mut random = [0_u8; 24];
        OsRng.fill_bytes(&mut random);
        let boundary = format!("pay-{}", hex_bytes(&random));
        let appears_in_input = fields.iter().any(|(_, value)| {
            value
                .as_bytes()
                .windows(boundary.len())
                .any(|w| w == boundary.as_bytes())
        }) || files.iter().any(|(_, _, _, bytes)| {
            bytes
                .windows(boundary.len())
                .any(|window| window == boundary.as_bytes())
        });
        if !appears_in_input {
            return boundary;
        }
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn append_with_limit(body: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    let next_len = body.len().checked_add(bytes.len()).ok_or_else(|| {
        Error::RequestValidation("Multipart request body size overflowed.".to_string())
    })?;
    if next_len > MAX_REQUEST_BODY_BYTES {
        return Err(Error::RequestValidation(
            "Multipart request body exceeds the 64 MiB limit.".to_string(),
        ));
    }
    body.extend_from_slice(bytes);
    Ok(())
}

impl From<&str> for RequestBody {
    fn from(value: &str) -> Self {
        Self(bytes::Bytes::copy_from_slice(value.as_bytes()))
    }
}

impl From<String> for RequestBody {
    fn from(value: String) -> Self {
        Self(bytes::Bytes::from(value))
    }
}

impl From<Vec<u8>> for RequestBody {
    fn from(value: Vec<u8>) -> Self {
        Self(bytes::Bytes::from(value))
    }
}

/// Controls whether reqwest follows HTTP redirects.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RedirectPolicy {
    /// Use reqwest's normal redirect behavior.
    #[default]
    Follow,
    /// Return the first redirect response without forwarding the request body.
    None,
}

/// Raw HTTP response — keeps status, headers, and body together so callers
/// (e.g. the rich probe pipeline) can both run `classify_402` and extract
/// additional 402 metadata without a second request.
///
/// `body` is held as raw bytes so binary responses (images, PDFs,
/// arbitrary `application/octet-stream`) round-trip without UTF-8
/// mangling. Use [`RawResponse::body_text`] when a string view is needed
/// (e.g. parsing a 402 challenge body, which is always JSON).
#[derive(Debug, Clone)]
pub struct RawResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl RawResponse {
    /// UTF-8 view of the body, with invalid sequences replaced by `U+FFFD`.
    /// Right call for text-typed responses (`text/*`, `application/json`,
    /// `application/xml`) where the wire format is guaranteed to be UTF-8.
    /// Wrong call for `image/*`, `application/pdf`, etc. — those should be
    /// handled as `Vec<u8>` directly.
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// `content-type` header value (case-insensitive lookup), or `None` if
    /// the server didn't send one. Includes the full value with
    /// parameters (e.g. `text/plain; charset=utf-8`); use
    /// [`RawResponse::mime_type`] to strip params and lowercase.
    pub fn content_type(&self) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-type"))
            .map(|(_, v)| v.as_str())
    }

    /// Lowercased MIME type with parameters stripped — `"text/plain"` from
    /// `"Text/Plain; charset=UTF-8"`. Empty string when the header is
    /// missing or malformed.
    pub fn mime_type(&self) -> String {
        self.content_type()
            .and_then(|v| v.split(';').next())
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default()
    }
}

/// Fetch a URL with an explicit HTTP method/body, detecting 402 + MPP challenges.
pub fn fetch_request(
    method: &str,
    url: &str,
    extra_headers: &[(String, String)],
    body: Option<&str>,
) -> Result<RunOutcome> {
    fetch_request_for(ClientApp::Cli, method, url, extra_headers, body)
}

pub fn fetch_request_for(
    client_app: ClientApp,
    method: &str,
    url: &str,
    extra_headers: &[(String, String)],
    body: Option<&str>,
) -> Result<RunOutcome> {
    let body = body.map(RequestBody::from);
    fetch_request_with_body_for(
        client_app,
        method,
        url,
        extra_headers,
        body.as_ref(),
        RedirectPolicy::Follow,
    )
}

/// Fetch a URL with an owned, replayable body and explicit redirect policy.
pub fn fetch_request_with_body_for(
    client_app: ClientApp,
    method: &str,
    url: &str,
    extra_headers: &[(String, String)],
    body: Option<&RequestBody>,
    redirect_policy: RedirectPolicy,
) -> Result<RunOutcome> {
    let method = Method::from_bytes(method.as_bytes())
        .map_err(|e| Error::Mpp(format!("Invalid HTTP method `{method}`: {e}")))?;
    let raw = fetch_raw_with_method(
        client_app,
        method,
        url,
        extra_headers,
        body,
        redirect_policy,
    )?;
    if redirect_policy == RedirectPolicy::None && (300..400).contains(&raw.status) {
        let location = raw
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("location"))
            .map(|(_, value)| value.as_str())
            .filter(|value| !value.is_empty());
        let location_guidance = location.map_or_else(
            || {
                " The response did not include a Location header; find the endpoint's final URL before staging the body again."
                    .to_string()
            },
            |location| {
                format!(
                    " The response Location is `{location}`; rerun the request against that final URL before retrying."
                )
            },
        );
        return Err(Error::RequestValidation(format!(
            "The request body was sent only to its bound URL. Pay did not forward it to the redirect destination after the server returned HTTP {}.{location_guidance}",
            raw.status
        )));
    }
    Ok(raw_to_outcome(raw, url))
}

/// Fetch a URL, detecting 402 + MPP challenges.
pub fn fetch(url: &str, extra_headers: &[(String, String)]) -> Result<RunOutcome> {
    let raw = fetch_raw_with_method(
        ClientApp::Cli,
        Method::GET,
        url,
        extra_headers,
        None,
        RedirectPolicy::Follow,
    )?;
    Ok(raw_to_outcome(raw, url))
}

/// Fetch a URL and return the raw status/headers/body — no 402 classification.
///
/// Use this when the caller needs to do its own analysis of the response
/// (e.g. the skills probe enriches the response with all advertised payment
/// protocols, not just the one Pay would settle on).
pub fn fetch_raw(
    method: &str,
    url: &str,
    extra_headers: &[(String, String)],
    body: Option<&str>,
) -> Result<RawResponse> {
    fetch_raw_for(ClientApp::Cli, method, url, extra_headers, body)
}

pub fn fetch_raw_for(
    client_app: ClientApp,
    method: &str,
    url: &str,
    extra_headers: &[(String, String)],
    body: Option<&str>,
) -> Result<RawResponse> {
    let body = body.map(RequestBody::from);
    fetch_raw_with_body_for(
        client_app,
        method,
        url,
        extra_headers,
        body.as_ref(),
        RedirectPolicy::Follow,
    )
}

/// Fetch a raw response with an owned, replayable body and redirect policy.
pub fn fetch_raw_with_body_for(
    client_app: ClientApp,
    method: &str,
    url: &str,
    extra_headers: &[(String, String)],
    body: Option<&RequestBody>,
    redirect_policy: RedirectPolicy,
) -> Result<RawResponse> {
    let method = Method::from_bytes(method.as_bytes())
        .map_err(|e| Error::Mpp(format!("Invalid HTTP method `{method}`: {e}")))?;
    fetch_raw_with_method(
        client_app,
        method,
        url,
        extra_headers,
        body,
        redirect_policy,
    )
}

fn raw_to_outcome(raw: RawResponse, url: &str) -> RunOutcome {
    if raw.status == 402 {
        // 402 challenge bodies are always JSON-as-text per spec; the
        // text view is correct here.
        return runner::classify_402(&raw.headers, Some(&raw.body_text()), url);
    }
    let exit_code = if raw.status >= 400 { 1 } else { 0 };
    let content_type = raw.content_type().map(str::to_string);
    RunOutcome::Completed {
        exit_code,
        body: Some(raw.body),
        content_type,
        response_headers: raw.headers,
    }
}

fn fetch_raw_with_method(
    client_app: ClientApp,
    method: Method,
    url: &str,
    extra_headers: &[(String, String)],
    body: Option<&RequestBody>,
    redirect_policy: RedirectPolicy,
) -> Result<RawResponse> {
    let mut client_builder = Client::builder().user_agent(client_app.user_agent());
    if redirect_policy == RedirectPolicy::None {
        client_builder = client_builder.redirect(reqwest::redirect::Policy::none());
    }
    let client = client_builder
        .build()
        .map_err(|e| Error::Mpp(format!("Failed to create HTTP client: {e}")))?;

    // When the debugger proxy is active, route through it so PDB captures
    // the traffic. The original URL is passed in X-Pay-Forward-To.
    let (actual_url, forward_header) = if let Ok(proxy) = std::env::var("PAY_DEBUGGER_PROXY") {
        // Rewrite: https://gateway/path → http://127.0.0.1:1402/path
        let path = url
            .find("://")
            .and_then(|i| url[i + 3..].find('/'))
            .map(|i| &url[url.find("://").unwrap() + 3 + i..])
            .unwrap_or("/");
        let proxy_url = format!("{}{}", proxy.trim_end_matches('/'), path);
        debug!(%url, %proxy_url, "Routing through debugger proxy");
        (proxy_url, Some(url.to_string()))
    } else {
        (url.to_string(), None)
    };

    debug!(%method, url = %actual_url, has_body = body.is_some(), "Fetching");

    let mut req = client.request(method, &actual_url);
    if let Some(dest) = &forward_header {
        req = req.header("x-pay-forward-to", dest.as_str());
    }
    for (key, value) in extra_headers {
        req = req.header(key.as_str(), value.as_str());
    }
    if forward_header.is_some() && redirect_policy == RedirectPolicy::None {
        req = req.header(DEBUGGER_NO_FOLLOW_HEADER, DEBUGGER_NO_FOLLOW_HEADER_VALUE);
    }
    if let Some(body) = body {
        req = req.body(body.0.clone());
    }

    let resp = req
        .send()
        .map_err(|e| Error::Mpp(format!("Request failed: {e}")))?;
    let status = resp.status().as_u16();

    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase(),
                v.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();

    // Use `bytes()` not `text()` — `text()` UTF-8-decodes lossily and
    // replaces non-UTF-8 sequences with `U+FFFD`, irreversibly mangling
    // binary responses (images, PDFs, octet-streams). Callers that want
    // a string view ask for `body_text()` explicitly.
    let body = resp
        .bytes()
        .map(|b| b.to_vec())
        .map_err(|e| Error::Mpp(format!("Failed to read body: {e}")))?;

    debug!(status, "Fetch complete");

    Ok(RawResponse {
        status,
        headers,
        body,
    })
}

#[cfg(all(test, feature = "server"))]
mod tests {
    use super::*;
    use crate::client::runner::RunOutcome;

    /// Start a background server on a random port, return its URL.
    /// Uses a separate thread with its own tokio runtime to avoid
    /// conflicts with reqwest::blocking inside fetch().
    fn start_server(handler: axum::Router) -> String {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                tx.send(format!("http://{addr}")).unwrap();
                axum::serve(listener, handler).await.ok();
            });
        });
        let url = rx.recv().unwrap();
        // Give the server time to accept connections
        std::thread::sleep(std::time::Duration::from_millis(50));
        url
    }

    #[test]
    fn fetch_200_returns_body() {
        let app =
            axum::Router::new().route("/data", axum::routing::get(|| async { "hello world" }));
        let base_url = start_server(app);

        let result = fetch(&format!("{base_url}/data"), &[]).unwrap();
        match result {
            RunOutcome::Completed {
                exit_code, body, ..
            } => {
                assert_eq!(exit_code, 0);
                assert_eq!(body.unwrap(), b"hello world");
            }
            _ => panic!("Expected Completed"),
        }
    }

    #[test]
    fn fetch_404_returns_exit_code_1() {
        let app = axum::Router::new().route(
            "/missing",
            axum::routing::get(|| async { (axum::http::StatusCode::NOT_FOUND, "not found") }),
        );
        let base_url = start_server(app);

        let result = fetch(&format!("{base_url}/missing"), &[]).unwrap();
        match result {
            RunOutcome::Completed {
                exit_code, body, ..
            } => {
                assert_eq!(exit_code, 1);
                assert_eq!(body.unwrap(), b"not found");
            }
            _ => panic!("Expected Completed"),
        }
    }

    #[test]
    fn fetch_402_without_mpp_returns_unknown() {
        let app = axum::Router::new().route(
            "/paid",
            axum::routing::get(|| async { (axum::http::StatusCode::PAYMENT_REQUIRED, "pay up") }),
        );
        let base_url = start_server(app);

        let result = fetch(&format!("{base_url}/paid"), &[]).unwrap();
        assert!(matches!(result, RunOutcome::UnknownPaymentRequired { .. }));
    }

    #[test]
    fn fetch_sends_extra_headers() {
        let app = axum::Router::new().route(
            "/echo-header",
            axum::routing::get(|headers: axum::http::HeaderMap| async move {
                headers
                    .get("x-custom")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("missing")
                    .to_string()
            }),
        );
        let base_url = start_server(app);

        let headers = vec![("x-custom".to_string(), "test-value".to_string())];
        let result = fetch(&format!("{base_url}/echo-header"), &headers).unwrap();
        match result {
            RunOutcome::Completed { body, .. } => {
                assert_eq!(body.unwrap(), b"test-value");
            }
            _ => panic!("Expected Completed"),
        }
    }

    #[test]
    fn fetch_defaults_to_cli_user_agent() {
        let app = axum::Router::new().route(
            "/ua",
            axum::routing::get(|headers: axum::http::HeaderMap| async move {
                headers
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("missing")
                    .to_string()
            }),
        );
        let base_url = start_server(app);

        let result = fetch(&format!("{base_url}/ua"), &[]).unwrap();
        match result {
            RunOutcome::Completed { body, .. } => {
                assert_eq!(
                    body.unwrap(),
                    ClientApp::Cli.user_agent().as_bytes().to_vec()
                );
            }
            _ => panic!("Expected Completed"),
        }
    }

    #[test]
    fn fetch_request_for_sends_mcp_user_agent() {
        let app = axum::Router::new().route(
            "/ua",
            axum::routing::get(|headers: axum::http::HeaderMap| async move {
                headers
                    .get("user-agent")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("missing")
                    .to_string()
            }),
        );
        let base_url = start_server(app);

        let result =
            fetch_request_for(ClientApp::Mcp, "GET", &format!("{base_url}/ua"), &[], None).unwrap();
        match result {
            RunOutcome::Completed { body, .. } => {
                assert_eq!(
                    body.unwrap(),
                    ClientApp::Mcp.user_agent().as_bytes().to_vec()
                );
            }
            _ => panic!("Expected Completed"),
        }
    }

    #[test]
    fn fetch_request_sends_post_body() {
        let app = axum::Router::new().route(
            "/echo-body",
            axum::routing::post(|body: String| async move { body }),
        );
        let base_url = start_server(app);

        let result = fetch_request(
            "POST",
            &format!("{base_url}/echo-body"),
            &[("content-type".to_string(), "application/json".to_string())],
            Some("{\"query\":\"SELECT 1\"}"),
        )
        .unwrap();

        match result {
            RunOutcome::Completed {
                exit_code, body, ..
            } => {
                assert_eq!(exit_code, 0);
                assert_eq!(body.unwrap(), br#"{"query":"SELECT 1"}"#);
            }
            _ => panic!("Expected Completed"),
        }
    }

    #[test]
    fn replayable_request_body_preserves_non_utf8_bytes() {
        let app = axum::Router::new().route(
            "/echo-bytes",
            axum::routing::post(|body: axum::body::Bytes| async move { body }),
        );
        let base_url = start_server(app);
        let payload = vec![0x00, 0xFF, 0xFE, 0x80, b'P', b'N', b'G'];
        let body = RequestBody::bytes(payload.clone());

        // The same owned snapshot can be borrowed for both the initial request
        // and its retry without rereading or re-encoding it.
        for _ in 0..2 {
            let raw = fetch_raw_with_body_for(
                ClientApp::Cli,
                "POST",
                &format!("{base_url}/echo-bytes"),
                &[],
                Some(&body),
                RedirectPolicy::Follow,
            )
            .unwrap();

            assert_eq!(raw.status, 200);
            assert_eq!(raw.body, payload);
        }
    }

    #[test]
    fn redirect_policy_can_follow_or_reject_redirects() {
        let app = axum::Router::new()
            .route(
                "/redirect",
                axum::routing::post(|| async {
                    (
                        axum::http::StatusCode::TEMPORARY_REDIRECT,
                        [(axum::http::header::LOCATION, "/destination")],
                        "",
                    )
                }),
            )
            .route(
                "/destination",
                axum::routing::post(|body: axum::body::Bytes| async move { body }),
            );
        let base_url = start_server(app);
        let body = RequestBody::text("same body");

        let followed = fetch_raw_with_body_for(
            ClientApp::Cli,
            "POST",
            &format!("{base_url}/redirect"),
            &[],
            Some(&body),
            RedirectPolicy::Follow,
        )
        .unwrap();
        assert_eq!(followed.status, 200);
        assert_eq!(followed.body, b"same body");

        let not_followed = fetch_raw_with_body_for(
            ClientApp::Cli,
            "POST",
            &format!("{base_url}/redirect"),
            &[],
            Some(&body),
            RedirectPolicy::None,
        )
        .unwrap();
        assert_eq!(not_followed.status, 307);

        let redirect_error = fetch_request_with_body_for(
            ClientApp::Cli,
            "POST",
            &format!("{base_url}/redirect"),
            &[],
            Some(&body),
            RedirectPolicy::None,
        )
        .unwrap_err();
        match redirect_error {
            Error::RequestValidation(message) => {
                assert!(message.contains("HTTP 307"));
                assert!(message.contains("`/destination`"));
                assert!(message.contains("final URL"));
            }
            other => panic!("Expected RequestValidation, got {other}"),
        }

        // Existing string-body APIs retain reqwest's normal redirect behavior.
        let existing = fetch_request(
            "POST",
            &format!("{base_url}/redirect"),
            &[],
            Some("existing body"),
        )
        .unwrap();
        match existing {
            RunOutcome::Completed { body, .. } => {
                assert_eq!(body.unwrap(), b"existing body");
            }
            _ => panic!("Expected Completed"),
        }
    }

    #[test]
    fn fetch_request_rejects_invalid_method() {
        let result = fetch_request("BAD METHOD", "https://example.com", &[], None);
        assert!(result.is_err());
    }

    #[test]
    fn fetch_invalid_url_errors() {
        let result = fetch("not-a-url", &[]);
        assert!(result.is_err());
    }

    #[test]
    fn fetch_connection_refused_errors() {
        let result = fetch("http://127.0.0.1:1/nope", &[]);
        assert!(result.is_err());
    }

    /// Regression for #350.4: binary responses must round-trip byte-for-byte
    /// — `text()` UTF-8 decoding silently mangles non-UTF-8 sequences (PNG
    /// header `0x89 0x50 0x4E 0x47` becomes `U+FFFD 0x50 0x4E 0x47`), which
    /// is an irreversible corruption.
    #[test]
    fn fetch_preserves_binary_bytes() {
        let payload: Vec<u8> = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0xFF, 0xFE, 0x00, 0x01,
        ];
        let payload_for_handler = payload.clone();
        let app = axum::Router::new().route(
            "/blob",
            axum::routing::get(move || {
                let bytes = payload_for_handler.clone();
                async move {
                    (
                        [(axum::http::header::CONTENT_TYPE, "application/octet-stream")],
                        bytes,
                    )
                }
            }),
        );
        let base_url = start_server(app);

        let raw = fetch_raw("GET", &format!("{base_url}/blob"), &[], None).unwrap();
        assert_eq!(raw.body, payload, "raw bytes must match exactly");
        assert_eq!(raw.mime_type(), "application/octet-stream");
    }

    #[test]
    fn fetch_completed_carries_content_type() {
        let app = axum::Router::new().route(
            "/img",
            axum::routing::get(|| async {
                (
                    [(axum::http::header::CONTENT_TYPE, "image/png")],
                    vec![0x89, b'P', b'N', b'G'],
                )
            }),
        );
        let base_url = start_server(app);

        let result = fetch(&format!("{base_url}/img"), &[]).unwrap();
        match result {
            RunOutcome::Completed {
                content_type, body, ..
            } => {
                assert_eq!(content_type.as_deref(), Some("image/png"));
                assert_eq!(body.unwrap(), vec![0x89, b'P', b'N', b'G']);
            }
            _ => panic!("Expected Completed"),
        }
    }

    #[test]
    fn fetch_completed_preserves_payment_response_header() {
        let app = axum::Router::new().route(
            "/paid",
            axum::routing::get(|| async {
                ([("payment-response", "encoded-settlement")], "delivered")
            }),
        );
        let base_url = start_server(app);

        let result = fetch(&format!("{base_url}/paid"), &[]).unwrap();
        match result {
            RunOutcome::Completed {
                response_headers, ..
            } => {
                assert!(response_headers.iter().any(|(name, value)| {
                    name.eq_ignore_ascii_case("payment-response") && value == "encoded-settlement"
                }));
            }
            _ => panic!("Expected Completed"),
        }
    }

    #[test]
    fn body_text_replaces_invalid_utf8() {
        let raw = RawResponse {
            status: 200,
            headers: vec![],
            body: vec![0xFF, 0xFE, b'h', b'i'],
        };
        let text = raw.body_text();
        assert!(text.contains("hi"));
        assert!(text.contains('\u{FFFD}'));
    }

    #[test]
    fn content_type_lookup_is_case_insensitive() {
        let raw = RawResponse {
            status: 200,
            headers: vec![("Content-Type".to_string(), "image/jpeg".to_string())],
            body: vec![],
        };
        assert_eq!(raw.content_type(), Some("image/jpeg"));
        assert_eq!(raw.mime_type(), "image/jpeg");
    }

    #[test]
    fn mime_type_strips_parameters() {
        let raw = RawResponse {
            status: 200,
            headers: vec![(
                "content-type".to_string(),
                "Text/Plain; charset=UTF-8".to_string(),
            )],
            body: vec![],
        };
        assert_eq!(raw.mime_type(), "text/plain");
    }

    #[test]
    fn mime_type_empty_when_header_missing() {
        let raw = RawResponse {
            status: 200,
            headers: vec![],
            body: vec![],
        };
        assert_eq!(raw.mime_type(), "");
    }
}
