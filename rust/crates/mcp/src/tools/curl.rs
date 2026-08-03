#![allow(deprecated)] // MCP roots remain required for local-file authorization.

use base64::{Engine, engine::general_purpose};
use pay_core::client::fetch::{RedirectPolicy, RequestBody};
use rmcp::model::{CallToolResult, ContentBlock, Resource, Root};
use rmcp::schemars;
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::path::PathBuf;
use std::time::SystemTime;

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Params {
    #[schemars(description = "The URL to fetch (e.g. https://api.example.com/data)")]
    pub url: String,
    #[schemars(description = "HTTP method. Defaults to GET.")]
    pub method: Option<String>,
    #[schemars(
        description = "Request headers as key-value pairs (e.g. {\"Authorization\": \"Bearer token\"})"
    )]
    pub headers: Option<std::collections::HashMap<String, String>>,
    #[schemars(
        description = "Request body for POST/PUT/PATCH. Pass either a string or a JSON value; JSON values are serialized before sending and validated locally against cached Pay catalog OpenAPI schemas when available."
    )]
    pub body: Option<BodyParam>,
    #[schemars(
        description = "Local file to use as the request body. The path must be within an MCP client-declared filesystem root. Pay snapshots the file and asks the user to approve its size, method, and destination before sending it. Cannot be combined with body."
    )]
    pub body_file: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum BodyParam {
    Text(String),
    Json(Value),
}

impl JsonSchema for BodyParam {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "BodyParam".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        // Schemars represents arbitrary JSON as the boolean schema `true`.
        // Some inference engines reject boolean tool schemas; `{}` has the
        // same accept-anything semantics and is broadly compatible.
        schemars::json_schema!({})
    }
}

impl BodyParam {
    fn into_string(self) -> Result<String, serde_json::Error> {
        match self {
            Self::Text(body) => Ok(body),
            Self::Json(value) => serde_json::to_string(&value),
        }
    }
}

/// Prepare request headers from params — auto-injects Accept and Content-Type.
pub fn prepare_headers(
    user_headers: &Option<std::collections::HashMap<String, String>>,
    has_body: bool,
) -> Vec<(String, String)> {
    let mut headers: Vec<(String, String)> = Vec::new();
    if let Some(h) = user_headers {
        for (k, v) in h {
            headers.push((k.clone(), v.clone()));
        }
    }
    if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("accept"))
    {
        headers.push(("Accept".to_string(), "application/json".to_string()));
    }
    if has_body
        && !headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("content-type"))
    {
        headers.push(("Content-Type".to_string(), "application/json".to_string()));
    }
    headers
}

fn prepare_headers_with_content_type(
    user_headers: &Option<std::collections::HashMap<String, String>>,
    default_content_type: Option<&str>,
) -> Vec<(String, String)> {
    let mut headers = prepare_headers(user_headers, false);
    if let Some(content_type) = default_content_type
        && !headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case("content-type"))
    {
        headers.push(("Content-Type".to_string(), content_type.to_string()));
    }
    headers
}

fn normalize_http_method(method: Option<&str>) -> Result<String, String> {
    let method = method.unwrap_or("GET");
    if method.is_empty() || !method.bytes().all(is_http_token_byte) {
        return Err(format!(
            "Invalid HTTP method `{method}`. Use an HTTP token such as GET, POST, PUT, PATCH, or DELETE."
        ));
    }
    Ok(method.to_ascii_uppercase())
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

pub async fn run(
    params: Params,
    peer: rmcp::Peer<rmcp::service::RoleServer>,
    payment_sessions: pay_core::session_manager::SessionManager,
) -> Result<CallToolResult, rmcp::ErrorData> {
    if params.body.is_some() && params.body_file.is_some() {
        return Ok(super::tool_error(
            "Pass either `body` or `body_file`, not both.",
        ));
    }

    let method = match normalize_http_method(params.method.as_deref()) {
        Ok(method) => method,
        Err(error) => return Ok(super::tool_error(error)),
    };
    let is_file_body = params.body_file.is_some();
    let body_and_content_type = match (params.body, params.body_file) {
        (Some(body), None) => match body.into_string() {
            Ok(body) => (
                Some(RequestBody::text(body)),
                Some("application/json".to_string()),
            ),
            Err(error) => {
                return Ok(super::tool_error(format!(
                    "Failed to serialize request body: {error}"
                )));
            }
        },
        (None, Some(path)) => match approved_body_file(&peer, &path, &method, &params.url).await {
            Ok(body) => (Some(body.body), Some(body.content_type)),
            Err(error) => return Ok(super::tool_error(error)),
        },
        (None, None) => (None, None),
        (Some(_), Some(_)) => unreachable!("body/body_file conflict returned above"),
    };
    let headers =
        prepare_headers_with_content_type(&params.headers, body_and_content_type.1.as_deref());
    let url = params.url;
    let body = body_and_content_type.0;
    let redirect_policy = if is_file_body {
        RedirectPolicy::None
    } else {
        RedirectPolicy::Follow
    };

    let response = crate::auth::spawn_blocking_with_elicitation(&peer, move |elicitation| {
        do_paid_fetch(
            &method,
            &url,
            &headers,
            body.as_ref(),
            redirect_policy,
            Some(elicitation),
            &payment_sessions,
        )
    })
    .await
    .map_err(|e| rmcp::ErrorData::internal_error(e.to_string(), None))?;

    match response {
        Ok((body, content_type)) => Ok(CallToolResult::success(body_to_mcp_content(
            body,
            content_type.as_deref(),
            "Request completed.",
        ))),
        Err(err) => Ok(pay_error_to_tool_result(err)),
    }
}

struct ApprovedBodyFile {
    body: RequestBody,
    content_type: String,
}

/// Resolve a local body file, obtain user approval, then snapshot the approved
/// file. A changed file is rejected rather than silently sent after approval.
async fn approved_body_file(
    peer: &rmcp::Peer<rmcp::service::RoleServer>,
    requested_path: &str,
    method: &str,
    url: &str,
) -> Result<ApprovedBodyFile, String> {
    let roots = peer
        .list_roots()
        .await
        .map_err(|error| format!("Could not obtain MCP filesystem roots: {error}"))?;
    let file = resolve_body_file_path(requested_path, &roots.roots)?;
    let destination = destination_label(url);
    let display_path = file.path.display().to_string();
    crate::auth::confirm_file_upload(peer, &display_path, file.bytes, method, &destination).await?;

    let path = file.path.clone();
    let expected = file.identity;
    let (body, content_type) =
        tokio::task::spawn_blocking(move || snapshot_approved_body_file(&path, expected))
            .await
            .map_err(|error| format!("Could not read approved request body file: {error}"))?
            .map_err(|error| error.to_string())?;
    Ok(ApprovedBodyFile { body, content_type })
}

#[derive(Debug)]
struct ResolvedBodyFile {
    path: PathBuf,
    bytes: u64,
    identity: BodyFileIdentity,
}

#[derive(Debug)]
struct BodyFileIdentity {
    bytes: u64,
    modified: SystemTime,
    handle: same_file::Handle,
}

fn resolve_body_file_path(
    requested_path: &str,
    roots: &[Root],
) -> Result<ResolvedBodyFile, String> {
    if requested_path.is_empty() {
        return Err("`body_file` must not be empty.".to_string());
    }
    if roots.is_empty() {
        return Err(
            "The MCP client did not provide any filesystem roots. Add the file's directory as an MCP root, then retry `body_file`."
                .to_string(),
        );
    }

    let root_paths = roots
        .iter()
        .map(mcp_root_path)
        .collect::<Result<Vec<_>, _>>()?;
    let requested = PathBuf::from(requested_path);
    let path = if requested.is_absolute() {
        requested
    } else if root_paths.len() == 1 && root_paths[0].is_dir() {
        root_paths[0].join(requested)
    } else {
        return Err(
            "A relative `body_file` needs exactly one directory MCP root. Use an absolute path inside a declared root when more than one root is available."
                .to_string(),
        );
    };

    let metadata = std::fs::symlink_metadata(&path).map_err(|error| {
        format!(
            "Could not inspect `body_file` `{}`: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "`body_file` `{}` must not be a symlink.",
            path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "`body_file` `{}` must be a regular file.",
            path.display()
        ));
    }
    if metadata.len() > pay_core::client::fetch::MAX_REQUEST_BODY_BYTES as u64 {
        return Err(format!(
            "`body_file` `{}` exceeds the 64 MiB limit.",
            path.display()
        ));
    }

    let canonical_file = std::fs::canonicalize(&path).map_err(|error| {
        format!(
            "Could not resolve `body_file` `{}`: {error}",
            path.display()
        )
    })?;
    let permitted = root_paths.iter().any(|root| {
        let root_metadata = std::fs::metadata(root).ok();
        root_metadata.is_some_and(|metadata| {
            if metadata.is_file() {
                canonical_file == *root
            } else {
                canonical_file.starts_with(root)
            }
        })
    });
    if !permitted {
        return Err(format!(
            "`body_file` `{}` is outside the MCP client's declared filesystem roots.",
            canonical_file.display()
        ));
    }

    let modified = metadata.modified().map_err(|error| {
        format!(
            "Could not read modification time for `body_file` `{}`: {error}",
            path.display()
        )
    })?;
    let handle = same_file::Handle::from_path(&canonical_file).map_err(|error| {
        format!(
            "Could not open `body_file` `{}` for approval: {error}",
            canonical_file.display()
        )
    })?;
    Ok(ResolvedBodyFile {
        path: canonical_file,
        bytes: metadata.len(),
        identity: BodyFileIdentity {
            bytes: metadata.len(),
            modified,
            handle,
        },
    })
}

fn snapshot_approved_body_file(
    path: &std::path::Path,
    expected: BodyFileIdentity,
) -> pay_core::Result<(RequestBody, String)> {
    let file = File::open(path).map_err(|error| {
        pay_core::Error::RequestValidation(format!(
            "Could not open approved `body_file` `{}`: {error}",
            path.display()
        ))
    })?;
    let handle = same_file::Handle::from_file(file.try_clone().map_err(|error| {
        pay_core::Error::RequestValidation(format!(
            "Could not verify approved `body_file` `{}`: {error}",
            path.display()
        ))
    })?)
    .map_err(|error| {
        pay_core::Error::RequestValidation(format!(
            "Could not verify approved `body_file` `{}`: {error}",
            path.display()
        ))
    })?;
    let metadata = file.metadata()?;
    let unchanged = handle == expected.handle
        && metadata.file_type().is_file()
        && metadata.len() == expected.bytes
        && metadata.modified().ok() == Some(expected.modified);
    if !unchanged {
        return Err(pay_core::Error::RequestValidation(
            "The local file changed after approval. Review and retry the request.".to_string(),
        ));
    }
    let mut bytes = Vec::with_capacity(expected.bytes as usize);
    file.take(pay_core::client::fetch::MAX_REQUEST_BODY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > pay_core::client::fetch::MAX_REQUEST_BODY_BYTES {
        return Err(pay_core::Error::RequestValidation(
            "The local file exceeds the 64 MiB upload limit.".to_string(),
        ));
    }
    let content_type = mime_guess::from_path(path)
        .first_raw()
        .unwrap_or("application/octet-stream")
        .to_string();
    Ok((RequestBody::bytes(bytes), content_type))
}

fn mcp_root_path(root: &Root) -> Result<PathBuf, String> {
    let uri = reqwest::Url::parse(&root.uri)
        .map_err(|error| format!("MCP root `{}` is not a valid URI: {error}", root.uri))?;
    if uri.scheme() != "file" {
        return Err(format!("MCP root `{}` is not a local file URI.", root.uri));
    }
    let path = uri
        .to_file_path()
        .map_err(|_| format!("MCP root `{}` is not a valid local file path.", root.uri))?;
    std::fs::canonicalize(&path)
        .map_err(|error| format!("Could not resolve MCP root `{}`: {error}", path.display()))
}

fn destination_label(url: &str) -> String {
    reqwest::Url::parse(url)
        .ok()
        .and_then(|parsed| {
            parsed.host_str().map(|host| match parsed.port() {
                Some(port) => format!("{}://{host}:{port}", parsed.scheme()),
                None => format!("{}://{host}", parsed.scheme()),
            })
        })
        .unwrap_or_else(|| url.to_string())
}

/// Route a response body to the right MCP content kind based on its MIME type.
///
/// - `image/*` → base64-encoded `Content::image` (so the LLM can see it)
/// - other binary (`application/pdf`, `application/octet-stream`, etc.) →
///   spilled to a tempfile, response carries the path as `Content::text`
///   (the JSON-RPC transport mangles raw bytes; tempfile keeps them intact)
/// - text-typed (`text/*`, `application/json`, `application/xml`) → handed to
///   [`text_body_to_content`], which extracts base64-embedded media (Gemini
///   `inlineData`, OpenAI `b64_json`, data: URLs) into files and caps the
///   inline size so a multi-megabyte JSON envelope never floods the context
/// - empty body → `Content::text(empty_message)`
fn body_to_mcp_content(
    body: Vec<u8>,
    content_type: Option<&str>,
    empty_message: &str,
) -> Vec<ContentBlock> {
    if body.is_empty() {
        return vec![ContentBlock::text(empty_message.to_string())];
    }

    let mime = mime_from_content_type(content_type);

    if mime.starts_with("image/") {
        let encoded = general_purpose::STANDARD.encode(&body);
        return vec![ContentBlock::image(encoded, mime)];
    }

    if is_binary_content_type(&mime) {
        return match write_body_to_tempfile(&body, &mime) {
            Ok(path) => {
                let note = ContentBlock::text(format!(
                    "Binary response ({} bytes, {mime}) written to {path}",
                    body.len()
                ));
                // Media types get a native resource link the client can open;
                // generic binary (zip, octet-stream, …) just gets the path.
                if mime.starts_with("audio/")
                    || mime.starts_with("video/")
                    || mime == "application/pdf"
                {
                    vec![note, resource_link_for_file(&path, &mime, body.len())]
                } else {
                    vec![note]
                }
            }
            Err(err) => vec![ContentBlock::text(format!(
                "Binary response ({} bytes, {mime}) — failed to spill to tempfile: {err}",
                body.len()
            ))],
        };
    }

    text_body_to_content(String::from_utf8_lossy(&body).into_owned())
}

fn mime_from_content_type(content_type: Option<&str>) -> String {
    content_type
        .and_then(|v| v.split(';').next())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "application/octet-stream".to_string())
}

/// True for MIME types whose payloads are not safe to embed as UTF-8 text.
/// Text-typed MIMEs (`text/*`, `application/json`, `application/xml`,
/// `application/*+json`, `application/*+xml`) return false.
fn is_binary_content_type(mime: &str) -> bool {
    if mime.starts_with("text/") {
        return false;
    }
    if mime == "application/json" || mime == "application/xml" {
        return false;
    }
    if mime.starts_with("application/") && (mime.ends_with("+json") || mime.ends_with("+xml")) {
        return false;
    }
    true
}

fn write_body_to_tempfile(body: &[u8], mime: &str) -> std::io::Result<String> {
    use std::io::Write;
    let extension = extension_for_mime(mime);
    let mut path = std::env::temp_dir();
    let name = format!(
        "pay-curl-{}{extension}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    path.push(name);
    let mut file = std::fs::File::create(&path)?;
    file.write_all(body)?;
    Ok(path.to_string_lossy().into_owned())
}

/// Pick a sensible filename extension for a MIME type using `mime_guess`'s
/// MIME→ext map. The extension is purely a hint for the human reading the
/// tempfile path — readers should always trust `Content-Type`, not the
/// suffix.
fn extension_for_mime(mime: &str) -> String {
    let parsed: Option<mime_guess::Mime> = mime.parse().ok();
    parsed
        .as_ref()
        .and_then(|m| mime_guess::get_mime_extensions(m))
        .and_then(|exts| exts.first())
        .map(|ext| format!(".{ext}"))
        .unwrap_or_else(|| ".bin".to_string())
}

/// Largest text/JSON body we embed inline before spilling it to a tempfile.
/// Above this the context-window cost outweighs the convenience.
const MAX_TEXT_INLINE_BYTES: usize = 256 * 1024;
/// How much of an over-cap text body to keep inline as a preview.
const TEXT_PREVIEW_BYTES: usize = 4 * 1024;
/// Minimum *decoded* size for a base64 string embedded in JSON to be worth
/// extracting to a file. Smaller blobs (icons, thumbnails) stay inline.
const MIN_BASE64_EXTRACT_BYTES: usize = 8 * 1024;

/// Media decoded out of a JSON envelope and written to disk.
struct ExtractedMedia {
    mime: String,
    path: String,
    /// Standard-base64 re-encoding of the decoded bytes, for `Content::image`.
    encoded: String,
    bytes: usize,
}

/// Turn a text-typed response into MCP content.
///
/// If the body is JSON, base64-embedded media (Gemini `inlineData.data`,
/// OpenAI `b64_json`, data: URLs, or any large base64 string that sniffs as a
/// known media type) is decoded, written to a tempfile, and replaced in the
/// JSON with a `<mime, N bytes → /path>` placeholder. Images are additionally
/// surfaced as `Content::image` so the model can see them. Whatever text
/// remains is size-capped by [`text_content_capped`].
fn text_body_to_content(text: String) -> Vec<ContentBlock> {
    if let Ok(mut value) = serde_json::from_str::<Value>(&text) {
        let mut extracted = Vec::new();
        extract_media_from_json(&mut value, &mut extracted);
        if !extracted.is_empty() {
            let slimmed = serde_json::to_string(&value).unwrap_or(text);
            let mut content = vec![text_content_capped(slimmed)];
            for media in &extracted {
                if let Some(block) = media_as_content_block(media) {
                    content.push(block);
                }
            }
            return content;
        }
    }
    vec![text_content_capped(text)]
}

/// Surface extracted media as a native MCP content block.
///
/// - `image/*` → `Content::image` (base64 inline, so the model can see it)
/// - `audio/*`, `video/*`, `application/pdf` → `Content::resource_link`
///   pointing at the file on disk. A resource link is the native MCP primitive
///   for handing a client a file by reference — clients that support these
///   types can open/play them, and we avoid inlining multi-megabyte base64
///   that would flood the context.
fn media_as_content_block(media: &ExtractedMedia) -> Option<ContentBlock> {
    if media.mime.starts_with("image/") {
        return Some(ContentBlock::image(
            media.encoded.clone(),
            media.mime.clone(),
        ));
    }
    if media.mime.starts_with("audio/")
        || media.mime.starts_with("video/")
        || media.mime == "application/pdf"
    {
        return Some(resource_link_for_file(
            &media.path,
            &media.mime,
            media.bytes,
        ));
    }
    None
}

/// Build a `resource_link` content block referencing a media file on disk.
fn resource_link_for_file(path: &str, mime: &str, bytes: usize) -> ContentBlock {
    let name = path
        .rsplit(['/', '\\'])
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or(path)
        .to_string();
    let resource = Resource::new(format!("file://{path}"), name)
        .with_mime_type(mime)
        .with_size(bytes as u64);
    ContentBlock::resource_link(resource)
}

/// Return the text as inline `Content::text`, or — when it exceeds
/// [`MAX_TEXT_INLINE_BYTES`] — spill the full body to a tempfile and return a
/// short preview plus the path, so a huge response can't flood the context.
fn text_content_capped(text: String) -> ContentBlock {
    if text.len() <= MAX_TEXT_INLINE_BYTES {
        return ContentBlock::text(text);
    }
    let preview: String = text.chars().take(TEXT_PREVIEW_BYTES).collect();
    match write_body_to_tempfile(text.as_bytes(), "text/plain") {
        Ok(path) => ContentBlock::text(format!(
            "Large text response ({} bytes) written to {path}. First {} chars:\n{preview}",
            text.len(),
            preview.len()
        )),
        Err(err) => ContentBlock::text(format!(
            "Large text response ({} bytes) — failed to spill to tempfile: {err}. First {} chars:\n{preview}",
            text.len(),
            preview.len()
        )),
    }
}

/// Recursively walk a JSON value, extracting large base64 media strings to
/// files and replacing each with a `<mime, N bytes → /path>` placeholder.
fn extract_media_from_json(value: &mut Value, out: &mut Vec<ExtractedMedia>) {
    match value {
        Value::Object(map) => {
            let sibling_mime = mime_hint_from_object(map);
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let Some(slot) = map.get_mut(&key) else {
                    continue;
                };
                if let Value::String(s) = slot
                    && let Some(media) =
                        try_extract_base64_media(s.as_str(), sibling_mime.as_deref())
                {
                    *slot = Value::String(format!(
                        "<{}, {} bytes → {}>",
                        media.mime, media.bytes, media.path
                    ));
                    out.push(media);
                    continue;
                }
                extract_media_from_json(slot, out);
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                extract_media_from_json(item, out);
            }
        }
        _ => {}
    }
}

/// Find a MIME-type hint among an object's own keys (e.g. Gemini's
/// `inlineData` carries a sibling `mimeType` next to `data`).
fn mime_hint_from_object(map: &serde_json::Map<String, Value>) -> Option<String> {
    for key in [
        "mimeType",
        "mime_type",
        "contentType",
        "content_type",
        "mime",
    ] {
        if let Some(Value::String(s)) = map.get(key) {
            let s = s.trim();
            if !s.is_empty() {
                return Some(s.to_ascii_lowercase());
            }
        }
    }
    None
}

/// Try to interpret a JSON string as base64-encoded media worth spilling to a
/// file. Returns `None` for ordinary strings — only large blobs that decode as
/// base64 *and* are identifiable as media (by magic bytes, a data: URL prefix,
/// or a sibling MIME hint) are extracted.
fn try_extract_base64_media(s: &str, hint: Option<&str>) -> Option<ExtractedMedia> {
    // Cheap length gate: decoded ≈ 3/4 of encoded, so a sub-threshold string
    // can't possibly yield enough bytes. Avoids decoding every short field.
    if s.len() < MIN_BASE64_EXTRACT_BYTES {
        return None;
    }

    let (data_url_mime, payload) = match strip_data_url(s) {
        Some((mime, payload)) => (Some(mime), payload),
        None => (None, s),
    };

    let decoded = decode_base64_relaxed(payload)?;
    if decoded.len() < MIN_BASE64_EXTRACT_BYTES {
        return None;
    }

    let sniffed = sniff_media_mime(&decoded);
    let hint_is_media = hint.map(mime_is_media).unwrap_or(false);
    // Require positive media evidence — never extract opaque base64 (tokens,
    // signatures, arbitrary blobs) that merely happens to be large.
    if data_url_mime.is_none() && sniffed.is_none() && !hint_is_media {
        return None;
    }

    // Prefer bytes-derived MIME (magic) over a data: URL label over a sibling
    // hint — the bytes don't lie.
    let mime = sniffed
        .map(str::to_string)
        .or(data_url_mime)
        .or_else(|| hint.map(str::to_string))
        .unwrap_or_else(|| "application/octet-stream".to_string());

    let path = write_body_to_tempfile(&decoded, &mime).ok()?;
    Some(ExtractedMedia {
        encoded: general_purpose::STANDARD.encode(&decoded),
        bytes: decoded.len(),
        mime,
        path,
    })
}

/// Split a `data:<mime>;base64,<payload>` URL into its MIME type and payload.
fn strip_data_url(s: &str) -> Option<(String, &str)> {
    let rest = s.strip_prefix("data:")?;
    let (meta, payload) = rest.split_once(',')?;
    let meta = meta.strip_suffix(";base64")?;
    let mime = meta
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    if mime.is_empty() {
        return None;
    }
    Some((mime, payload))
}

/// Decode base64 tolerantly across the common variants APIs emit (standard,
/// unpadded, URL-safe).
fn decode_base64_relaxed(s: &str) -> Option<Vec<u8>> {
    general_purpose::STANDARD
        .decode(s)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(s))
        .or_else(|_| general_purpose::URL_SAFE.decode(s))
        .or_else(|_| general_purpose::URL_SAFE_NO_PAD.decode(s))
        .ok()
}

/// True for MIME types that name real media we'd want materialized as a file.
fn mime_is_media(mime: &str) -> bool {
    let mime = mime.trim();
    mime.starts_with("image/")
        || mime.starts_with("audio/")
        || mime.starts_with("video/")
        || mime == "application/pdf"
}

/// Identify common media formats by their leading magic bytes. Returns a
/// canonical MIME type, or `None` when the bytes aren't a recognized format.
fn sniff_media_mime(bytes: &[u8]) -> Option<&'static str> {
    const PNG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
    if bytes.starts_with(PNG) {
        return Some("image/png");
    }
    if bytes.starts_with(&[0xFF, 0xD8, 0xFF]) {
        return Some("image/jpeg");
    }
    if bytes.starts_with(b"GIF87a") || bytes.starts_with(b"GIF89a") {
        return Some("image/gif");
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WAVE" {
        return Some("audio/wav");
    }
    if bytes.starts_with(b"OggS") {
        return Some("audio/ogg");
    }
    if bytes.starts_with(b"fLaC") {
        return Some("audio/flac");
    }
    if bytes.starts_with(b"%PDF") {
        return Some("application/pdf");
    }
    // MP3: ID3 tag or an MPEG audio frame sync (11 set bits).
    if bytes.starts_with(b"ID3")
        || (bytes.len() >= 2 && bytes[0] == 0xFF && (bytes[1] & 0xE0) == 0xE0)
    {
        return Some("audio/mpeg");
    }
    // ISO base media (MP4/M4V/MOV): `....ftyp` box at offset 4.
    if bytes.len() >= 12 && &bytes[4..8] == b"ftyp" {
        return Some("video/mp4");
    }
    None
}

/// Result of a paid fetch: raw response body bytes and the content-type the
/// server advertised. Bytes (not String) so binary payloads — images, PDFs,
/// octet streams — round-trip without UTF-8 mangling.
type PaidFetchResult = (Vec<u8>, Option<String>);

type SessionOpener =
    fn(
        &pay_core::mpp::Challenge,
        &dyn pay_core::accounts::AccountsStore,
        Option<&str>,
        Option<&str>,
        &str,
        bool,
        pay_core::signer::AuthOverride,
    ) -> Result<pay_core::session_manager::PreparedOperatorSession, pay_core::Error>;

#[allow(clippy::too_many_arguments)]
fn chosen_payment_headers(
    chosen: pay_core::client::mpp::ChosenPayment,
    store: &dyn pay_core::accounts::AccountsStore,
    network_override: Option<&str>,
    account_override: Option<&str>,
    resource_url: &str,
    extra_headers: &[(String, String)],
    auth_override: pay_core::signer::AuthOverride,
) -> Result<Vec<(String, String)>, pay_core::Error> {
    use pay_core::client::mpp::ChosenPayment;

    let mut headers = extra_headers.to_vec();
    match chosen {
        ChosenPayment::Mpp(challenge) => {
            let (authorization, _ephemeral) =
                pay_core::client::mpp::build_credential_with_override(
                    challenge.as_ref(),
                    store,
                    network_override,
                    account_override,
                    Some(resource_url),
                    auth_override,
                )?;
            headers.push(("Authorization".to_string(), authorization));
        }
        ChosenPayment::X402(challenge) => {
            let built = pay_core::client::x402::build_payment_with_override(
                challenge.as_ref(),
                store,
                network_override,
                account_override,
                Some(resource_url),
                auth_override,
            )?;
            headers.extend(
                built
                    .headers
                    .into_iter()
                    .map(|(name, value)| (name.to_string(), value)),
            );
        }
        ChosenPayment::X402Upto(challenge) => {
            let built = pay_core::client::x402::build_upto_payment_with_override(
                challenge.as_ref(),
                store,
                network_override,
                account_override,
                Some(resource_url),
                auth_override,
            )?;
            headers.extend(
                built
                    .headers
                    .into_iter()
                    .map(|(name, value)| (name.to_string(), value)),
            );
        }
    }
    Ok(headers)
}

fn do_paid_fetch(
    method: &str,
    url: &str,
    extra_headers: &[(String, String)],
    body: Option<&RequestBody>,
    redirect_policy: RedirectPolicy,
    elicitation: Option<tokio::sync::mpsc::UnboundedSender<crate::auth::BrokerRequest>>,
    payment_sessions: &pay_core::session_manager::SessionManager,
) -> Result<PaidFetchResult, pay_core::Error> {
    do_paid_fetch_with_session_opener(
        method,
        url,
        extra_headers,
        body,
        redirect_policy,
        elicitation,
        payment_sessions,
        pay_core::session_manager::prepare_operator_session_with_override,
    )
}

#[allow(clippy::too_many_arguments)]
fn do_paid_fetch_with_session_opener(
    method: &str,
    url: &str,
    extra_headers: &[(String, String)],
    body: Option<&RequestBody>,
    redirect_policy: RedirectPolicy,
    elicitation: Option<tokio::sync::mpsc::UnboundedSender<crate::auth::BrokerRequest>>,
    payment_sessions: &pay_core::session_manager::SessionManager,
    session_opener: SessionOpener,
) -> Result<PaidFetchResult, pay_core::Error> {
    use pay_core::client::runner::RunOutcome;

    validate_cached_catalog_body(method, url, extra_headers, body)?;

    let fetch_request = |headers: &[(String, String)]| {
        pay_core::client::fetch::fetch_request_with_body_for(
            pay_core::ClientApp::Mcp,
            method,
            url,
            headers,
            body,
            redirect_policy,
        )
    };

    // Build a fresh elicitation-backed AuthGate per signing operation when
    // we have a request broker AND no local biometric is available. A local Touch ID /
    // Windows Hello / polkit prompt is faster and more familiar than a
    // round-trip through the MCP client UI, so we prefer it whenever the
    // platform offers it. `PAY_FORCE_ELICITATION=1` opts back into the
    // elicitation path for users who want approvals in the MCP client
    // anyway (remote MCP, screen-sharing demos, etc.).
    //
    // When None (e.g. unit tests, or biometrics-available path), each
    // `_with_override` call gets `None` and falls back to the platform
    // default gate. The broker keeps server-to-client requests associated
    // with the originating tools/call under MCP 2026-07-28 (SEP-2260).
    let make_auth_override = || -> pay_core::signer::AuthOverride {
        let elicitation = elicitation.as_ref()?;
        let force = std::env::var("PAY_FORCE_ELICITATION")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !force && pay_keystore::Keystore::any_biometric_available() {
            return None;
        }
        Some(
            Box::new(crate::ElicitationAuth::via_broker(elicitation.clone()))
                as Box<dyn pay_keystore::AuthGate>,
        )
    };

    let store = pay_core::accounts::FileAccountsStore::default_path();
    let network_override = std::env::var("PAY_NETWORK_ENFORCED").ok();
    let account_override = std::env::var("PAY_ACTIVE_ACCOUNT").ok();
    let session_slot = payment_sessions.slot(
        url,
        network_override.as_deref(),
        account_override.as_deref(),
    )?;
    let mut session = session_slot.blocking_acquire();

    // Pre-attach a cached subscription token or reusable operator-session
    // proof before challenge discovery. Explicit caller authorization wins;
    // subscriptions win over sessions because both occupy Authorization.
    let cached_auth_header =
        pay_core::client::authenticate::cached_header_for_resource(&store, url);
    let has_explicit_authorization = extra_headers
        .iter()
        .any(|(name, _)| name.eq_ignore_ascii_case("authorization"));
    let mut initial_headers = extra_headers.to_vec();
    let mut used_cached_session = false;
    if !has_explicit_authorization {
        if let Some(token) = cached_auth_header {
            initial_headers.push(("Authorization".to_string(), token));
        } else if let Some(authorization) = session.authorization() {
            initial_headers.push(("Authorization".to_string(), authorization.to_string()));
            used_cached_session = true;
        }
    }

    let mut outcome = fetch_request(&initial_headers)?;
    if used_cached_session {
        outcome = match outcome {
            completed @ RunOutcome::Completed { .. } => return interpret_retry(completed),
            RunOutcome::PaymentRejected {
                retryable: true, ..
            } => {
                let retried = fetch_request(&initial_headers)?;
                match retried {
                    completed @ RunOutcome::Completed { .. } => return interpret_retry(completed),
                    rejected @ RunOutcome::PaymentRejected {
                        retryable: true, ..
                    } => return interpret_retry(rejected),
                    RunOutcome::PaymentRejected {
                        retryable: false, ..
                    } => {
                        session.clear();
                        fetch_request(extra_headers)?
                    }
                    challenge @ RunOutcome::SessionChallenge { .. } => {
                        session.clear();
                        challenge
                    }
                    other => other,
                }
            }
            RunOutcome::PaymentRejected {
                retryable: false, ..
            } => {
                session.clear();
                fetch_request(extra_headers)?
            }
            challenge @ RunOutcome::SessionChallenge { .. } => {
                session.clear();
                challenge
            }
            other => other,
        };
    }

    match outcome {
        RunOutcome::MppChallenge {
            challenge,
            alternatives,
            x402_alternative,
            x402_upto_accepts,
            ..
        } => {
            let mut challenges = Vec::with_capacity(1 + alternatives.len());
            challenges.push((*challenge).clone());
            challenges.extend(alternatives);
            // Balance- and cost-aware, cross-scheme pick: settle the cheapest
            // option the wallet can fund across MPP charge, x402 exact, and
            // every advertised x402 upto currency.
            let chosen = pay_core::client::mpp::choose_payment(
                &challenges,
                x402_alternative.as_deref(),
                &x402_upto_accepts,
                &store,
                network_override.as_deref(),
                account_override.as_deref(),
            )?;
            let headers = chosen_payment_headers(
                chosen,
                &store,
                network_override.as_deref(),
                account_override.as_deref(),
                url,
                extra_headers,
                make_auth_override(),
            )?;
            interpret_retry(fetch_request(&headers)?)
        }
        RunOutcome::X402Challenge { challenge, .. } => {
            let built_payment = pay_core::client::x402::build_payment_with_override(
                &challenge,
                &store,
                network_override.as_deref(),
                account_override.as_deref(),
                Some(url),
                make_auth_override(),
            )?;
            let mut headers = extra_headers.to_vec();
            headers.extend(
                built_payment
                    .headers
                    .into_iter()
                    .map(|(name, value)| (name.to_string(), value)),
            );
            interpret_retry(fetch_request(&headers)?)
        }
        RunOutcome::X402UptoChallenge { challenge, .. } => {
            let built_payment = pay_core::client::x402::build_upto_payment_with_override(
                &challenge,
                &store,
                network_override.as_deref(),
                account_override.as_deref(),
                Some(url),
                make_auth_override(),
            )?;
            let mut headers = extra_headers.to_vec();
            headers.extend(
                built_payment
                    .headers
                    .into_iter()
                    .map(|(name, value)| (name.to_string(), value)),
            );
            interpret_retry(fetch_request(&headers)?)
        }
        RunOutcome::X402SignInChallenge {
            challenge,
            payment_fallback,
            ..
        } => {
            // Prefer spending existing credits: sign in with the wallet and
            // retry. The sign-in signature takes one Touch ID / approval; if
            // sign-in doesn't grant access and we fall back to paying below,
            // the payment signature requires a second approval.
            let built = pay_core::client::x402::build_siwx_auth_header_with_override(
                &challenge,
                &store,
                network_override.as_deref(),
                account_override.as_deref(),
                Some(url),
                make_auth_override(),
            )?;
            let mut headers = extra_headers.to_vec();
            headers.extend(
                built
                    .headers
                    .into_iter()
                    .map(|(name, value)| (name.to_string(), value)),
            );
            let retry = fetch_request(&headers)?;

            // If sign-in granted access, we're done — credits were spent, no
            // payment made. If the server still refuses (e.g. the wallet has
            // no credits yet) and the same 402 also offered a payment option,
            // fall back to paying so the call can still go through.
            if matches!(retry, RunOutcome::Completed { .. }) {
                interpret_retry(retry)
            } else if let Some(pay_challenge) = payment_fallback {
                let built_payment = pay_core::client::x402::build_payment_with_override(
                    &pay_challenge,
                    &store,
                    network_override.as_deref(),
                    account_override.as_deref(),
                    Some(url),
                    make_auth_override(),
                )?;
                let mut headers = extra_headers.to_vec();
                headers.extend(
                    built_payment
                        .headers
                        .into_iter()
                        .map(|(name, value)| (name.to_string(), value)),
                );
                interpret_retry(fetch_request(&headers)?)
            } else if let RunOutcome::PaymentRejected { reason, .. } = retry {
                Err(pay_core::Error::PaymentRejected(reason))
            } else {
                // Sign-in didn't grant access and the 402 offered no payment
                // option to fall back to — typically the wallet has no credits
                // yet. Don't claim a payment was made/rejected here.
                Err(pay_core::Error::Mpp(
                    "Server returned 402 again after sign-in — the wallet has no usable credits \
                     and the endpoint offered no payment option"
                        .to_string(),
                ))
            }
        }
        RunOutcome::SessionChallenge {
            challenge,
            x402_alternative,
            x402_upto_accepts,
            ..
        } => {
            if !pay_core::session_manager::is_operator_session(&challenge)
                && (x402_alternative.is_some() || !x402_upto_accepts.is_empty())
            {
                let chosen = pay_core::client::mpp::choose_payment(
                    &[],
                    x402_alternative.as_deref(),
                    &x402_upto_accepts,
                    &store,
                    network_override.as_deref(),
                    account_override.as_deref(),
                )?;
                let headers = chosen_payment_headers(
                    chosen,
                    &store,
                    network_override.as_deref(),
                    account_override.as_deref(),
                    url,
                    extra_headers,
                    make_auth_override(),
                )?;
                return interpret_retry(fetch_request(&headers)?);
            }

            let prepared = session_opener(
                &challenge,
                &store,
                network_override.as_deref(),
                account_override.as_deref(),
                url,
                network_override.as_deref() == Some("localnet"),
                make_auth_override(),
            )?;
            let mut headers = extra_headers.to_vec();
            headers.push(("Authorization".to_string(), prepared.open_authorization));
            let retry = fetch_request(&headers)?;
            if matches!(retry, RunOutcome::Completed { .. }) {
                session.adopt(prepared.use_authorization);
            } else {
                session.clear();
            }
            interpret_retry(retry)
        }
        RunOutcome::SubscriptionChallenge {
            challenge,
            authenticate,
            ..
        } => {
            // Build + send the activation credential, same flow as
            // `pay http`. Touch ID (or whatever keystore the active
            // account uses) gates the signature, so an agent invocation
            // can't silently commit a recurring on-chain delegation —
            // the user still has to approve in the system prompt. On
            // success we persist a local record to accounts.yml via
            // pay-core's shared helper so the MCP path stays in sync
            // with `pay subscriptions list`. When the server bundled an
            // `authenticate` challenge in the 402, we sign it with the
            // same unlocked signer and cache the resulting token so
            // subsequent requests in the period skip the prompt.
            let built =
                pay_core::client::subscription::build_credential_with_authenticate_and_override(
                    &challenge,
                    authenticate.as_deref(),
                    &store,
                    network_override.as_deref(),
                    account_override.as_deref(),
                    Some(url),
                    make_auth_override(),
                )?;
            let mut headers = extra_headers.to_vec();
            headers.push(("Authorization".to_string(), built.authorization.clone()));
            let retry = fetch_request(&headers)?;
            if let RunOutcome::Completed { exit_code, .. } = &retry
                && *exit_code == 0
                && let Err(e) =
                    pay_core::client::subscription::persist_local_subscription_after_activation(
                        &built, &store,
                    )
            {
                tracing::warn!(
                    error = %e,
                    "Subscription activation succeeded but local persistence failed"
                );
            }
            interpret_retry(retry)
        }
        RunOutcome::PaymentRejected { reason, .. } => Err(pay_core::Error::PaymentRejected(reason)),
        RunOutcome::UnknownPaymentRequired { .. } => Err(pay_core::Error::Mpp(
            "402 Payment Required but no recognized protocol".to_string(),
        )),
        RunOutcome::Completed {
            body, content_type, ..
        } => Ok((body.unwrap_or_default(), content_type)),
    }
}

/// Run cached catalog validation for every request.
///
/// Non-JSON bodies keep method, path, query, and media-type validation while
/// intentionally skipping JSON-schema validation.
fn validate_cached_catalog_body(
    method: &str,
    url: &str,
    headers: &[(String, String)],
    body: Option<&RequestBody>,
) -> Result<(), pay_core::Error> {
    let Some(body) = body else {
        return pay_core::skills::validate_cached_catalog_request(method, url, None);
    };

    let content_type = headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .map(|(_, value)| value.as_str());
    if !content_type.is_some_and(is_json_media_type) {
        return pay_core::skills::validate_cached_catalog_opaque_request(
            method,
            url,
            content_type.unwrap_or("application/octet-stream"),
        );
    }

    let text = body.as_text().ok_or_else(|| {
        pay_core::Error::RequestValidation(
            "A request declared as JSON contains non-UTF-8 bytes. Stage valid UTF-8 JSON or use the payload's actual content type."
                .to_string(),
        )
    })?;
    pay_core::skills::validate_cached_catalog_request(method, url, Some(text))
}

fn is_json_media_type(value: &str) -> bool {
    let media_type = value
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}

fn pay_error_to_tool_result(err: pay_core::Error) -> CallToolResult {
    let message = match err {
        pay_core::Error::RequestValidation(message) => message,
        pay_core::Error::PaymentRejected(reason) if is_user_rejection(&reason) => {
            format!(
                "User declined the OS authentication prompt for this paid request: {reason}. \
                 The HTTP request was NOT sent and no funds moved. Ask the user for \
                 clarification before retrying — they may have intended to decline (in which \
                 case clarify what to do instead), or they may want to retry and approve at \
                 the prompt."
            )
        }
        other => format!("Pay curl failed: {other}"),
    };
    super::tool_error(message)
}

/// True when a `PaymentRejected` reason came from the user denying their OS
/// auth prompt (Apple Keychain, Windows Hello, GNOME Keyring, 1Password, or
/// the generic fallback) — not from a server-side `verification_failed` body.
/// See `signer::rejection_source` for the matching producer.
fn is_user_rejection(reason: &str) -> bool {
    reason.starts_with("rejected by user")
}

fn interpret_retry(
    outcome: pay_core::client::runner::RunOutcome,
) -> Result<PaidFetchResult, pay_core::Error> {
    use pay_core::client::runner::RunOutcome;
    match outcome {
        RunOutcome::Completed {
            body, content_type, ..
        } => Ok((body.unwrap_or_default(), content_type)),
        RunOutcome::PaymentRejected { reason, .. } => Err(pay_core::Error::PaymentRejected(reason)),
        _ => Err(pay_core::Error::Mpp(
            "Server returned 402 again after payment".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static SESSION_OPEN_CALLS: AtomicUsize = AtomicUsize::new(0);

    fn fake_session_opener(
        _challenge: &pay_core::mpp::Challenge,
        _store: &dyn pay_core::accounts::AccountsStore,
        _network_override: Option<&str>,
        _account_override: Option<&str>,
        _resource_url: &str,
        _sandbox: bool,
        _auth_override: pay_core::signer::AuthOverride,
    ) -> Result<pay_core::session_manager::PreparedOperatorSession, pay_core::Error> {
        SESSION_OPEN_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(pay_core::session_manager::PreparedOperatorSession {
            open_authorization: "Payment open-test".to_string(),
            use_authorization: "Payment use-test".to_string(),
        })
    }

    fn read_request(stream: &mut std::net::TcpStream) -> String {
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let count = stream.read(&mut chunk).unwrap();
            if count == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..count]);
            if bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        String::from_utf8(bytes).unwrap()
    }

    fn session_challenge_header() -> String {
        let request = serde_json::json!({
            "amount": "1",
            "currency": "USDC",
            "recipient": "So11111111111111111111111111111111111111112",
            "methodDetails": {
                "network": "solana:mainnet",
                "channelProgram": "So11111111111111111111111111111111111111112",
                "voucherSigner": "operator",
                "operator": "So11111111111111111111111111111111111111112"
            }
        });
        let encoded =
            general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&request).unwrap());
        format!(
            "Payment id=\"session-test\", realm=\"test\", method=\"solana\", intent=\"session\", request=\"{encoded}\""
        )
    }

    #[test]
    fn params_deserialize_minimal() {
        let json = r#"{"url": "https://example.com"}"#;
        let params: Params = serde_json::from_str(json).unwrap();
        assert_eq!(params.url, "https://example.com");
        assert!(params.method.is_none());
        assert!(params.headers.is_none());
        assert!(params.body.is_none());
        assert!(params.body_file.is_none());
    }

    #[test]
    fn params_deserialize_full() {
        let json = r#"{
            "url": "https://example.com",
            "method": "POST",
            "headers": {"Authorization": "Bearer tok"},
            "body": "{\"q\":1}"
        }"#;
        let params: Params = serde_json::from_str(json).unwrap();
        assert_eq!(params.method.unwrap(), "POST");
        assert_eq!(params.headers.as_ref().unwrap().len(), 1);
        assert!(params.body.is_some());
    }

    #[test]
    fn params_deserialize_json_object_body() {
        let json = r#"{
            "url": "https://example.com",
            "method": "POST",
            "body": {"q": 1, "limit": 2}
        }"#;
        let params: Params = serde_json::from_str(json).unwrap();
        let body = params.body.unwrap().into_string().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&body).unwrap(),
            serde_json::json!({"q": 1, "limit": 2})
        );
    }

    #[test]
    fn params_deserialize_json_array_body() {
        let json = r#"{
            "url": "https://example.com",
            "method": "POST",
            "body": ["a", "b"]
        }"#;
        let params: Params = serde_json::from_str(json).unwrap();
        let body = params.body.unwrap().into_string().unwrap();
        assert_eq!(body, r#"["a","b"]"#);
    }

    #[test]
    fn method_normalization_matches_wire_method() {
        assert_eq!(normalize_http_method(Some("post")).unwrap(), "POST");
        assert_eq!(normalize_http_method(None).unwrap(), "GET");
        assert!(normalize_http_method(Some("BAD METHOD")).is_err());
    }

    #[test]
    fn body_file_is_advertised_and_deserializes() {
        let params = serde_json::from_str::<Params>(
            r#"{"url":"https://example.com","body_file":"/workspace/photo.png"}"#,
        )
        .unwrap();
        assert_eq!(params.body_file.as_deref(), Some("/workspace/photo.png"));

        let schema = serde_json::to_value(rmcp::schemars::schema_for!(Params)).unwrap();
        assert!(schema.pointer("/properties/body_file").is_some());
        assert!(schema.pointer("/properties/body").is_some());
    }

    #[test]
    fn arbitrary_json_body_schema_uses_compatible_object_form() {
        let mut generator = schemars::SchemaGenerator::default();
        let body_schema = serde_json::to_value(BodyParam::json_schema(&mut generator)).unwrap();
        assert_eq!(body_schema, serde_json::json!({}));

        let schema = serde_json::to_value(rmcp::schemars::schema_for!(Params)).unwrap();
        assert!(
            schema
                .pointer("/properties/body")
                .is_some_and(Value::is_object)
        );
        assert!(schema.pointer("/$defs/BodyParam").is_none());
    }

    #[test]
    fn resolves_relative_file_inside_the_single_declared_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("photo.png");
        std::fs::write(&path, b"image bytes").unwrap();
        let root = Root::new(
            reqwest::Url::from_directory_path(dir.path())
                .unwrap()
                .to_string(),
        )
        .with_name("workspace");

        let file = resolve_body_file_path("photo.png", &[root]).unwrap();
        assert_eq!(file.path, std::fs::canonicalize(path).unwrap());
        assert_eq!(file.bytes, 11);
    }

    #[test]
    fn changed_body_file_is_rejected_after_approval() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("payload.json");
        std::fs::write(&path, br#"{"approved":true}"#).unwrap();
        let root = Root::new(
            reqwest::Url::from_directory_path(dir.path())
                .unwrap()
                .to_string(),
        )
        .with_name("workspace");

        let file = resolve_body_file_path("payload.json", &[root]).unwrap();
        std::fs::write(&path, b"changed").unwrap();

        assert!(snapshot_approved_body_file(&file.path, file.identity).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn swapped_root_cannot_redirect_an_approved_file() {
        use std::os::unix::fs::symlink;

        let outer = tempfile::tempdir().unwrap();
        let root_path = outer.path().join("root");
        let moved_root = outer.path().join("moved-root");
        let outside = outer.path().join("outside");
        std::fs::create_dir(&root_path).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(root_path.join("payload"), b"approved").unwrap();
        std::fs::write(outside.join("payload"), b"outside!").unwrap();
        let root = Root::new(
            reqwest::Url::from_directory_path(&root_path)
                .unwrap()
                .to_string(),
        )
        .with_name("workspace");

        let file = resolve_body_file_path("payload", &[root]).unwrap();
        std::fs::rename(&root_path, &moved_root).unwrap();
        symlink(&outside, &root_path).unwrap();

        assert!(snapshot_approved_body_file(&file.path, file.identity).is_err());
    }

    #[test]
    fn rejects_file_outside_declared_roots() {
        let allowed = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        let root = Root::new(
            reqwest::Url::from_directory_path(allowed.path())
                .unwrap()
                .to_string(),
        );

        let error = resolve_body_file_path(outside.path().to_str().unwrap(), &[root]).unwrap_err();
        assert!(error.contains("outside the MCP client's declared filesystem roots"));
    }

    #[test]
    fn relative_file_with_multiple_roots_requires_an_absolute_path() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let roots = [
            Root::new(
                reqwest::Url::from_directory_path(first.path())
                    .unwrap()
                    .to_string(),
            ),
            Root::new(
                reqwest::Url::from_directory_path(second.path())
                    .unwrap()
                    .to_string(),
            ),
        ];

        let error = resolve_body_file_path("photo.png", &roots).unwrap_err();
        assert!(error.contains("relative `body_file`"));
    }

    #[test]
    fn json_media_type_detection_handles_parameters_and_suffixes() {
        assert!(is_json_media_type("application/json"));
        assert!(is_json_media_type(
            "Application/Problem+JSON; charset=utf-8"
        ));
        assert!(!is_json_media_type("image/png"));
        assert!(!is_json_media_type("multipart/form-data; boundary=abc"));
    }

    #[test]
    fn params_still_reject_unknown_fields() {
        let error = serde_json::from_str::<Params>(
            r#"{"url":"https://example.com","read_any_file":"/etc/passwd"}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field `read_any_file`"));
    }

    #[test]
    fn prepare_headers_injects_accept() {
        let headers = prepare_headers(&None, false);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Accept");
        assert_eq!(headers[0].1, "application/json");
    }

    #[test]
    fn prepare_headers_injects_content_type_with_body() {
        let headers = prepare_headers(&None, true);
        assert_eq!(headers.len(), 2);
        assert!(headers.iter().any(|(k, _)| k == "Accept"));
        assert!(headers.iter().any(|(k, _)| k == "Content-Type"));
    }

    #[test]
    fn prepare_headers_no_content_type_without_body() {
        let headers = prepare_headers(&None, false);
        assert!(!headers.iter().any(|(k, _)| k == "Content-Type"));
    }

    #[test]
    fn prepare_headers_preserves_user_accept() {
        let mut user = std::collections::HashMap::new();
        user.insert("Accept".to_string(), "text/xml".to_string());
        let headers = prepare_headers(&Some(user), false);
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].1, "text/xml");
    }

    #[test]
    fn prepare_headers_preserves_user_content_type() {
        let mut user = std::collections::HashMap::new();
        user.insert("content-type".to_string(), "text/plain".to_string());
        let headers = prepare_headers(&Some(user), true);
        // Should have user's content-type + auto Accept, but NOT auto Content-Type
        assert!(
            headers
                .iter()
                .any(|(k, v)| k == "content-type" && v == "text/plain")
        );
        assert!(
            !headers
                .iter()
                .any(|(k, v)| k == "Content-Type" && v == "application/json")
        );
    }

    #[test]
    fn prepare_headers_case_insensitive_check() {
        let mut user = std::collections::HashMap::new();
        user.insert("ACCEPT".to_string(), "text/html".to_string());
        let headers = prepare_headers(&Some(user), false);
        // Should not add a second Accept
        let accept_count = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("accept"))
            .count();
        assert_eq!(accept_count, 1);
    }

    #[test]
    fn do_paid_fetch_returns_error_for_invalid_url() {
        let result = do_paid_fetch(
            "GET",
            "not-a-url",
            &[],
            None,
            RedirectPolicy::Follow,
            None,
            &pay_core::session_manager::SessionManager::default(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn paid_fetch_opens_and_adopts_an_mpp_session() {
        SESSION_OPEN_CALLS.store(0, Ordering::SeqCst);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let challenge = session_challenge_header();
        let x402 = serde_json::json!({
            "x402Version": 2,
            "accepts": [{
                "scheme": "upto",
                "network": "solana:mainnet",
                "amount": "250000",
                "asset": "USDC",
                "payTo": "So11111111111111111111111111111111111111112"
            }]
        });
        let x402 = general_purpose::STANDARD.encode(serde_json::to_vec(&x402).unwrap());

        let server = std::thread::spawn(move || {
            let (mut first, _) = listener.accept().unwrap();
            let first_request = read_request(&mut first);
            assert!(
                !first_request
                    .to_ascii_lowercase()
                    .contains("authorization:")
            );
            let response = format!(
                "HTTP/1.1 402 Payment Required\r\nWWW-Authenticate: {challenge}\r\nPayment-Required: {x402}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            );
            first.write_all(response.as_bytes()).unwrap();

            let (mut retry, _) = listener.accept().unwrap();
            let retry_request = read_request(&mut retry);
            assert!(
                retry_request
                    .to_ascii_lowercase()
                    .contains("authorization: payment open-test")
            );
            retry
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                )
                .unwrap();

            let (mut reused, _) = listener.accept().unwrap();
            let reused_request = read_request(&mut reused);
            assert!(
                reused_request
                    .to_ascii_lowercase()
                    .contains("authorization: payment use-test")
            );
            reused
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 6\r\nConnection: close\r\n\r\nreused",
                )
                .unwrap();
        });

        let manager = pay_core::session_manager::SessionManager::default();
        let result = do_paid_fetch_with_session_opener(
            "POST",
            &format!("http://{address}/v1/chat"),
            &[],
            Some(&RequestBody::text("{}")),
            RedirectPolicy::Follow,
            None,
            &manager,
            fake_session_opener,
        )
        .unwrap();

        assert_eq!(result.0, b"ok");
        let reused = do_paid_fetch_with_session_opener(
            "POST",
            &format!("http://{address}/v1/chat"),
            &[],
            Some(&RequestBody::text("{}")),
            RedirectPolicy::Follow,
            None,
            &manager,
            fake_session_opener,
        )
        .unwrap();
        assert_eq!(reused.0, b"reused");
        assert_eq!(SESSION_OPEN_CALLS.load(Ordering::SeqCst), 1);
        server.join().unwrap();
    }

    #[test]
    fn request_validation_errors_are_returned_as_tool_content() {
        let result = pay_error_to_tool_result(pay_core::Error::RequestValidation(
            "body.email is required".to_string(),
        ));

        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap();
        assert_eq!(text.text, "body.email is required");
    }

    #[test]
    fn payment_errors_are_returned_as_tool_content() {
        let result = pay_error_to_tool_result(pay_core::Error::PaymentRejected(
            "insufficient funds".to_string(),
        ));

        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap();
        assert_eq!(
            text.text,
            "Pay curl failed: Payment rejected: insufficient funds"
        );
    }

    #[test]
    fn user_rejection_emits_clarification_guidance_macos() {
        let result = pay_error_to_tool_result(pay_core::Error::PaymentRejected(
            "rejected by user at Apple Keychain".to_string(),
        ));

        assert_eq!(result.is_error, Some(true));
        let text = &result.content[0].as_text().unwrap().text;
        assert!(text.contains("User declined"));
        assert!(text.contains("Apple Keychain"));
        assert!(text.contains("NOT sent"));
        assert!(text.contains("clarification"));
    }

    #[test]
    fn user_rejection_emits_clarification_guidance_windows() {
        let result = pay_error_to_tool_result(pay_core::Error::PaymentRejected(
            "rejected by user at Windows Hello".to_string(),
        ));
        let text = &result.content[0].as_text().unwrap().text;
        assert!(text.contains("User declined"));
        assert!(text.contains("Windows Hello"));
    }

    #[test]
    fn user_rejection_emits_clarification_guidance_linux() {
        let result = pay_error_to_tool_result(pay_core::Error::PaymentRejected(
            "rejected by user at GNOME Keyring".to_string(),
        ));
        let text = &result.content[0].as_text().unwrap().text;
        assert!(text.contains("User declined"));
        assert!(text.contains("GNOME Keyring"));
    }

    #[test]
    fn server_rejection_does_not_use_user_rejection_path() {
        // Server-side verification_failed → must keep the original "Pay curl
        // failed" prefix so the LLM sees it as a server error, not a user
        // declination.
        let result = pay_error_to_tool_result(pay_core::Error::PaymentRejected(
            "wrong network: expected localnet".to_string(),
        ));
        let text = &result.content[0].as_text().unwrap().text;
        assert!(text.starts_with("Pay curl failed: Payment rejected:"));
        assert!(!text.contains("User declined"));
    }

    // ── Env var propagation for network/account overrides ─────────────

    #[test]
    fn network_override_reads_from_env() {
        // Simulate what main.rs sets when --sandbox is used
        unsafe { std::env::set_var("PAY_NETWORK_ENFORCED", "localnet") };
        let val = std::env::var("PAY_NETWORK_ENFORCED").ok();
        assert_eq!(val.as_deref(), Some("localnet"));
        unsafe { std::env::remove_var("PAY_NETWORK_ENFORCED") };

        // Without the env var, returns None
        let val = std::env::var("PAY_NETWORK_ENFORCED").ok();
        assert!(val.is_none());
    }

    #[test]
    fn account_override_reads_from_env() {
        unsafe { std::env::set_var("PAY_ACTIVE_ACCOUNT", "my-wallet") };
        let val = std::env::var("PAY_ACTIVE_ACCOUNT").ok();
        assert_eq!(val.as_deref(), Some("my-wallet"));
        unsafe { std::env::remove_var("PAY_ACTIVE_ACCOUNT") };
    }

    #[test]
    fn x402_paid_fetch_supports_v1_and_v2_header_names() {
        assert_eq!(pay_core::x402::X402_V1_PAYMENT_HEADER, "X-PAYMENT");
        assert_eq!(pay_core::x402::X402_V2_PAYMENT_HEADER, "PAYMENT-SIGNATURE");
        assert_eq!(pay_core::x402::SIGN_IN_WITH_X_HEADER, "SIGN-IN-WITH-X");
    }

    // ── body_to_mcp_content content-type routing ──────────────────────
    //
    // Regression coverage for #350.4: pay-mcp must keep binary payloads
    // intact across the MCP transport. Text → Content::text, image →
    // base64 Content::image, other binary → tempfile path.

    #[test]
    fn is_binary_content_type_recognizes_text() {
        assert!(!is_binary_content_type("text/plain"));
        assert!(!is_binary_content_type("text/html"));
        assert!(!is_binary_content_type("text/csv"));
        assert!(!is_binary_content_type("application/json"));
        assert!(!is_binary_content_type("application/xml"));
        assert!(!is_binary_content_type("application/ld+json"));
        assert!(!is_binary_content_type("application/atom+xml"));
    }

    #[test]
    fn is_binary_content_type_recognizes_binary() {
        assert!(is_binary_content_type("application/pdf"));
        assert!(is_binary_content_type("application/octet-stream"));
        assert!(is_binary_content_type("application/zip"));
        assert!(is_binary_content_type("image/png"));
        assert!(is_binary_content_type("audio/mpeg"));
        assert!(is_binary_content_type("video/mp4"));
    }

    #[test]
    fn body_to_mcp_content_routes_text_as_text() {
        let body = b"plain string".to_vec();
        let content = body_to_mcp_content(body, Some("text/plain"), "empty");
        assert_eq!(content.len(), 1);
        let text = content[0].as_text().expect("text content").text.clone();
        assert_eq!(text, "plain string");
    }

    #[test]
    fn body_to_mcp_content_routes_json_as_text() {
        let body = br#"{"ok":true}"#.to_vec();
        let content = body_to_mcp_content(body, Some("application/json"), "empty");
        let text = content[0].as_text().expect("text content").text.clone();
        assert_eq!(text, r#"{"ok":true}"#);
    }

    #[test]
    fn body_to_mcp_content_strips_charset_parameter() {
        let body = b"hello".to_vec();
        let content = body_to_mcp_content(body, Some("text/plain; charset=utf-8"), "empty");
        let text = content[0].as_text().expect("text content").text.clone();
        assert_eq!(text, "hello");
    }

    #[test]
    fn body_to_mcp_content_routes_image_as_base64_image() {
        // Real PNG signature so encoding is meaningful.
        let body: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        let content = body_to_mcp_content(body.clone(), Some("image/png"), "empty");
        assert_eq!(content.len(), 1);
        let image = content[0].as_image().expect("image content");
        assert_eq!(image.mime_type, "image/png");
        let decoded = general_purpose::STANDARD.decode(&image.data).unwrap();
        assert_eq!(decoded, body, "base64 round-trips byte-for-byte");
    }

    #[test]
    fn body_to_mcp_content_spills_pdf_to_tempfile() {
        let body: Vec<u8> = b"%PDF-1.4 fake content with \xFF\xFE bytes".to_vec();
        let content = body_to_mcp_content(body.clone(), Some("application/pdf"), "empty");
        let text = content[0].as_text().expect("text content").text.clone();
        // Text content should describe the spill and contain a path
        assert!(text.contains("Binary response"));
        assert!(text.contains("application/pdf"));
        // Extract the path and verify the file contents match exactly
        let path = text.split(" written to ").nth(1).expect("path in message");
        let on_disk = std::fs::read(path).expect("tempfile readable");
        assert_eq!(on_disk, body, "spilled bytes preserved");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn body_to_mcp_content_octet_stream_spills_to_tempfile() {
        let body: Vec<u8> = vec![0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD];
        let content = body_to_mcp_content(body.clone(), Some("application/octet-stream"), "empty");
        let text = content[0].as_text().expect("text content").text.clone();
        let path = text.split(" written to ").nth(1).expect("path in message");
        let on_disk = std::fs::read(path).expect("tempfile readable");
        assert_eq!(on_disk, body);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn body_to_mcp_content_empty_body_returns_message() {
        let content = body_to_mcp_content(vec![], Some("application/json"), "Request completed.");
        let text = content[0].as_text().expect("text content").text.clone();
        assert_eq!(text, "Request completed.");
    }

    #[test]
    fn body_to_mcp_content_missing_content_type_treats_as_binary() {
        // No content-type → treat as octet-stream (safer than mangling
        // potential binary payload through UTF-8 lossy decode).
        let body: Vec<u8> = vec![0xFF, 0xFE, 0x00];
        let content = body_to_mcp_content(body.clone(), None, "empty");
        let text = content[0].as_text().expect("text content").text.clone();
        assert!(text.contains("Binary response"));
        let path = text.split(" written to ").nth(1).expect("path in message");
        let on_disk = std::fs::read(path).expect("tempfile readable");
        assert_eq!(on_disk, body);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn body_to_mcp_content_text_with_invalid_utf8_uses_replacement_chars() {
        // Caller advertised text/plain but body has invalid UTF-8 — we keep
        // it as text and replace bad sequences (data is lost, but caller
        // chose the text route by labeling it text/plain).
        let body: Vec<u8> = vec![b'h', b'i', 0xFF, 0xFE];
        let content = body_to_mcp_content(body, Some("text/plain"), "empty");
        let text = content[0].as_text().expect("text content").text.clone();
        assert!(text.starts_with("hi"));
        assert!(text.contains('\u{FFFD}'));
    }

    #[test]
    fn extension_for_mime_known_types() {
        assert_eq!(extension_for_mime("application/pdf"), ".pdf");
        assert_eq!(extension_for_mime("image/png"), ".png");
        // mime_guess returns the first registered extension, which is
        // database-version dependent (e.g. JPEG resolves to ".jpe" today).
        // Just assert we get a non-empty leading-dot extension that's
        // not the generic fallback.
        let jpg = extension_for_mime("image/jpeg");
        assert!(jpg.starts_with('.'));
        assert_ne!(jpg, ".bin");
    }

    #[test]
    fn extension_for_mime_unknown_falls_back_to_bin() {
        assert_eq!(extension_for_mime("application/x-totally-made-up"), ".bin");
        assert_eq!(extension_for_mime(""), ".bin");
    }

    // ── JSON-embedded base64 media extraction ─────────────────────────
    //
    // AI media APIs (Gemini, OpenAI, TTS) return binary as base64 *inside*
    // an application/json envelope. The MIME router sees "json" and would
    // otherwise dump the whole multi-megabyte blob as text. These cover the
    // extraction-to-file path that keeps the context small.

    /// Build a base64 string whose decoded bytes start with `sig`, padded to
    /// `total` bytes — large enough to clear MIN_BASE64_EXTRACT_BYTES.
    fn media_b64(sig: &[u8], total: usize) -> (Vec<u8>, String) {
        let mut bytes = sig.to_vec();
        bytes.resize(total, 0xAB);
        let encoded = general_purpose::STANDARD.encode(&bytes);
        (bytes, encoded)
    }

    const PNG_SIG: &[u8] = &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

    /// Pull the on-disk path out of a `<mime, N bytes → /path>` placeholder.
    fn path_from_placeholder(text: &str) -> String {
        let after = text.split("→ ").nth(1).expect("arrow in placeholder");
        after
            .split('>')
            .next()
            .expect("closing >")
            .trim()
            .to_string()
    }

    #[test]
    fn json_gemini_inline_data_extracts_image() {
        let (raw, b64) = media_b64(PNG_SIG, 9000);
        let body = serde_json::json!({
            "candidates": [{
                "content": { "parts": [
                    { "inlineData": { "mimeType": "image/png", "data": b64 } }
                ]}
            }]
        });
        let content = text_body_to_content(serde_json::to_string(&body).unwrap());

        // Slimmed JSON text + an inline image the model can see.
        assert!(content.len() >= 2);
        let text = content[0].as_text().expect("text").text.clone();
        assert!(!text.contains(&b64), "raw base64 removed from JSON");
        assert!(text.contains("image/png") && text.contains("bytes →"));

        let image = content[1].as_image().expect("image block");
        assert_eq!(image.mime_type, "image/png");
        assert_eq!(general_purpose::STANDARD.decode(&image.data).unwrap(), raw);

        let path = path_from_placeholder(&text);
        assert_eq!(std::fs::read(&path).expect("file on disk"), raw);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn json_openai_b64_json_extracts_via_magic_bytes() {
        // No mime hint — extraction must rely on PNG magic bytes.
        let (raw, b64) = media_b64(PNG_SIG, 9000);
        let body = serde_json::json!({ "data": [{ "b64_json": b64 }] });
        let content = text_body_to_content(serde_json::to_string(&body).unwrap());

        let text = content[0].as_text().expect("text").text.clone();
        assert!(text.contains("image/png") && !text.contains(&b64));
        assert!(content.iter().any(|c| c.as_image().is_some()));
        let _ = std::fs::remove_file(path_from_placeholder(&text));
        let _ = raw;
    }

    #[test]
    fn json_data_url_image_extracts() {
        let (_, b64) = media_b64(PNG_SIG, 9000);
        let body = serde_json::json!({ "image": format!("data:image/png;base64,{b64}") });
        let content = text_body_to_content(serde_json::to_string(&body).unwrap());

        let text = content[0].as_text().expect("text").text.clone();
        assert!(text.contains("image/png"));
        assert!(content.iter().any(|c| c.as_image().is_some()));
        let _ = std::fs::remove_file(path_from_placeholder(&text));
    }

    #[test]
    fn json_audio_extracts_as_resource_link() {
        // MP3 ID3 header → audio/mpeg, surfaced as a resource_link (not inline).
        let (_, b64) = media_b64(b"ID3\x03\x00\x00\x00", 9000);
        let body = serde_json::json!({ "audio": { "mimeType": "audio/mpeg", "data": b64 } });
        let content = text_body_to_content(serde_json::to_string(&body).unwrap());

        let text = content[0].as_text().expect("text").text.clone();
        assert!(text.contains("audio/mpeg"));
        let link = content
            .iter()
            .find_map(|c| c.as_resource_link())
            .expect("resource_link block");
        assert_eq!(link.mime_type.as_deref(), Some("audio/mpeg"));
        assert!(link.uri.starts_with("file://"));
        // Audio is referenced, never inlined as base64.
        assert!(content.iter().all(|c| c.as_image().is_none()));
        let _ = std::fs::remove_file(path_from_placeholder(&text));
    }

    #[test]
    fn json_small_base64_stays_inline() {
        // Below MIN_BASE64_EXTRACT_BYTES → left untouched in the JSON.
        let small = general_purpose::STANDARD.encode(PNG_SIG);
        let body = serde_json::json!({ "inlineData": { "mimeType": "image/png", "data": small } });
        let content = text_body_to_content(serde_json::to_string(&body).unwrap());
        assert_eq!(content.len(), 1);
        assert!(content[0].as_text().unwrap().text.contains(&small));
    }

    #[test]
    fn json_large_opaque_base64_not_extracted() {
        // 9 KB of base64 with no media signature and no mime hint — must NOT
        // be written to a file (could be a signature, token, opaque blob).
        let b64 = general_purpose::STANDARD.encode(vec![0x01u8; 9000]);
        let body = serde_json::json!({ "signature": b64 });
        let content = text_body_to_content(serde_json::to_string(&body).unwrap());
        assert_eq!(content.len(), 1);
        assert!(content[0].as_text().unwrap().text.contains(&b64));
    }

    #[test]
    fn large_plain_text_spills_with_preview() {
        let big = "x".repeat(MAX_TEXT_INLINE_BYTES + 100);
        let content = text_body_to_content(big.clone());
        assert_eq!(content.len(), 1);
        let text = content[0].as_text().unwrap().text.clone();
        assert!(text.contains("Large text response"));
        assert!(text.len() < big.len(), "only a preview is inlined");
        let path = text
            .split(" written to ")
            .nth(1)
            .and_then(|s| s.split(". First").next())
            .expect("path in message");
        assert_eq!(std::fs::read(path).unwrap().len(), big.len());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn top_level_pdf_gets_resource_link() {
        let mut body = b"%PDF-1.4".to_vec();
        body.resize(64, 0x20);
        let content = body_to_mcp_content(body.clone(), Some("application/pdf"), "empty");
        let note = content[0].as_text().expect("text note").text.clone();
        let path = note.split(" written to ").nth(1).expect("path").to_string();
        let link = content
            .iter()
            .find_map(|c| c.as_resource_link())
            .expect("resource_link");
        assert_eq!(link.mime_type.as_deref(), Some("application/pdf"));
        assert_eq!(link.size, Some(body.len() as u64));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn sniff_media_mime_detects_common_formats() {
        assert_eq!(sniff_media_mime(PNG_SIG), Some("image/png"));
        assert_eq!(
            sniff_media_mime(&[0xFF, 0xD8, 0xFF, 0xE0]),
            Some("image/jpeg")
        );
        assert_eq!(sniff_media_mime(b"GIF89a...."), Some("image/gif"));
        assert_eq!(sniff_media_mime(b"%PDF-1.7"), Some("application/pdf"));
        assert_eq!(sniff_media_mime(b"ID3\x03\x00\x00\x00"), Some("audio/mpeg"));
        assert_eq!(sniff_media_mime(b"OggS\x00\x02\x00\x00"), Some("audio/ogg"));
        assert_eq!(
            sniff_media_mime(b"RIFF\x00\x00\x00\x00WEBP"),
            Some("image/webp")
        );
        assert_eq!(
            sniff_media_mime(b"RIFF\x00\x00\x00\x00WAVE"),
            Some("audio/wav")
        );
        assert_eq!(
            sniff_media_mime(b"\x00\x00\x00\x18ftypmp42"),
            Some("video/mp4")
        );
        assert_eq!(sniff_media_mime(b"just some plain text here"), None);
    }
}
