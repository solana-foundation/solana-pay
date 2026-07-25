use std::path::PathBuf;

use clap::Args;
use pay_core::client::fetch::{MultipartFile, RedirectPolicy, RequestBody};

/// Fetch a URL using Pay's built-in HTTP client.
///
/// Prints the response body to stdout and handles 402 Payment Required flows.
/// Local files are snapshotted once and the same bytes are reused for a paid
/// retry.
#[derive(Args)]
pub struct FetchCommand {
    /// The URL to fetch.
    pub url: String,

    /// HTTP method. Defaults to GET without a body and POST with a body.
    #[arg(short = 'X', long, value_name = "METHOD")]
    pub method: Option<String>,

    /// Extra header in "Key: Value" format.
    #[arg(short = 'H', long = "header")]
    pub headers: Vec<String>,

    /// Inline request body. Defaults to text/plain; use --content-type for JSON.
    /// Mutually exclusive with file and form inputs.
    #[arg(long, value_name = "TEXT")]
    pub body: Option<String>,

    /// Read the complete request body from a local file.
    #[arg(long, value_name = "PATH")]
    pub body_file: Option<PathBuf>,

    /// Multipart text field in NAME=VALUE form. May be repeated.
    #[arg(long = "form", value_name = "NAME=VALUE")]
    pub form_fields: Vec<String>,

    /// Multipart file field in NAME=PATH form. May be repeated.
    #[arg(long = "form-file", value_name = "NAME=PATH")]
    pub form_files: Vec<String>,

    /// MIME type for --body or --body-file. File types are inferred by default.
    #[arg(long, value_name = "MIME")]
    pub content_type: Option<String>,
}

pub struct PreparedFetchRequest {
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<RequestBody>,
    pub redirect_policy: RedirectPolicy,
    pub validation_body: Option<String>,
    pub content_type: Option<String>,
}

impl FetchCommand {
    pub fn prepare(&self) -> pay_core::Result<PreparedFetchRequest> {
        let has_multipart = !self.form_fields.is_empty() || !self.form_files.is_empty();
        let body_sources = usize::from(self.body.is_some())
            + usize::from(self.body_file.is_some())
            + usize::from(has_multipart);
        if body_sources > 1 {
            return Err(pay_core::Error::RequestValidation(
                "Use exactly one body source: --body, --body-file, or --form/--form-file."
                    .to_string(),
            ));
        }
        if has_multipart && self.content_type.is_some() {
            return Err(pay_core::Error::RequestValidation(
                "Do not use --content-type with multipart input; Pay generates the boundary and Content-Type header."
                    .to_string(),
            ));
        }

        let mut headers = parse_headers(&self.headers)?;
        let explicit_header_content_type = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.clone());
        if has_multipart && explicit_header_content_type.is_some() {
            return Err(pay_core::Error::RequestValidation(
                "Do not supply a Content-Type header with multipart input; Pay generates the boundary and Content-Type header."
                    .to_string(),
            ));
        }
        if explicit_header_content_type.is_some() && self.content_type.is_some() {
            return Err(pay_core::Error::RequestValidation(
                "Set the request content type with either --content-type or a Content-Type header, not both."
                    .to_string(),
            ));
        }

        let (body, inferred_content_type, file_backed) = if let Some(body) = &self.body {
            (
                Some(RequestBody::text(body.clone())),
                Some("text/plain".to_string()),
                false,
            )
        } else if let Some(path) = &self.body_file {
            let (body, content_type) = RequestBody::from_file(path)?;
            (Some(body), Some(content_type), true)
        } else if has_multipart {
            let fields = parse_name_values("--form", &self.form_fields)?;
            let files = parse_form_files(&self.form_files)?;
            let (body, content_type) = RequestBody::multipart(&fields, &files)?;
            (Some(body), Some(content_type), true)
        } else {
            (None, None, false)
        };

        let content_type = match (
            self.content_type.as_deref(),
            explicit_header_content_type.as_deref(),
            inferred_content_type,
        ) {
            (Some(value), None, _) => Some(pay_core::fetch::normalize_content_type(value)?),
            (None, Some(value), _) => Some(pay_core::fetch::normalize_content_type(value)?),
            (None, None, inferred) => inferred,
            (Some(_), Some(_), _) => unreachable!("duplicate content type rejected above"),
        };

        if body.is_some() && explicit_header_content_type.is_none() {
            headers.push((
                "Content-Type".to_string(),
                content_type
                    .clone()
                    .unwrap_or_else(|| "application/octet-stream".to_string()),
            ));
        }

        if file_backed {
            reject_file_body_managed_headers(&headers)?;
        }

        let has_body = body.is_some();
        let method = self
            .method
            .as_deref()
            .unwrap_or(if has_body { "POST" } else { "GET" })
            .to_ascii_uppercase();
        let validation_body = if content_type.as_deref().is_some_and(is_json_content_type) {
            body.as_ref()
                .and_then(RequestBody::as_text)
                .map(str::to_string)
        } else {
            None
        };

        Ok(PreparedFetchRequest {
            method,
            headers,
            body,
            redirect_policy: if file_backed {
                RedirectPolicy::None
            } else {
                RedirectPolicy::Follow
            },
            validation_body,
            content_type,
        })
    }
}

fn parse_headers(values: &[String]) -> pay_core::Result<Vec<(String, String)>> {
    values
        .iter()
        .map(|header| {
            let (name, value) = header.split_once(':').ok_or_else(|| {
                pay_core::Error::RequestValidation(format!(
                    "Header `{header}` is invalid; use `Name: Value`."
                ))
            })?;
            let name = name.trim();
            let value = value.trim();
            if name.is_empty() {
                return Err(pay_core::Error::RequestValidation(format!(
                    "Header `{header}` has an empty name; use `Name: Value`."
                )));
            }
            Ok((name.to_string(), value.to_string()))
        })
        .collect()
}

fn parse_name_values(option: &str, values: &[String]) -> pay_core::Result<Vec<(String, String)>> {
    values
        .iter()
        .map(|value| {
            let (name, value) = value.split_once('=').ok_or_else(|| {
                pay_core::Error::RequestValidation(format!(
                    "{option} value `{value}` is invalid; use NAME=VALUE."
                ))
            })?;
            if name.is_empty() {
                return Err(pay_core::Error::RequestValidation(format!(
                    "{option} value `{value}` has an empty field name."
                )));
            }
            Ok((name.to_string(), value.to_string()))
        })
        .collect()
}

fn parse_form_files(values: &[String]) -> pay_core::Result<Vec<MultipartFile>> {
    parse_name_values("--form-file", values).map(|files| {
        files
            .into_iter()
            .map(|(name, path)| MultipartFile {
                name,
                path: PathBuf::from(path),
                filename: None,
                content_type: None,
            })
            .collect()
    })
}

fn reject_file_body_managed_headers(headers: &[(String, String)]) -> pay_core::Result<()> {
    const MANAGED: &[&str] = &[
        "host",
        "content-length",
        "transfer-encoding",
        "connection",
        "proxy-connection",
        "trailer",
        "x-pay-forward-to",
        pay_core::fetch::DEBUGGER_NO_FOLLOW_HEADER,
    ];
    if let Some((name, _)) = headers.iter().find(|(name, _)| {
        MANAGED
            .iter()
            .any(|managed| name.eq_ignore_ascii_case(managed))
    }) {
        return Err(pay_core::Error::RequestValidation(format!(
            "Header `{name}` cannot be supplied with a file-backed request; Pay controls destination and body framing."
        )));
    }
    Ok(())
}

fn is_json_content_type(value: &str) -> bool {
    let media_type = value.split(';').next().unwrap_or(value).trim();
    media_type.eq_ignore_ascii_case("application/json")
        || media_type.to_ascii_lowercase().ends_with("+json")
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        command: FetchCommand,
    }

    #[test]
    fn inline_text_body_defaults_to_text_plain_without_json_validation() {
        let cli = TestCli::try_parse_from([
            "pay-fetch",
            "https://example.com/messages",
            "--body",
            "hello",
        ])
        .unwrap();
        let prepared = cli.command.prepare().unwrap();
        assert_eq!(prepared.method, "POST");
        assert_eq!(prepared.body.as_ref().unwrap().as_bytes(), b"hello");
        assert!(
            prepared
                .headers
                .contains(&("Content-Type".to_string(), "text/plain".to_string()))
        );
        assert_eq!(prepared.validation_body, None);
    }

    #[test]
    fn inline_json_body_requires_an_explicit_json_content_type() {
        let cli = TestCli::try_parse_from([
            "pay-fetch",
            "https://example.com/messages",
            "--body",
            r#"{"message":"hello"}"#,
            "--content-type",
            "application/json",
        ])
        .unwrap();
        let prepared = cli.command.prepare().unwrap();

        assert!(
            prepared
                .headers
                .contains(&("Content-Type".to_string(), "application/json".to_string()))
        );
        assert_eq!(
            prepared.validation_body.as_deref(),
            Some(r#"{"message":"hello"}"#)
        );
    }

    #[test]
    fn file_body_is_snapshotted_and_does_not_follow_redirects() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("image.png");
        std::fs::write(&path, [0, 159, 146, 150]).unwrap();
        let cli = TestCli::try_parse_from([
            "pay-fetch",
            "https://example.com/images",
            "--body-file",
            path.to_str().unwrap(),
        ])
        .unwrap();
        let prepared = cli.command.prepare().unwrap();
        std::fs::write(&path, b"changed after preparation").unwrap();
        assert_eq!(prepared.body.unwrap().as_bytes(), [0, 159, 146, 150]);
        assert_eq!(prepared.redirect_policy, RedirectPolicy::None);
    }

    #[test]
    fn multipart_accepts_text_and_file_fields_in_one_request() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("note.txt");
        std::fs::write(&path, b"hello from file").unwrap();
        let cli = TestCli::try_parse_from([
            "pay-fetch",
            "https://example.com/upload",
            "--form",
            "prompt=describe this",
            "--form-file",
            &format!("document={}", path.display()),
        ])
        .unwrap();
        let prepared = cli.command.prepare().unwrap();
        let body = prepared.body.unwrap();
        let text = String::from_utf8_lossy(body.as_bytes());
        assert!(text.contains("name=\"prompt\""));
        assert!(text.contains("describe this"));
        assert!(text.contains("name=\"document\"; filename=\"note.txt\""));
        assert!(text.contains("hello from file"));
        assert_eq!(prepared.redirect_policy, RedirectPolicy::None);
    }

    #[test]
    fn body_sources_are_mutually_exclusive() {
        let cli = TestCli::try_parse_from([
            "pay-fetch",
            "https://example.com/upload",
            "--body",
            "inline",
            "--body-file",
            "payload.bin",
        ])
        .unwrap();
        assert!(cli.command.prepare().is_err());
    }
}
