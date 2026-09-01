use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Args;
use pay_core::client::fetch::{MultipartFile, RedirectPolicy, RequestBody};
use sha2::{Digest, Sha256};

const MAX_OUTPUT_SCHEMA_BYTES: usize = 1_048_576;
const OUTPUT_SCHEMA_DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";
const SHA256_PREFIX: &str = "sha256:";

/// One locally compiled buyer acceptance contract. The source file is read
/// once before account setup, then this immutable validator is reused for the
/// initial response and every paid retry.
#[derive(Debug, Clone)]
pub struct PreparedOutputSchema {
    digest: String,
    validator: jsonschema::Validator,
}

impl PreparedOutputSchema {
    pub fn validate_response(
        &self,
        content_type: Option<&str>,
        body: Option<&[u8]>,
    ) -> pay_core::Result<()> {
        let content_type = content_type.ok_or_else(|| {
            pay_core::Error::DeliveryValidation(
                "the response omitted Content-Type; the buyer contract requires JSON".to_string(),
            )
        })?;
        if !is_json_content_type(content_type) {
            return Err(pay_core::Error::DeliveryValidation(format!(
                "the response Content-Type `{content_type}` is not JSON"
            )));
        }
        let body = body.ok_or_else(|| {
            pay_core::Error::DeliveryValidation(
                "the buffered response body is unavailable for buyer-contract validation"
                    .to_string(),
            )
        })?;
        let value: serde_json::Value = serde_json::from_slice(body).map_err(|error| {
            pay_core::Error::DeliveryValidation(format!(
                "the response body is not valid JSON: {error}"
            ))
        })?;
        let failures = self
            .validator
            .iter_errors(&value)
            .take(3)
            .map(|error| {
                let instance_path = if error.instance_path().as_str().is_empty() {
                    "/"
                } else {
                    error.instance_path().as_str()
                };
                format!("{instance_path} against {}", error.schema_path())
            })
            .collect::<Vec<_>>();
        if failures.is_empty() {
            return Ok(());
        }
        Err(pay_core::Error::DeliveryValidation(format!(
            "the response does not satisfy buyer output contract {} at {}",
            self.digest,
            failures.join(", ")
        )))
    }
}

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

    /// Local JSON Schema 2020-12 file that the final response must satisfy.
    #[arg(long, value_name = "PATH", requires = "output_schema_sha256")]
    pub output_schema: Option<PathBuf>,

    /// Expected SHA-256 of the canonical output schema JSON.
    #[arg(long, value_name = "sha256:HEX", requires = "output_schema")]
    pub output_schema_sha256: Option<String>,

    #[arg(skip)]
    pub(crate) prepared_output_schema: Option<PreparedOutputSchema>,
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
    /// Validate and snapshot every local buyer-controlled acceptance input.
    /// `main` calls this before loading config or starting account setup.
    pub fn preflight_local_inputs(&mut self) -> pay_core::Result<()> {
        if self.prepared_output_schema.is_some() {
            return Ok(());
        }
        self.prepared_output_schema = match (
            self.output_schema.as_deref(),
            self.output_schema_sha256.as_deref(),
        ) {
            (None, None) => None,
            (Some(path), Some(expected_digest)) => {
                Some(prepare_output_schema(path, expected_digest)?)
            }
            _ => {
                return Err(pay_core::Error::RequestValidation(
                    "Use --output-schema and --output-schema-sha256 together.".to_string(),
                ));
            }
        };
        Ok(())
    }

    pub fn prepared_output_schema(&self) -> Option<&PreparedOutputSchema> {
        self.prepared_output_schema.as_ref()
    }

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

fn prepare_output_schema(
    path: &Path,
    expected_digest: &str,
) -> pay_core::Result<PreparedOutputSchema> {
    let expected_digest = normalize_schema_digest(expected_digest)?;
    let bytes = read_output_schema_file(path)?;
    let mut schema: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        pay_core::Error::RequestValidation(format!(
            "Output schema `{}` is not valid JSON: {error}",
            path.display()
        ))
    })?;
    normalize_ecmascript_numbers(&mut schema)?;

    if let Some(declared) = schema.get("$schema")
        && declared.as_str() != Some(OUTPUT_SCHEMA_DRAFT)
    {
        return Err(pay_core::Error::RequestValidation(format!(
            "Output schema `{}` must use JSON Schema 2020-12 (`{OUTPUT_SCHEMA_DRAFT}`).",
            path.display()
        )));
    }
    reject_external_schema_references(&schema, "")?;
    jsonschema::draft202012::meta::validate(&schema).map_err(|error| {
        pay_core::Error::RequestValidation(format!(
            "Output schema `{}` is not valid JSON Schema 2020-12 at {}.",
            path.display(),
            error.instance_path()
        ))
    })?;

    let canonical = canonical_json(&schema)?;
    let actual_digest = format!("sha256:{:x}", Sha256::digest(canonical.as_bytes()));
    if actual_digest != expected_digest {
        return Err(pay_core::Error::RequestValidation(format!(
            "Output schema digest mismatch: expected {expected_digest}, got {actual_digest}."
        )));
    }

    let validator = jsonschema::draft202012::options()
        .should_validate_formats(true)
        .build(&schema)
        .map_err(|error| {
            pay_core::Error::RequestValidation(format!(
                "Could not compile output schema `{}`: {error}",
                path.display()
            ))
        })?;

    Ok(PreparedOutputSchema {
        digest: actual_digest,
        validator,
    })
}

fn normalize_schema_digest(value: &str) -> pay_core::Result<String> {
    let value = value.trim();
    let hex = value.strip_prefix(SHA256_PREFIX).ok_or_else(|| {
        pay_core::Error::RequestValidation(
            "--output-schema-sha256 must be `sha256:` followed by 64 lowercase hex characters."
                .to_string(),
        )
    })?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(pay_core::Error::RequestValidation(
            "--output-schema-sha256 must be `sha256:` followed by 64 lowercase hex characters."
                .to_string(),
        ));
    }
    Ok(value.to_string())
}

fn read_output_schema_file(path: &Path) -> pay_core::Result<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        pay_core::Error::RequestValidation(format!(
            "Could not inspect output schema `{}`: {error}",
            path.display()
        ))
    })?;
    if metadata.file_type().is_symlink() {
        return Err(pay_core::Error::RequestValidation(format!(
            "Output schema `{}` must not be a symlink.",
            path.display()
        )));
    }
    if !metadata.file_type().is_file() {
        return Err(pay_core::Error::RequestValidation(format!(
            "Output schema `{}` must be a regular file.",
            path.display()
        )));
    }
    if metadata.len() > MAX_OUTPUT_SCHEMA_BYTES as u64 {
        return Err(pay_core::Error::RequestValidation(format!(
            "Output schema `{}` exceeds the 1 MiB limit.",
            path.display()
        )));
    }

    let file = open_output_schema_no_follow(path).map_err(|error| {
        pay_core::Error::RequestValidation(format!(
            "Could not open output schema `{}`: {error}",
            path.display()
        ))
    })?;
    if !file.metadata()?.file_type().is_file() {
        return Err(pay_core::Error::RequestValidation(format!(
            "Output schema `{}` must be a regular file.",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_OUTPUT_SCHEMA_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_OUTPUT_SCHEMA_BYTES {
        return Err(pay_core::Error::RequestValidation(format!(
            "Output schema `{}` exceeds the 1 MiB limit.",
            path.display()
        )));
    }
    Ok(bytes)
}

fn open_output_schema_no_follow(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

fn reject_external_schema_references(
    value: &serde_json::Value,
    path: &str,
) -> pay_core::Result<()> {
    match value {
        serde_json::Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                reject_external_schema_references(value, &format!("{path}/{index}"))?;
            }
        }
        serde_json::Value::Object(values) => {
            for (key, value) in values {
                let child_path = format!("{path}/{}", json_pointer_escape(key));
                if (key == "$ref" || key == "$dynamicRef")
                    && value
                        .as_str()
                        .is_some_and(|reference| !reference.starts_with('#'))
                {
                    return Err(pay_core::Error::RequestValidation(format!(
                        "Output schema reference at {child_path} must be local; external schema retrieval is disabled."
                    )));
                }
                reject_external_schema_references(value, &child_path)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn json_pointer_escape(value: &str) -> String {
    value.replace('~', "~0").replace('/', "~1")
}

fn canonical_json(value: &serde_json::Value) -> pay_core::Result<String> {
    serde_json_canonicalizer::to_string(value).map_err(pay_core::Error::Json)
}

fn normalize_ecmascript_numbers(value: &mut serde_json::Value) -> pay_core::Result<()> {
    match value {
        serde_json::Value::Number(number) => {
            let number = number.as_f64().ok_or_else(|| {
                pay_core::Error::RequestValidation(
                    "Output schema contains a number outside the ECMAScript JSON range."
                        .to_string(),
                )
            })?;
            *value = serde_json::Value::Number(serde_json::Number::from_f64(number).ok_or_else(
                || {
                    pay_core::Error::RequestValidation(
                        "Output schema contains a non-finite number.".to_string(),
                    )
                },
            )?);
        }
        serde_json::Value::Array(values) => {
            for value in values {
                normalize_ecmascript_numbers(value)?;
            }
        }
        serde_json::Value::Object(values) => {
            for value in values.values_mut() {
                normalize_ecmascript_numbers(value)?;
            }
        }
        _ => {}
    }
    Ok(())
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
    use serde_json::json;

    use super::*;

    const TEST_SCHEMA_DIGEST: &str =
        "sha256:b00c561bf9bc8da2bb4c8762557e2bbbdebd43dd7547a446fcb5fe5ef160b8f0";

    fn test_schema() -> serde_json::Value {
        json!({
            "$schema": OUTPUT_SCHEMA_DRAFT,
            "type": "object",
            "properties": {
                "value": { "minimum": 0.000001, "type": "number" },
                "url": { "format": "uri", "type": "string" }
            },
            "required": ["url", "value"],
            "additionalProperties": false
        })
    }

    fn write_test_schema(directory: &tempfile::TempDir) -> PathBuf {
        let path = directory.path().join("output.schema.json");
        std::fs::write(&path, serde_json::to_vec_pretty(&test_schema()).unwrap()).unwrap();
        path
    }

    fn command_with_schema(path: &Path) -> FetchCommand {
        TestCli::try_parse_from([
            "pay-fetch",
            "https://example.com/data",
            "--output-schema",
            path.to_str().unwrap(),
            "--output-schema-sha256",
            TEST_SCHEMA_DIGEST,
        ])
        .unwrap()
        .command
    }

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

    #[test]
    fn output_schema_flags_are_required_as_a_pair() {
        assert!(
            TestCli::try_parse_from([
                "pay-fetch",
                "https://example.com/data",
                "--output-schema",
                "schema.json",
            ])
            .is_err()
        );
        assert!(
            TestCli::try_parse_from([
                "pay-fetch",
                "https://example.com/data",
                "--output-schema-sha256",
                TEST_SCHEMA_DIGEST,
            ])
            .is_err()
        );
    }

    #[test]
    fn canonical_schema_digest_matches_agent_payment_policy() {
        let canonical = canonical_json(&test_schema()).unwrap();
        assert_eq!(
            canonical,
            r#"{"$schema":"https://json-schema.org/draft/2020-12/schema","additionalProperties":false,"properties":{"url":{"format":"uri","type":"string"},"value":{"minimum":0.000001,"type":"number"}},"required":["url","value"],"type":"object"}"#
        );
        assert_eq!(
            format!("sha256:{:x}", Sha256::digest(canonical.as_bytes())),
            TEST_SCHEMA_DIGEST
        );
    }

    #[test]
    fn canonical_key_order_matches_javascript_utf16_sort() {
        let value = json!({ "\u{e000}": 1, "\u{10000}": 2 });
        assert_eq!(canonical_json(&value).unwrap(), "{\"𐀀\":2,\"\":1}");
    }

    #[test]
    fn canonical_numbers_match_ecmascript_json_stringify() {
        let mut value = json!([1.0, 0.000001, 1e21, 1e-7, 9007199254740993_u64, -0.0]);
        normalize_ecmascript_numbers(&mut value).unwrap();
        assert_eq!(
            canonical_json(&value).unwrap(),
            "[1,0.000001,1e+21,1e-7,9007199254740992,0]"
        );
    }

    #[test]
    fn prepared_output_schema_validates_shape_and_standard_formats() {
        let directory = tempfile::tempdir().unwrap();
        let path = write_test_schema(&directory);
        let mut command = command_with_schema(&path);
        command.preflight_local_inputs().unwrap();
        let contract = command.prepared_output_schema().unwrap();

        contract
            .validate_response(
                Some("application/json; charset=utf-8"),
                Some(br#"{"url":"https://example.com/result","value":0.5}"#),
            )
            .unwrap();
        for invalid in [
            br#"{"url":"not a uri","value":0.5}"#.as_slice(),
            br#"{"url":"https://example.com/result","value":"0.5"}"#.as_slice(),
            br#"{"url":"https://example.com/result"}"#.as_slice(),
            br#"{"url":"https://example.com/result","value":0.5,"extra":true}"#.as_slice(),
        ] {
            assert!(
                contract
                    .validate_response(Some("application/json"), Some(invalid))
                    .is_err()
            );
        }
    }

    #[test]
    fn prepared_schema_is_immutable_after_preflight() {
        let directory = tempfile::tempdir().unwrap();
        let path = write_test_schema(&directory);
        let mut command = command_with_schema(&path);
        command.preflight_local_inputs().unwrap();
        std::fs::write(&path, br#"{"type":"string"}"#).unwrap();

        command
            .prepared_output_schema()
            .unwrap()
            .validate_response(
                Some("application/problem+json"),
                Some(br#"{"url":"https://example.com/result","value":1}"#),
            )
            .unwrap();

        command.preflight_local_inputs().unwrap();
        command
            .prepared_output_schema()
            .unwrap()
            .validate_response(
                Some("application/json"),
                Some(br#"{"url":"https://example.com/result","value":2}"#),
            )
            .unwrap();
    }

    #[test]
    fn output_schema_rejects_bad_digest_malformed_json_and_external_refs() {
        let directory = tempfile::tempdir().unwrap();
        let path = write_test_schema(&directory);
        assert!(prepare_output_schema(&path, &format!("sha256:{}", "0".repeat(64))).is_err());

        std::fs::write(&path, b"{").unwrap();
        assert!(prepare_output_schema(&path, TEST_SCHEMA_DIGEST).is_err());

        let external = json!({
            "$schema": OUTPUT_SCHEMA_DRAFT,
            "$ref": "https://example.com/remote.schema.json"
        });
        std::fs::write(&path, serde_json::to_vec(&external).unwrap()).unwrap();
        let digest = format!(
            "sha256:{:x}",
            Sha256::digest(canonical_json(&external).unwrap().as_bytes())
        );
        let error = prepare_output_schema(&path, &digest).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("external schema retrieval is disabled")
        );
    }

    #[test]
    fn output_schema_rejects_non_json_delivery_without_echoing_body() {
        let directory = tempfile::tempdir().unwrap();
        let path = write_test_schema(&directory);
        let contract = prepare_output_schema(&path, TEST_SCHEMA_DIGEST).unwrap();
        let secret_body = b"secret-response-body";
        let error = contract
            .validate_response(Some("text/plain"), Some(secret_body))
            .unwrap_err();
        assert!(!error.to_string().contains("secret-response-body"));
    }

    #[cfg(unix)]
    #[test]
    fn output_schema_rejects_symlinks() {
        use std::os::unix::fs::symlink;

        let directory = tempfile::tempdir().unwrap();
        let path = write_test_schema(&directory);
        let link = directory.path().join("linked.schema.json");
        symlink(&path, &link).unwrap();
        assert!(prepare_output_schema(&link, TEST_SCHEMA_DIGEST).is_err());
    }

    #[test]
    fn output_schema_rejects_oversized_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oversized.schema.json");
        std::fs::write(&path, vec![b' '; MAX_OUTPUT_SCHEMA_BYTES + 1]).unwrap();
        assert!(prepare_output_schema(&path, TEST_SCHEMA_DIGEST).is_err());
    }

    #[test]
    fn repository_fixture_digest_stays_compatible_with_agent_payment_policy() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/output.schema.json");
        prepare_output_schema(&path, TEST_SCHEMA_DIGEST).unwrap();
    }
}
