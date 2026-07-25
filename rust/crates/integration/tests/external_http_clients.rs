//! Hermetic process-boundary contracts for the external HTTP client wrappers.
//!
//! Each test shadows curl, wget, or HTTPie with a deterministic executable.
//! The fake clients never open a socket: they only emit a scripted transcript
//! and record the argv that `pay-core` passed to them.

#![cfg(unix)]

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

use pay_core::runner::RunOutcome;
use pay_core::{run_curl_with_headers, run_httpie_with_headers, run_wget_with_headers};
use tempfile::TempDir;

const URL: &str = "https://offline.invalid/paid-resource";
const PROXY_ENV: &[&str] = &[
    "ALL_PROXY",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "all_proxy",
    "http_proxy",
    "https_proxy",
    "no_proxy",
];

static PROCESS_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct TestEnvironment {
    _lock: MutexGuard<'static, ()>,
    temp: TempDir,
    previous_cwd: PathBuf,
    previous_env: Vec<(&'static str, Option<OsString>)>,
}

impl TestEnvironment {
    fn new() -> Self {
        let lock = PROCESS_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let temp = tempfile::tempdir().expect("create isolated tempdir");
        let bin = temp.path().join("bin");
        fs::create_dir(&bin).expect("create fake client directory");

        write_fake_client(&bin.join("curl"), CURL_FAKE);
        write_fake_client(&bin.join("wget"), WGET_FAKE);
        write_fake_client(&bin.join("http"), HTTPIE_FAKE);
        write_fake_client(&bin.join("which"), WHICH_FAKE);

        let mut names = vec!["PATH", "PAY_TEST_ARGV", "PAY_TEST_RESPONSE"];
        names.extend_from_slice(PROXY_ENV);
        let previous_env = names
            .into_iter()
            .map(|name| (name, std::env::var_os(name)))
            .collect();
        let previous_cwd = std::env::current_dir().expect("read current directory");

        // The fake binaries are the only executables reachable by the wrappers.
        // Proxies and cwd are also process-global, so save and restore all of them.
        unsafe {
            std::env::set_var("PATH", &bin);
            std::env::set_var("PAY_TEST_ARGV", temp.path().join("argv.txt"));
            std::env::remove_var("PAY_TEST_RESPONSE");
            for name in PROXY_ENV {
                std::env::remove_var(name);
            }
        }
        std::env::set_current_dir(temp.path()).expect("enter isolated tempdir");

        Self {
            _lock: lock,
            temp,
            previous_cwd,
            previous_env,
        }
    }

    fn set_response(&self, response: &str) {
        unsafe { std::env::set_var("PAY_TEST_RESPONSE", response) };
    }

    fn argv(&self) -> Vec<String> {
        fs::read_to_string(self.temp.path().join("argv.txt"))
            .expect("fake client wrote argv")
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Drop for TestEnvironment {
    fn drop(&mut self) {
        std::env::set_current_dir(&self.previous_cwd).expect("restore current directory");
        unsafe {
            for (name, value) in &self.previous_env {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
}

fn write_fake_client(path: &Path, script: &str) {
    fs::write(path, script).expect("write fake client");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .expect("make fake client executable");
}

fn assert_completed(outcome: RunOutcome) {
    match outcome {
        RunOutcome::Completed { exit_code, .. } => assert_eq!(exit_code, 0),
        other => panic!("expected a completed 200 response, got {other:?}"),
    }
}

fn assert_unknown_402(outcome: RunOutcome, expected_header: &str) {
    match outcome {
        RunOutcome::UnknownPaymentRequired {
            headers,
            resource_url,
            ..
        } => {
            assert_eq!(resource_url, URL);
            assert!(
                headers
                    .iter()
                    .any(|(name, value)| { name == "x-pay-test" && value == expected_header })
            );
        }
        other => panic!("expected a classified 402 response, got {other:?}"),
    }
}

fn assert_argv_contains_in_order(argv: &[String], expected: &[&str]) {
    let mut index = 0;
    for arg in argv {
        if expected.get(index).is_some_and(|wanted| arg == wanted) {
            index += 1;
        }
    }
    assert_eq!(
        index,
        expected.len(),
        "expected argv sequence {expected:?}, got {argv:?}"
    );
}

fn assert_arg_occurs_once(argv: &[String], expected: &str) {
    assert_eq!(
        argv.iter().filter(|arg| arg.as_str() == expected).count(),
        1,
        "expected exactly one {expected:?} argument, got {argv:?}"
    );
}

#[test]
fn curl_wrapper_classifies_scripted_200_and_402_and_injects_headers() {
    let env = TestEnvironment::new();
    let args = vec![URL.to_string()];

    env.set_response("curl-200-transcript");
    assert_completed(
        run_curl_with_headers(&args, &["X-Inert-Curl: 200".to_string()])
            .expect("run fake curl 200"),
    );
    let argv = env.argv();
    assert_argv_contains_in_order(&argv, &[URL, "-H", "X-Inert-Curl: 200", "-D", "-o"]);
    assert_arg_occurs_once(&argv, "X-Inert-Curl: 200");

    env.set_response("curl-402");
    assert_unknown_402(
        run_curl_with_headers(&args, &["X-Inert-Curl: 402".to_string()])
            .expect("run fake curl 402"),
        "curl-402",
    );
    let argv = env.argv();
    assert_argv_contains_in_order(&argv, &[URL, "-H", "X-Inert-Curl: 402", "-D", "-o"]);
    assert_arg_occurs_once(&argv, "X-Inert-Curl: 402");
}

#[test]
fn wget_wrapper_classifies_scripted_200_and_402_and_injects_headers() {
    let env = TestEnvironment::new();
    let args = vec![URL.to_string()];

    env.set_response("wget-200-transcript");
    assert_completed(
        run_wget_with_headers(&args, &["X-Inert-Wget: 200".to_string()])
            .expect("run fake wget 200"),
    );
    let argv = env.argv();
    assert_argv_contains_in_order(
        &argv,
        &["--server-response", URL, "--header", "X-Inert-Wget: 200"],
    );
    assert_arg_occurs_once(&argv, "X-Inert-Wget: 200");

    env.set_response("wget-402");
    assert_unknown_402(
        run_wget_with_headers(&args, &["X-Inert-Wget: 402".to_string()])
            .expect("run fake wget 402"),
        "wget-402",
    );
    let argv = env.argv();
    assert_argv_contains_in_order(
        &argv,
        &["--server-response", URL, "--header", "X-Inert-Wget: 402"],
    );
    assert_arg_occurs_once(&argv, "X-Inert-Wget: 402");
}

#[test]
fn httpie_wrapper_keeps_a_200_body_transcript_completed_and_classifies_real_402() {
    let env = TestEnvironment::new();
    let args = vec!["GET".to_string(), URL.to_string()];

    // This body includes a complete, plausible 402 transcript. The outer
    // response is 200, so treating the body as a second response would be a
    // false payment prompt.
    env.set_response("httpie-200-body-transcript");
    assert_completed(
        run_httpie_with_headers(&args, &["X-Inert-HTTPie: 200".to_string()])
            .expect("run fake HTTPie 200"),
    );
    let argv = env.argv();
    assert_argv_contains_in_order(&argv, &["GET", URL, "X-Inert-HTTPie: 200", "--print=hb"]);
    assert_arg_occurs_once(&argv, "X-Inert-HTTPie: 200");
    assert_arg_occurs_once(&argv, "--print=hb");

    env.set_response("httpie-402");
    assert_unknown_402(
        run_httpie_with_headers(&args, &["X-Inert-HTTPie: 402".to_string()])
            .expect("run fake HTTPie 402"),
        "httpie-402",
    );
    let argv = env.argv();
    assert_argv_contains_in_order(&argv, &["GET", URL, "X-Inert-HTTPie: 402", "--print=hb"]);
    assert_arg_occurs_once(&argv, "X-Inert-HTTPie: 402");
    assert_arg_occurs_once(&argv, "--print=hb");
}

const CURL_FAKE: &str = r#"#!/bin/sh
: > "$PAY_TEST_ARGV"
for arg in "$@"; do
  printf '%s\n' "$arg" >> "$PAY_TEST_ARGV"
done
headers=''
body=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    -D) headers="$2"; shift 2 ;;
    -o) body="$2"; shift 2 ;;
    *) shift ;;
  esac
done
case "$PAY_TEST_RESPONSE" in
  curl-200-transcript)
    printf 'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\n' > "$headers"
    printf '%s\n' 'HTTP/1.1 402 Payment Required' 'WWW-Authenticate: Payment realm="offline"' '' '{"error":"payment required"}' > "$body"
    ;;
  curl-402)
    printf 'HTTP/1.1 402 Payment Required\r\nX-Pay-Test: curl-402\r\n\r\n' > "$headers"
    : > "$body"
    ;;
  *) exit 97 ;;
esac
"#;

const WGET_FAKE: &str = r#"#!/bin/sh
: > "$PAY_TEST_ARGV"
for arg in "$@"; do
  printf '%s\n' "$arg" >> "$PAY_TEST_ARGV"
done
case "$PAY_TEST_RESPONSE" in
  wget-200-transcript)
    printf '%s\n' 'HTTP/1.1 200 OK' 'Content-Type: text/plain' '' >&2
    printf '%s\n' 'HTTP/1.1 402 Payment Required' 'X-Pay-Test: body-only'
    ;;
  wget-402)
    printf '%s\n' 'HTTP/1.1 402 Payment Required' 'X-Pay-Test: wget-402' '' >&2
    ;;
  *) exit 97 ;;
esac
"#;

const HTTPIE_FAKE: &str = r#"#!/bin/sh
: > "$PAY_TEST_ARGV"
for arg in "$@"; do
  printf '%s\n' "$arg" >> "$PAY_TEST_ARGV"
done
case "$PAY_TEST_RESPONSE" in
  httpie-200-body-transcript)
    printf '%s\n' 'HTTP/1.1 200 OK' 'Content-Type: text/plain' '' 'captured upstream transcript:' 'HTTP/1.1 402 Payment Required' 'WWW-Authenticate: Payment realm="offline"' '' '{"error":"payment required"}'
    ;;
  httpie-402)
    printf '%s\n' 'HTTP/1.1 402 Payment Required' 'X-Pay-Test: httpie-402' ''
    ;;
  *) exit 97 ;;
esac
"#;

const WHICH_FAKE: &str = r#"#!/bin/sh
case "$1" in
  curl|wget|http) exit 0 ;;
  *) exit 1 ;;
esac
"#;
