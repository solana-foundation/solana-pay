//! CLI transport and Buzz publisher for the reusable `pay-acp` tracker.

use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;

use pay_acp::{BuzzDelivery, BuzzDeliveryTracker};

const BUZZ_RELAY_URL_ENV: &str = "BUZZ_RELAY_URL";
const BUZZ_PRIVATE_KEY_ENV: &str = "BUZZ_PRIVATE_KEY";

/// Whether this ACP launch has the credentials needed to publish as a
/// Buzz-managed agent.
pub(super) fn buzz_delivery_available() -> bool {
    nonempty_env(BUZZ_RELAY_URL_ENV) && nonempty_env(BUZZ_PRIVATE_KEY_ENV)
}

fn nonempty_env(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| !value.trim().is_empty())
}

/// Run an ACP child with stdin/stdout relayed byte-for-byte while observing
/// complete NDJSON frames for Buzz delivery state.
pub(super) fn run(mut command: Command) -> io::Result<i32> {
    let mut child = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| io::Error::other("ACP child stdin was not piped"))?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("ACP child stdout was not piped"))?;

    let tracker = Arc::new(Mutex::new(BuzzDeliveryTracker::default()));
    let input_tracker = Arc::clone(&tracker);
    thread::spawn(move || relay_client_input(io::stdin(), child_stdin, input_tracker));

    relay_agent_output(child_stdout, io::stdout(), tracker)?;
    let status = child.wait()?;
    Ok(status.code().unwrap_or(1))
}

fn relay_client_input<R: Read, W: Write>(
    input: R,
    mut child_stdin: W,
    tracker: Arc<Mutex<BuzzDeliveryTracker>>,
) {
    let mut reader = BufReader::new(input);
    let mut frame = Vec::new();
    loop {
        frame.clear();
        match reader.read_until(b'\n', &mut frame) {
            Ok(0) => break,
            Ok(_) => {
                lock_tracker(&tracker).observe_client_frame(&frame);
                if child_stdin.write_all(&frame).is_err() || child_stdin.flush().is_err() {
                    break;
                }
            }
            Err(error) => {
                tracing::warn!(%error, "Pay ACP middleware could not read client input");
                break;
            }
        }
    }
}

fn relay_agent_output<R: Read, W: Write>(
    output: R,
    destination: W,
    tracker: Arc<Mutex<BuzzDeliveryTracker>>,
) -> io::Result<()> {
    let mut reader = BufReader::new(output);
    let mut destination = BufWriter::new(destination);
    let mut frame = Vec::new();
    loop {
        frame.clear();
        if reader.read_until(b'\n', &mut frame)? == 0 {
            break;
        }

        let delivery = lock_tracker(&tracker).observe_agent_frame(&frame);
        if let Some(delivery) = delivery {
            publish_fallback(&delivery);
        }

        destination.write_all(&frame)?;
        destination.flush()?;
    }
    Ok(())
}

fn lock_tracker(tracker: &Arc<Mutex<BuzzDeliveryTracker>>) -> MutexGuard<'_, BuzzDeliveryTracker> {
    tracker
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn publish_fallback(delivery: &BuzzDelivery) {
    let mut command = Command::new("buzz");
    command
        .args(["messages", "send", "--channel", &delivery.channel])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(reply_to) = delivery.reply_to.as_deref() {
        command.args(["--reply-to", reply_to]);
    }
    command.args(["--content", "-"]);

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            tracing::warn!(%error, "Pay ACP fallback could not launch `buzz messages send`");
            return;
        }
    };
    let write_error = child
        .stdin
        .take()
        .and_then(|mut stdin| stdin.write_all(delivery.content.as_bytes()).err());
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => {
            tracing::warn!(%error, "Pay ACP fallback could not wait for `buzz messages send`");
            return;
        }
    };
    if let Some(error) = write_error {
        tracing::warn!(%error, "Pay ACP fallback could not write message content");
    } else if output.status.success() {
        tracing::info!(
            channel = %delivery.channel,
            reply_to = ?delivery.reply_to,
            "Pay ACP published assistant text to Buzz"
        );
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::warn!(
            status = ?output.status.code(),
            error = %stderr.trim(),
            "Pay ACP fallback `buzz messages send` failed"
        );
    }
}
