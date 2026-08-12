//! Strict CSV parsing and canonical manifests for `pay push`.

use std::collections::HashMap;
use std::io::{Cursor, Read};
use std::str::FromStr;

use solana_pubkey::Pubkey;

use crate::client::send::parse_token_amount;
use crate::{Error, Result};

/// Upper bound on a single batch. This prevents a malformed input from using
/// unbounded memory before the user has reviewed or authorized the payout.
pub const MAX_TRANSFER_ROWS: usize = 100_000;

/// A valid 100k-row CSV is well below this limit. Keep the pre-authorization
/// parser bounded even when a malformed input contains one enormous record.
pub const MAX_CSV_BYTES: usize = 16 * 1024 * 1024;

const MANIFEST_VERSION: &[u8] = b"pay-push:v1";

/// On-chain properties that bind a parsed CSV to one precise payout plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestContext {
    /// The network's genesis hash, not a human-readable network alias.
    pub network_genesis_hash: [u8; 32],
    pub mint: Pubkey,
    pub token_program: Pubkey,
    pub decimals: u8,
}

/// One normalized, ordered payout row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferRow {
    /// One-based logical CSV record number; the header occupies record one.
    pub row_number: u64,
    pub recipient: Pubkey,
    pub amount_raw: u64,
}

/// The complete, normalized batch that the authorization and journal bind to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferManifest {
    pub context: ManifestContext,
    pub rows: Vec<TransferRow>,
    pub total_amount_raw: u64,
    /// BLAKE3 digest of the exact normalized plan.
    pub hash: [u8; 32],
}

impl TransferManifest {
    pub fn hash_hex(&self) -> String {
        self.hash.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

/// Parse RFC 4180 CSV input into a strictly validated, canonical manifest.
///
/// The input must contain exactly the `recipient` and `amount` headers (in
/// either order). Amounts are converted into raw mint units, so differences in
/// harmless CSV representation (such as CRLF) do not affect the manifest.
pub fn parse_manifest_csv<R: Read>(
    mut reader: R,
    context: ManifestContext,
) -> Result<TransferManifest> {
    let mut input = Vec::new();
    reader
        .by_ref()
        .take((MAX_CSV_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    if input.len() > MAX_CSV_BYTES {
        return Err(Error::Config(format!(
            "CSV exceeds the {} MiB size limit",
            MAX_CSV_BYTES / (1024 * 1024)
        )));
    }
    reject_empty_records(&input)?;
    let mut csv = csv::ReaderBuilder::new()
        .has_headers(false)
        .flexible(false)
        .from_reader(Cursor::new(input));
    let mut records = csv.records();

    let header = records
        .next()
        .transpose()
        .map_err(csv_error)?
        .ok_or_else(|| Error::Config("CSV must contain a header row".to_string()))?;
    let (recipient_column, amount_column) = parse_header(&header)?;

    let mut rows = Vec::new();
    let mut recipient_lines = HashMap::new();
    let mut total_amount_raw = 0u64;

    for record in records {
        let record = record.map_err(csv_error)?;
        // A logical record is more useful than a byte/physical-line offset:
        // RFC 4180 permits quoted fields to contain newlines, and the csv
        // crate reports CRLF and LF positions differently. The header is
        // record one, so the first payout is consistently row two.
        let row_number = (rows.len() + 2) as u64;
        if rows.len() == MAX_TRANSFER_ROWS {
            return Err(Error::Config(format!(
                "CSV exceeds the {MAX_TRANSFER_ROWS}-row limit (line {row_number})"
            )));
        }
        if record.len() != 2 {
            return Err(Error::Config(format!(
                "CSV line {row_number} must contain exactly recipient and amount"
            )));
        }

        let recipient_input = record.get(recipient_column).unwrap_or_default();
        let amount_input = record.get(amount_column).unwrap_or_default();
        require_nonempty_unpadded(recipient_input, row_number, "recipient")?;
        require_nonempty_unpadded(amount_input, row_number, "amount")?;

        let recipient = Pubkey::from_str(recipient_input).map_err(|error| {
            Error::Config(format!(
                "CSV line {row_number} has invalid recipient: {error}"
            ))
        })?;
        if let Some(first_line) = recipient_lines.insert(recipient, row_number) {
            return Err(Error::Config(format!(
                "CSV line {row_number} recipient duplicates line {first_line}"
            )));
        }

        let amount_raw = parse_token_amount(amount_input, context.decimals).map_err(|error| {
            Error::Config(format!("CSV line {row_number} has invalid amount: {error}"))
        })?;
        if amount_raw == 0 {
            return Err(Error::Config(format!(
                "CSV line {row_number} amount must be positive"
            )));
        }
        total_amount_raw = total_amount_raw
            .checked_add(amount_raw)
            .ok_or_else(|| Error::Config(format!("CSV total exceeds u64 at line {row_number}")))?;
        rows.push(TransferRow {
            row_number,
            recipient,
            amount_raw,
        });
    }

    if rows.is_empty() {
        return Err(Error::Config(
            "CSV must contain at least one payout row".to_string(),
        ));
    }

    let hash = canonical_hash(&context, &rows);
    Ok(TransferManifest {
        context,
        rows,
        total_amount_raw,
        hash,
    })
}

fn parse_header(header: &csv::StringRecord) -> Result<(usize, usize)> {
    if header.len() != 2 {
        return Err(Error::Config(
            "CSV header must contain exactly `recipient,amount`".to_string(),
        ));
    }

    let mut recipient_column = None;
    let mut amount_column = None;
    for (index, name) in header.iter().enumerate() {
        let name = if index == 0 {
            name.strip_prefix('\u{feff}').unwrap_or(name)
        } else {
            name
        };
        match name {
            "recipient" if recipient_column.replace(index).is_none() => {}
            "amount" if amount_column.replace(index).is_none() => {}
            "recipient" | "amount" => {
                return Err(Error::Config(format!(
                    "CSV header has duplicate `{name}` column"
                )));
            }
            _ => {
                return Err(Error::Config(format!(
                    "CSV header has unknown `{name}` column"
                )));
            }
        }
    }

    match (recipient_column, amount_column) {
        (Some(recipient), Some(amount)) => Ok((recipient, amount)),
        _ => Err(Error::Config(
            "CSV header must contain both `recipient` and `amount` columns".to_string(),
        )),
    }
}

fn require_nonempty_unpadded(value: &str, row_number: u64, field: &str) -> Result<()> {
    if value.is_empty() {
        return Err(Error::Config(format!(
            "CSV line {row_number} {field} must not be empty"
        )));
    }
    if value.trim() != value {
        return Err(Error::Config(format!(
            "CSV line {row_number} {field} must not contain leading or trailing whitespace"
        )));
    }
    Ok(())
}

/// The csv crate intentionally skips blank records. A payout input must not:
/// otherwise an accidentally deleted record would be silently accepted. Scan
/// just enough RFC 4180 quoting state to distinguish a blank line from a
/// newline contained in a quoted field.
fn reject_empty_records(input: &[u8]) -> Result<()> {
    let mut line = 1u64;
    let mut index = 0;
    let mut in_quotes = false;
    let mut record_has_content = false;

    while index < input.len() {
        let byte = input[index];
        if in_quotes {
            if byte == b'"' {
                if input.get(index + 1) == Some(&b'"') {
                    index += 2;
                    continue;
                }
                in_quotes = false;
            }
            index += 1;
            continue;
        }

        if byte == b'"' {
            in_quotes = true;
            record_has_content = true;
            index += 1;
            continue;
        }
        if byte == b'\r' || byte == b'\n' {
            if !record_has_content {
                return Err(Error::Config(format!(
                    "CSV has an empty record at line {line}"
                )));
            }
            record_has_content = false;
            line += 1;
            index += usize::from(byte == b'\r' && input.get(index + 1) == Some(&b'\n')) + 1;
            continue;
        }

        record_has_content = true;
        index += 1;
    }
    Ok(())
}

fn canonical_hash(context: &ManifestContext, rows: &[TransferRow]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hash_part(&mut hasher, MANIFEST_VERSION);
    hash_part(&mut hasher, &context.network_genesis_hash);
    hash_part(&mut hasher, context.mint.as_ref());
    hash_part(&mut hasher, context.token_program.as_ref());
    hash_part(&mut hasher, &[context.decimals]);
    hash_part(&mut hasher, &(rows.len() as u64).to_le_bytes());
    for row in rows {
        hash_part(&mut hasher, row.recipient.as_ref());
        hash_part(&mut hasher, &row.amount_raw.to_le_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn hash_part(hasher: &mut blake3::Hasher, value: &[u8]) {
    hasher.update(&(value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn csv_error(error: csv::Error) -> Error {
    Error::Config(format!("Invalid CSV: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ManifestContext {
        ManifestContext {
            network_genesis_hash: [7; 32],
            mint: Pubkey::new_from_array([8; 32]),
            token_program: Pubkey::new_from_array([9; 32]),
            decimals: 6,
        }
    }

    fn recipient(seed: u8) -> String {
        Pubkey::new_from_array([seed; 32]).to_string()
    }

    fn parse(input: &str) -> Result<TransferManifest> {
        parse_manifest_csv(input.as_bytes(), context())
    }

    #[test]
    fn parses_bom_quoted_csv_and_preserves_order() {
        let first = recipient(1);
        let second = recipient(2);
        let manifest = parse(&format!(
            "\u{feff}amount,recipient\r\n\"1.25\",\"{first}\"\r\n0.000001,{second}\r\n"
        ))
        .unwrap();

        assert_eq!(manifest.rows.len(), 2);
        assert_eq!(manifest.rows[0].row_number, 2);
        assert_eq!(manifest.rows[0].recipient.to_string(), first);
        assert_eq!(manifest.rows[0].amount_raw, 1_250_000);
        assert_eq!(manifest.rows[1].recipient.to_string(), second);
        assert_eq!(manifest.rows[1].amount_raw, 1);
        assert_eq!(manifest.total_amount_raw, 1_250_001);
    }

    #[test]
    fn canonical_hash_ignores_crlf_and_csv_quoting() {
        let first = recipient(1);
        let second = recipient(2);
        let unix = parse(&format!("recipient,amount\n{first},1.25\n{second},2\n")).unwrap();
        let windows = parse(&format!(
            "amount,recipient\r\n\"1.25\",\"{first}\"\r\n2,{second}\r\n"
        ))
        .unwrap();
        assert_eq!(unix.hash, windows.hash);
    }

    #[test]
    fn canonical_hash_changes_when_row_order_changes() {
        let first = recipient(1);
        let second = recipient(2);
        let ordered = parse(&format!("recipient,amount\n{first},1\n{second},2\n")).unwrap();
        let reversed = parse(&format!("recipient,amount\n{second},2\n{first},1\n")).unwrap();
        assert_ne!(ordered.hash, reversed.hash);
    }

    #[test]
    fn rejects_duplicate_recipients_with_both_lines() {
        let address = recipient(1);
        let error = parse(&format!("recipient,amount\n{address},1\n{address},2\n"))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("line 3 recipient duplicates line 2"),
            "{error}"
        );
    }

    #[test]
    fn rejects_invalid_headers_empty_fields_and_non_positive_amounts() {
        let address = recipient(1);
        for (input, expected) in [
            (format!("recipient,other\n{address},1\n"), "unknown `other`"),
            (
                format!("recipient,amount\n,1\n"),
                "line 2 recipient must not be empty",
            ),
            (
                format!("recipient,amount\n{address},0\n"),
                "line 2 amount must be positive",
            ),
            (
                format!("recipient,amount\n{address},1.0000001\n"),
                "line 2 has invalid amount",
            ),
        ] {
            let error = parse(&input).unwrap_err().to_string();
            assert!(
                error.contains(expected),
                "expected {expected:?}, got {error:?}"
            );
        }
    }

    #[test]
    fn rejects_blank_records_but_allows_newlines_in_quoted_fields() {
        let first = recipient(1);
        let second = recipient(2);
        let blank = parse(&format!("recipient,amount\n{first},1\n\n{second},2\n"))
            .unwrap_err()
            .to_string();
        assert!(blank.contains("empty record at line 3"), "{blank}");

        let quoted_newline = parse(&format!("recipient,amount\n\"{first}\",\"1\n\"\n"))
            .unwrap_err()
            .to_string();
        assert!(
            quoted_newline.contains("amount must not contain leading or trailing whitespace"),
            "{quoted_newline}"
        );
    }
}
