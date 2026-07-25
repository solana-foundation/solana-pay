//! Small dependency-free ASCII table renderer for human CLI diagnostics.
//!
//! Tables use at most 78 columns, leaving room for a two-column notice rail.

use super::terminal::sanitize_terminal_text;

const MAX_TABLE_WIDTH: usize = 78;
const MAX_CELL_WIDTH: usize = 48;

/// Render an untitled table suitable for embedding directly in a notice body.
pub(crate) fn render_table(headers: &[&str], rows: &[Vec<String>]) -> String {
    debug_assert!(!headers.is_empty());
    debug_assert!(rows.iter().all(|row| row.len() == headers.len()));

    let widths = column_widths(headers, rows);
    let rule = rule(&widths);
    let mut output = String::with_capacity(rows.len() * 96);
    output.push_str(&rule);
    output.push('\n');
    push_line(
        &mut output,
        headers.iter().map(|header| (*header).to_string()),
        &widths,
    );
    output.push_str(&rule);
    output.push('\n');
    for row in rows {
        push_line(&mut output, row.iter().cloned(), &widths);
    }
    output.push_str(&rule);
    output
}

fn column_widths(headers: &[&str], rows: &[Vec<String>]) -> Vec<usize> {
    let mut widths: Vec<usize> = headers.iter().map(|header| display_width(header)).collect();
    for row in rows {
        for (index, cell) in row.iter().enumerate() {
            widths[index] = widths[index].max(display_width(cell).min(MAX_CELL_WIDTH));
        }
    }

    while table_width(&widths) > MAX_TABLE_WIDTH {
        let Some((index, _)) = widths
            .iter()
            .enumerate()
            .filter(|(index, width)| **width > display_width(headers[*index]))
            .max_by_key(|(_, width)| **width)
        else {
            break;
        };
        widths[index] -= 1;
    }
    widths
}

fn table_width(widths: &[usize]) -> usize {
    widths.iter().sum::<usize>() + widths.len() * 3 + 1
}

fn rule(widths: &[usize]) -> String {
    let mut rule = String::from("+");
    for width in widths {
        rule.push_str(&"-".repeat(*width + 2));
        rule.push('+');
    }
    rule
}

fn push_line<I>(output: &mut String, cells: I, widths: &[usize])
where
    I: IntoIterator<Item = String>,
{
    output.push('|');
    for (index, cell) in cells.into_iter().enumerate() {
        let cell = abbreviate(&cell, widths[index]);
        output.push(' ');
        output.push_str(&cell);
        output.push_str(&" ".repeat(widths[index].saturating_sub(display_width(&cell)) + 1));
        output.push('|');
    }
    output.push('\n');
}

fn abbreviate(value: &str, width: usize) -> String {
    let value = sanitize_terminal_text(value);
    if display_width(&value) <= width {
        return value;
    }
    if width <= 3 {
        return value.chars().take(width).collect();
    }
    format!("{}...", value.chars().take(width - 3).collect::<String>())
}

fn display_width(value: &str) -> usize {
    value.chars().count()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_headers_rows_and_abbreviated_values_within_80_columns() {
        let table = render_table(
            &["Field", "Value"],
            &[vec!["challenge.amount".to_string(), "x".repeat(100)]],
        );

        assert!(table.starts_with('+'));
        assert!(table.contains("| Field"));
        assert!(table.contains("challenge.amount"));
        assert!(table.contains("..."));
        assert!(table.lines().all(|line| display_width(line) <= 80));
        assert_eq!(
            table.lines().filter(|line| line.starts_with('+')).count(),
            3
        );
    }

    #[test]
    fn strips_terminal_controls_from_cells_before_rendering() {
        let table = render_table(
            &["Field"],
            &[vec![
                "safe\u{1b}]8;;https://evil.example\u{1b}\\text\u{7}".to_string(),
            ]],
        );

        assert!(!table.contains('\u{1b}'));
        assert!(!table.contains('\u{7}'));
        assert!(table.contains("safe]8;;https://evil.example\\text"));
    }
}
