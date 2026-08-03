pub mod create_skill;
pub mod curl;
pub mod get_balance;
pub mod get_catalog_entry;
pub mod list_catalog;
pub mod request_capability;
pub mod search_catalog;
pub mod topup;

pub(crate) fn tool_error(message: impl Into<String>) -> rmcp::model::CallToolResult {
    rmcp::model::CallToolResult::error(vec![rmcp::model::ContentBlock::text(message.into())])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_error_returns_visible_error_content() {
        let result = tool_error("visible failure");

        assert_eq!(result.is_error, Some(true));
        assert_eq!(result.content[0].as_text().unwrap().text, "visible failure");
    }
}
