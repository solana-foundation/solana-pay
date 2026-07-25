/// Pay client surface making an outbound HTTP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ClientApp {
    #[default]
    Cli,
    Mcp,
}

impl ClientApp {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Cli => "cli",
            Self::Mcp => "mcp",
        }
    }

    pub fn user_agent(self) -> String {
        format!("pay/{}/{}", self.name(), env!("CARGO_PKG_VERSION"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_user_agents_include_surface_and_version() {
        assert_eq!(
            ClientApp::Cli.user_agent(),
            format!("pay/cli/{}", env!("CARGO_PKG_VERSION"))
        );
        assert_eq!(
            ClientApp::Mcp.user_agent(),
            format!("pay/mcp/{}", env!("CARGO_PKG_VERSION"))
        );
    }
}
