#![forbid(unsafe_code)]

pub mod api;
pub mod code_actions;
pub mod config;
pub mod diagnostics;
mod lsp;
mod package_locator;
mod state;

pub use config::{Config, DetailLevel};
pub use lsp::VulneraLanguageServer;

use tower_lsp::{LspService, Server};

#[derive(thiserror::Error, Debug)]
pub enum AdapterError {
    #[error("LSP server error: {0}")]
    Server(String),
}

/// Run the LSP server over stdio. Intended to be hosted by IDE extensions.
pub async fn run_stdio(config: Config) -> Result<(), AdapterError> {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    let (service, socket) = LspService::new(|client| VulneraLanguageServer::new(client, config));
    Server::new(stdin, stdout, socket).serve(service).await;

    Ok(())
}
