use crate::code_actions::build_code_actions;
use crate::config::Config;
use crate::state::{DocumentSnapshot, ServerState};
use std::sync::Arc;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::{
    CodeActionOptions, CodeActionOrCommand, CodeActionProviderCapability, CodeActionResponse,
    InitializeParams, InitializeResult, InitializedParams, MessageType, ServerCapabilities,
    TextDocumentSyncCapability, TextDocumentSyncKind,
};
use tower_lsp::{Client, LanguageServer};

#[derive(Clone)]
pub struct VulneraLanguageServer {
    client: Client,
    state: Arc<ServerState>,
}

impl VulneraLanguageServer {
    pub fn new(client: Client, config: Config) -> Self {
        let state = Arc::new(ServerState::new(client.clone(), config));
        Self { client, state }
    }
}

#[tower_lsp::async_trait]
impl LanguageServer for VulneraLanguageServer {
    async fn initialize(&self, params: InitializeParams) -> Result<InitializeResult> {
        let config = Config::from_env().apply_initialize_options(params.initialization_options);
        self.state.update_config(config).await;

        let capabilities = ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
            code_action_provider: Some(CodeActionProviderCapability::Options(CodeActionOptions {
                code_action_kinds: Some(vec![tower_lsp::lsp_types::CodeActionKind::QUICKFIX]),
                work_done_progress_options: Default::default(),
                resolve_provider: Some(false),
            })),
            ..ServerCapabilities::default()
        };

        Ok(InitializeResult {
            capabilities,
            server_info: Some(tower_lsp::lsp_types::ServerInfo {
                name: "Vulnera Dependency LSP".to_string(),
                version: Some("0.1.0".to_string()),
            }),
        })
    }

    async fn initialized(&self, _: InitializedParams) {
        self.client
            .log_message(MessageType::INFO, "Vulnera LSP initialized")
            .await;
    }

    async fn shutdown(&self) -> Result<()> {
        Ok(())
    }

    async fn did_open(&self, params: tower_lsp::lsp_types::DidOpenTextDocumentParams) {
        let doc = params.text_document;
        let uri = doc.uri.clone();
        let file_name = uri
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .map(|s| s.to_string());
        let language_id = doc.language_id.clone();
        let ecosystem = detect_ecosystem(&file_name, Some(language_id.as_str()));

        self.state.upsert_document(DocumentSnapshot {
            uri: uri.clone(),
            text: doc.text.clone(),
            version: doc.version,
            language_id: Some(language_id),
            file_name: file_name.clone(),
            workspace_path: Some(uri.path().to_string()),
            ecosystem,
        });

        let state = Arc::clone(&self.state);
        state.schedule_analysis(uri).await;
    }

    async fn did_change(&self, params: tower_lsp::lsp_types::DidChangeTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        let version = params.text_document.version;
        let text = params
            .content_changes
            .last()
            .map(|change| change.text.clone())
            .unwrap_or_default();

        let previous = self.state.document_snapshot(&uri);
        let file_name = uri
            .path_segments()
            .and_then(|mut segments| segments.next_back())
            .map(|s| s.to_string());
        let language_id = previous.as_ref().and_then(|doc| doc.language_id.clone());
        let ecosystem = detect_ecosystem(&file_name, language_id.as_deref());

        self.state.upsert_document(DocumentSnapshot {
            uri: uri.clone(),
            text,
            version,
            language_id,
            file_name: file_name.clone(),
            workspace_path: Some(uri.path().to_string()),
            ecosystem,
        });

        let state = Arc::clone(&self.state);
        state.schedule_analysis(uri).await;
    }

    async fn did_save(&self, params: tower_lsp::lsp_types::DidSaveTextDocumentParams) {
        let uri = params.text_document.uri.clone();
        if let Some(text) = params.text {
            let previous = self.state.document_snapshot(&uri);
            let version = previous.as_ref().map(|doc| doc.version).unwrap_or_default();
            let file_name = uri
                .path_segments()
                .and_then(|mut segments| segments.next_back())
                .map(|s| s.to_string());
            let language_id = previous.as_ref().and_then(|doc| doc.language_id.clone());
            let ecosystem = detect_ecosystem(&file_name, language_id.as_deref());
            self.state.upsert_document(DocumentSnapshot {
                uri: uri.clone(),
                text,
                version,
                language_id,
                file_name: file_name.clone(),
                workspace_path: Some(uri.path().to_string()),
                ecosystem,
            });
        }

        let state = Arc::clone(&self.state);
        state.schedule_analysis(uri).await;
    }

    async fn did_close(&self, params: tower_lsp::lsp_types::DidCloseTextDocumentParams) {
        let uri = params.text_document.uri;
        self.state.remove_document(&uri);
        self.client.publish_diagnostics(uri, vec![], None).await;
    }

    async fn code_action(
        &self,
        params: tower_lsp::lsp_types::CodeActionParams,
    ) -> Result<Option<CodeActionResponse>> {
        let uri = params.text_document.uri;
        let Some(analysis) = self.state.analysis_for(&uri) else {
            return Ok(Some(Vec::new()));
        };

        let recommendations = analysis.result.version_recommendations.unwrap_or_default();
        let doc_text = self.state.document_text(&uri).unwrap_or_default();
        let diagnostics = analysis.diagnostics.clone();
        let language_id = self
            .state
            .document_snapshot(&uri)
            .and_then(|doc| doc.language_id)
            .as_deref()
            .map(|value| value.to_string());

        let actions = build_code_actions(
            &uri,
            &analysis.result.ecosystem,
            &doc_text,
            &recommendations,
            language_id.as_deref(),
        );

        let response: CodeActionResponse = actions
            .into_iter()
            .map(|mut action| {
                action.diagnostics = Some(diagnostics.clone());
                CodeActionOrCommand::CodeAction(action)
            })
            .collect();
        Ok(Some(response))
    }
}

fn detect_ecosystem(file_name: &Option<String>, language_id: Option<&str>) -> String {
    if let Some(name) = file_name.as_deref() {
        if name.ends_with("package.json")
            || name.ends_with("package-lock.json")
            || name.ends_with("yarn.lock")
        {
            return "npm".to_string();
        }
        if name.ends_with("requirements.txt")
            || name.ends_with("pyproject.toml")
            || name.ends_with("Pipfile")
        {
            return "pypi".to_string();
        }
        if name.ends_with("Cargo.toml") || name.ends_with("Cargo.lock") {
            return "cargo".to_string();
        }
        if name.ends_with("go.mod") || name.ends_with("go.sum") {
            return "go".to_string();
        }
        if name.ends_with("pom.xml")
            || name.ends_with("build.gradle")
            || name.ends_with("build.gradle.kts")
        {
            return "maven".to_string();
        }
        if name.ends_with("composer.json") || name.ends_with("composer.lock") {
            return "packagist".to_string();
        }
    }

    if let Some(language_id) = language_id {
        match language_id {
            "javascript" | "typescript" => return "npm".to_string(),
            "python" => return "pypi".to_string(),
            "rust" => return "cargo".to_string(),
            "go" => return "go".to_string(),
            "java" | "kotlin" => return "maven".to_string(),
            "php" => return "packagist".to_string(),
            _ => {}
        }
    }

    "npm".to_string()
}
