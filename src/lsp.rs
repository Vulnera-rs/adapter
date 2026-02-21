use crate::code_actions::build_code_actions;
use crate::config::Config;
use crate::state::{DocumentSnapshot, ServerState};
use std::sync::Arc;
use tower_lsp::jsonrpc::Result;
use tower_lsp::lsp_types::{
    CodeActionOptions, CodeActionOrCommand, CodeActionProviderCapability, CodeActionResponse,
    InitializeParams, InitializeResult, InitializedParams, MessageType, SaveOptions,
    ServerCapabilities, TextDocumentContentChangeEvent, TextDocumentSyncCapability,
    TextDocumentSyncKind, TextDocumentSyncOptions,
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
            text_document_sync: Some(TextDocumentSyncCapability::Options(
                TextDocumentSyncOptions {
                    open_close: Some(true),
                    change: Some(TextDocumentSyncKind::INCREMENTAL),
                    will_save: None,
                    will_save_wait_until: None,
                    save: Some(
                        tower_lsp::lsp_types::TextDocumentSyncSaveOptions::SaveOptions(
                            SaveOptions {
                                include_text: Some(true),
                            },
                        ),
                    ),
                },
            )),
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
                version: Some(env!("CARGO_PKG_VERSION").to_string()),
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
        let previous = self.state.document_snapshot(&uri);
        let mut text = previous
            .as_ref()
            .map(|doc| doc.text.clone())
            .unwrap_or_default();

        if let Err(err) = apply_content_changes(&mut text, &params.content_changes) {
            self.client
                .log_message(
                    MessageType::WARNING,
                    format!(
                        "Failed to apply incremental change for {}: {}. Falling back to last full text.",
                        uri, err
                    ),
                )
                .await;
            text = params
                .content_changes
                .last()
                .map(|change| change.text.clone())
                .unwrap_or(text);
        }

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
        let name = name.to_ascii_lowercase();

        if name.ends_with("package.json")
            || name.ends_with("package-lock.json")
            || name.ends_with("yarn.lock")
            || name.ends_with("pnpm-lock.yaml")
        {
            return "npm".to_string();
        }
        if name.ends_with("requirements.txt")
            || name.ends_with("pyproject.toml")
            || name.ends_with("pipfile")
            || name.ends_with("pipfile.lock")
            || name.ends_with("poetry.lock")
            || name.ends_with("uv.lock")
        {
            return "pypi".to_string();
        }
        if name.ends_with("cargo.toml") || name.ends_with("cargo.lock") {
            return "cargo".to_string();
        }
        if name.ends_with("go.mod") || name.ends_with("go.sum") {
            return "go".to_string();
        }
        if name.ends_with("pom.xml")
            || name.ends_with("build.gradle")
            || name.ends_with("build.gradle.kts")
            || name.ends_with("gradle.lockfile")
        {
            return "maven".to_string();
        }
        if name.ends_with("composer.json") || name.ends_with("composer.lock") {
            return "packagist".to_string();
        }
    }

    if file_name.is_none()
        && let Some(language_id) = language_id
    {
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

    "unknown".to_string()
}

fn apply_content_changes(
    text: &mut String,
    changes: &[TextDocumentContentChangeEvent],
) -> std::result::Result<(), String> {
    for change in changes {
        if let Some(range) = change.range {
            let start = position_to_offset_utf16(text, range.start)
                .ok_or_else(|| format!("Invalid start position: {:?}", range.start))?;
            let end = position_to_offset_utf16(text, range.end)
                .ok_or_else(|| format!("Invalid end position: {:?}", range.end))?;

            if start > end || end > text.len() {
                return Err(format!(
                    "Invalid edit range offsets: start={}, end={}, len={}",
                    start,
                    end,
                    text.len()
                ));
            }

            text.replace_range(start..end, &change.text);
        } else {
            *text = change.text.clone();
        }
    }

    Ok(())
}

fn position_to_offset_utf16(text: &str, position: tower_lsp::lsp_types::Position) -> Option<usize> {
    let target_line = position.line as usize;
    let target_col = position.character as usize;

    let mut line_start = 0usize;
    for _ in 0..target_line {
        let rel_newline = text[line_start..].find('\n')?;
        line_start += rel_newline + 1;
    }

    let line_slice = &text[line_start..];
    let line_end_rel = line_slice.find('\n').unwrap_or(line_slice.len());
    let line_content = &line_slice[..line_end_rel];

    let mut utf16_col = 0usize;
    for (idx, ch) in line_content.char_indices() {
        if utf16_col == target_col {
            return Some(line_start + idx);
        }
        utf16_col += ch.len_utf16();
        if utf16_col > target_col {
            return None;
        }
    }

    if utf16_col == target_col {
        Some(line_start + line_end_rel)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::apply_content_changes;
    use tower_lsp::lsp_types::{Position, Range, TextDocumentContentChangeEvent};

    #[test]
    fn applies_incremental_range_change() {
        let mut text = "dependencies:\nlodash=4.17.20\n".to_string();
        let changes = vec![TextDocumentContentChangeEvent {
            range: Some(Range {
                start: Position::new(1, 7),
                end: Position::new(1, 14),
            }),
            range_length: None,
            text: "5.0.0".to_string(),
        }];

        apply_content_changes(&mut text, &changes).expect("change should apply");
        assert_eq!(text, "dependencies:\nlodash=5.0.0\n");
    }

    #[test]
    fn applies_full_document_change() {
        let mut text = "old".to_string();
        let changes = vec![TextDocumentContentChangeEvent {
            range: None,
            range_length: None,
            text: "new".to_string(),
        }];

        apply_content_changes(&mut text, &changes).expect("full sync should apply");
        assert_eq!(text, "new");
    }
}
