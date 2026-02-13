use crate::api::{
    BatchDependencyAnalysisRequest, DependencyFileRequest, FileAnalysisResult, VulneraApiClient,
};
use crate::config::Config;
use crate::diagnostics::{build_analysis_failure_diagnostic, build_diagnostics};
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{Duration, sleep};
use tower_lsp::Client;
use tower_lsp::lsp_types::Url;

#[derive(Debug, Clone)]
pub struct DocumentSnapshot {
    pub uri: Url,
    pub text: String,
    pub version: i32,
    pub language_id: Option<String>,
    pub file_name: Option<String>,
    pub workspace_path: Option<String>,
    pub ecosystem: String,
}

#[derive(Debug, Clone)]
pub struct AnalysisCache {
    pub result: FileAnalysisResult,
    pub diagnostics: Vec<tower_lsp::lsp_types::Diagnostic>,
}

#[derive(Clone)]
pub struct ServerState {
    client: Client,
    config: Arc<RwLock<Config>>,
    http: Arc<RwLock<VulneraApiClient>>,
    documents: Arc<DashMap<Url, DocumentSnapshot>>,
    analysis: Arc<DashMap<Url, AnalysisCache>>,
    pending: Arc<DashMap<String, JoinHandle<()>>>,
    dirty_by_workspace: Arc<DashMap<String, HashSet<Url>>>,
}

impl ServerState {
    pub fn new(client: Client, config: Config) -> Self {
        let http = VulneraApiClient::new(
            config.api_url.clone(),
            config.api_key.clone(),
            &config.user_agent,
        )
        .expect("http client initialization");

        Self {
            client,
            config: Arc::new(RwLock::new(config)),
            http: Arc::new(RwLock::new(http)),
            documents: Arc::new(DashMap::new()),
            analysis: Arc::new(DashMap::new()),
            pending: Arc::new(DashMap::new()),
            dirty_by_workspace: Arc::new(DashMap::new()),
        }
    }

    pub async fn update_config(&self, next: Config) {
        {
            let mut config = self.config.write().await;
            *config = next.clone();
        }
        let http =
            VulneraApiClient::new(next.api_url.clone(), next.api_key.clone(), &next.user_agent)
                .expect("http client initialization");
        let mut http_guard = self.http.write().await;
        *http_guard = http;
    }

    pub fn upsert_document(&self, snapshot: DocumentSnapshot) {
        self.documents.insert(snapshot.uri.clone(), snapshot);
    }

    pub fn remove_document(&self, uri: &Url) {
        let workspace_key = self
            .documents
            .get(uri)
            .map(|doc| workspace_key_for_path(doc.workspace_path.as_deref(), uri));

        self.documents.remove(uri);
        self.analysis.remove(uri);

        if let Some(workspace_key) = workspace_key
            && let Some(mut entry) = self.dirty_by_workspace.get_mut(&workspace_key)
        {
            entry.remove(uri);
            if entry.is_empty() {
                drop(entry);
                self.dirty_by_workspace.remove(&workspace_key);
                if let Some((_, handle)) = self.pending.remove(&workspace_key) {
                    handle.abort();
                }
            }
        }
    }

    pub async fn schedule_analysis(self: Arc<Self>, uri: Url) {
        let workspace_key = match self.documents.get(&uri) {
            Some(snapshot) => {
                if snapshot.ecosystem == "unknown" {
                    self.analysis.remove(&uri);
                    self.client
                        .publish_diagnostics(uri.clone(), vec![], Some(snapshot.version))
                        .await;
                    return;
                }
                workspace_key_for_path(snapshot.workspace_path.as_deref(), &uri)
            }
            None => return,
        };

        self.dirty_by_workspace
            .entry(workspace_key.clone())
            .or_insert_with(HashSet::new)
            .insert(uri.clone());

        if let Some((_, handle)) = self.pending.remove(&workspace_key) {
            handle.abort();
        }

        let debounce_ms = { self.config.read().await.debounce_ms };
        let state = Arc::clone(&self);
        let workspace_key_for_task = workspace_key.clone();
        let handle = tokio::spawn(async move {
            sleep(Duration::from_millis(debounce_ms)).await;
            if let Err(err) = state
                .run_batch_analysis(workspace_key_for_task.clone())
                .await
            {
                let affected_documents = state
                    .documents
                    .iter()
                    .filter_map(|entry| {
                        let key =
                            workspace_key_for_path(entry.workspace_path.as_deref(), &entry.uri);
                        if key == workspace_key_for_task {
                            Some(entry.uri.clone())
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();

                for affected_uri in affected_documents {
                    if let Some(snapshot) = state.document_snapshot(&affected_uri) {
                        state
                            .client
                            .publish_diagnostics(
                                affected_uri,
                                vec![build_analysis_failure_diagnostic(&err)],
                                Some(snapshot.version),
                            )
                            .await;
                    }
                }

                state
                    .client
                    .show_message(
                        tower_lsp::lsp_types::MessageType::ERROR,
                        format!("Vulnera dependency analysis failed: {}", err),
                    )
                    .await;

                state
                    .client
                    .log_message(
                        tower_lsp::lsp_types::MessageType::ERROR,
                        format!("Dependency analysis failed: {}", err),
                    )
                    .await;
            }

            state.pending.remove(&workspace_key_for_task);
        });

        self.pending.insert(workspace_key, handle);
    }

    async fn run_batch_analysis(&self, workspace_key: String) -> Result<(), String> {
        let uris = self
            .dirty_by_workspace
            .remove(&workspace_key)
            .map(|(_, uris)| uris.into_iter().collect::<Vec<_>>())
            .unwrap_or_default();

        if uris.is_empty() {
            return Ok(());
        }

        let snapshots = uris
            .iter()
            .filter_map(|uri| self.documents.get(uri).map(|doc| doc.clone()))
            .filter(|snapshot| snapshot.ecosystem != "unknown")
            .collect::<Vec<_>>();

        if snapshots.is_empty() {
            return Ok(());
        }

        let snapshot_by_file_id: HashMap<String, DocumentSnapshot> = snapshots
            .iter()
            .map(|snapshot| (snapshot.uri.to_string(), snapshot.clone()))
            .collect();

        let config = self.config.read().await.clone();
        let request = BatchDependencyAnalysisRequest {
            files: snapshots
                .iter()
                .map(|snapshot| DependencyFileRequest {
                    file_id: Some(snapshot.uri.to_string()),
                    file_content: snapshot.text.clone(),
                    ecosystem: snapshot.ecosystem.clone(),
                    filename: snapshot.file_name.clone(),
                    workspace_path: snapshot.workspace_path.clone(),
                })
                .collect(),
            enable_cache: config.enable_cache,
            compact_mode: config.compact_mode,
        };

        let response = {
            let http = self.http.read().await;
            http.analyze_dependencies(config.detail_level, request)
                .await
                .map_err(|e| e.to_string())?
        };

        if let Some(request_id) = response.metadata.request_id.as_deref() {
            self.client
                .log_message(
                    tower_lsp::lsp_types::MessageType::INFO,
                    format!("Vulnera dependency batch request_id={}", request_id),
                )
                .await;
        }

        if response.results.len() != snapshots.len() {
            return Err(format!(
                "Batch response cardinality mismatch: requested {}, received {}",
                snapshots.len(),
                response.results.len()
            ));
        }

        let has_file_ids = response
            .results
            .iter()
            .all(|result| result.file_id.is_some());

        if has_file_ids {
            for result in response.results {
                let file_id = result
                    .file_id
                    .clone()
                    .ok_or_else(|| "Missing file_id in batch response".to_string())?;
                let snapshot = snapshot_by_file_id.get(&file_id).ok_or_else(|| {
                    format!("Unknown file_id returned by analysis service: {}", file_id)
                })?;

                if let Some(error) = result.error.clone() {
                    self.client
                        .publish_diagnostics(
                            snapshot.uri.clone(),
                            vec![build_analysis_failure_diagnostic(&error)],
                            Some(snapshot.version),
                        )
                        .await;
                    continue;
                }

                let diagnostics =
                    build_diagnostics(&result, &snapshot.text, snapshot.language_id.as_deref());
                self.client
                    .publish_diagnostics(
                        snapshot.uri.clone(),
                        diagnostics.clone(),
                        Some(snapshot.version),
                    )
                    .await;

                self.analysis.insert(
                    snapshot.uri.clone(),
                    AnalysisCache {
                        result,
                        diagnostics,
                    },
                );
            }
            return Ok(());
        }

        for (snapshot, result) in snapshots.into_iter().zip(response.results.into_iter()) {
            if let Some(error) = result.error.clone() {
                self.client
                    .publish_diagnostics(
                        snapshot.uri.clone(),
                        vec![build_analysis_failure_diagnostic(&error)],
                        Some(snapshot.version),
                    )
                    .await;
                continue;
            }

            let diagnostics =
                build_diagnostics(&result, &snapshot.text, snapshot.language_id.as_deref());
            self.client
                .publish_diagnostics(
                    snapshot.uri.clone(),
                    diagnostics.clone(),
                    Some(snapshot.version),
                )
                .await;

            self.analysis.insert(
                snapshot.uri.clone(),
                AnalysisCache {
                    result,
                    diagnostics,
                },
            );
        }

        Ok(())
    }

    pub fn analysis_for(&self, uri: &Url) -> Option<AnalysisCache> {
        self.analysis.get(uri).map(|entry| entry.clone())
    }

    pub fn document_text(&self, uri: &Url) -> Option<String> {
        self.documents.get(uri).map(|entry| entry.text.clone())
    }

    pub fn document_snapshot(&self, uri: &Url) -> Option<DocumentSnapshot> {
        self.documents.get(uri).map(|entry| entry.clone())
    }
}

fn workspace_key_for_path(workspace_path: Option<&str>, uri: &Url) -> String {
    let candidate = workspace_path
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| uri.path());

    match candidate.rsplit_once('/') {
        Some((prefix, _)) if !prefix.is_empty() => prefix.to_string(),
        _ => candidate.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::workspace_key_for_path;
    use tower_lsp::lsp_types::Url;

    #[test]
    fn workspace_key_prefers_parent_directory() {
        let uri = Url::parse("file:///workspace/repo/package.json").expect("valid file URL");
        let key = workspace_key_for_path(Some("/workspace/repo/package.json"), &uri);
        assert_eq!(key, "/workspace/repo");
    }

    #[test]
    fn workspace_key_falls_back_to_uri_path() {
        let uri = Url::parse("file:///tmp/Cargo.toml").expect("valid file URL");
        let key = workspace_key_for_path(None, &uri);
        assert_eq!(key, "/tmp");
    }
}
