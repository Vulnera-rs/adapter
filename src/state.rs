use crate::api::{
    BatchDependencyAnalysisRequest, DependencyFileRequest, FileAnalysisResult, VulneraApiClient,
};
use crate::config::Config;
use crate::diagnostics::build_diagnostics;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{sleep, Duration};
use tower_lsp::lsp_types::Url;
use tower_lsp::Client;

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
    pending: Arc<DashMap<Url, JoinHandle<()>>>,
}

impl ServerState {
    pub fn new(client: Client, config: Config) -> Self {
        let http = VulneraApiClient::new(config.api_url.clone(), config.api_key.clone(), &config.user_agent)
            .expect("http client initialization");

        Self {
            client,
            config: Arc::new(RwLock::new(config)),
            http: Arc::new(RwLock::new(http)),
            documents: Arc::new(DashMap::new()),
            analysis: Arc::new(DashMap::new()),
            pending: Arc::new(DashMap::new()),
        }
    }

    pub async fn update_config(&self, next: Config) {
        {
            let mut config = self.config.write().await;
            *config = next.clone();
        }
        let http = VulneraApiClient::new(next.api_url.clone(), next.api_key.clone(), &next.user_agent)
            .expect("http client initialization");
        let mut http_guard = self.http.write().await;
        *http_guard = http;
    }

    pub fn upsert_document(&self, snapshot: DocumentSnapshot) {
        self.documents.insert(snapshot.uri.clone(), snapshot);
    }

    pub fn remove_document(&self, uri: &Url) {
        self.documents.remove(uri);
        self.analysis.remove(uri);
        if let Some((_, handle)) = self.pending.remove(uri) {
            handle.abort();
        }
    }

    pub async fn schedule_analysis(self: Arc<Self>, uri: Url) {
        if let Some((_, handle)) = self.pending.remove(&uri) {
            handle.abort();
        }

        let debounce_ms = { self.config.read().await.debounce_ms };
        let state = Arc::clone(&self);
        let uri_for_task = uri.clone();
        let handle = tokio::spawn(async move {
            sleep(Duration::from_millis(debounce_ms)).await;
            if let Err(err) = state.run_analysis(uri_for_task.clone()).await {
                state
                    .client
                    .log_message(
                        tower_lsp::lsp_types::MessageType::ERROR,
                        format!("Dependency analysis failed: {}", err),
                    )
                    .await;
            }
        });

        self.pending.insert(uri, handle);
    }

    async fn run_analysis(&self, uri: Url) -> Result<(), String> {
        let snapshot = match self.documents.get(&uri) {
            Some(doc) => doc.clone(),
            None => return Ok(()),
        };

        let config = self.config.read().await.clone();
        let request = BatchDependencyAnalysisRequest {
            files: vec![DependencyFileRequest {
                file_content: snapshot.text.clone(),
                ecosystem: snapshot.ecosystem.clone(),
                filename: snapshot.file_name.clone(),
                workspace_path: snapshot.workspace_path.clone(),
            }],
            enable_cache: config.enable_cache,
            compact_mode: config.compact_mode,
        };

        let response = {
            let http = self.http.read().await;
            http.analyze_dependencies(config.detail_level, request)
                .await
                .map_err(|e| e.to_string())?
        };

        let result = response
            .results
            .into_iter()
            .next()
            .ok_or_else(|| "Empty analysis response".to_string())?;

        let diagnostics = build_diagnostics(
            &result,
            &snapshot.text,
            snapshot.language_id.as_deref(),
        );
        self.client
            .publish_diagnostics(uri.clone(), diagnostics.clone(), Some(snapshot.version))
            .await;

        self.analysis.insert(
            uri.clone(),
            AnalysisCache {
                result,
                diagnostics,
            },
        );

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
