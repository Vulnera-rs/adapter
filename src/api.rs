use crate::config::DetailLevel;
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone)]
pub struct VulneraApiClient {
    base_url: Url,
    api_key: Option<String>,
    http: reqwest::Client,
}

impl VulneraApiClient {
    pub fn new(base_url: Url, api_key: Option<String>, user_agent: &str) -> Result<Self, ApiError> {
        let http = reqwest::Client::builder()
            .user_agent(user_agent)
            .build()
            .map_err(ApiError::HttpClient)?;

        Ok(Self {
            base_url,
            api_key,
            http,
        })
    }

    pub async fn analyze_dependencies(
        &self,
        detail_level: DetailLevel,
        request: BatchDependencyAnalysisRequest,
    ) -> Result<BatchDependencyAnalysisResponse, ApiError> {
        let mut url = self
            .base_url
            .join("/api/v1/dependencies/analyze")
            .map_err(ApiError::InvalidUrl)?;

        url.query_pairs_mut()
            .append_pair("detail_level", detail_level.as_str());

        let mut req = self.http.post(url).json(&request);
        if let Some(api_key) = &self.api_key {
            req = req.header("X-API-Key", api_key);
        }

        let response = req.send().await.map_err(ApiError::HttpRequest)?;
        let status = response.status();
        let payload = response.text().await.map_err(ApiError::HttpRequest)?;

        if !status.is_success() {
            return Err(ApiError::HttpStatus(status, payload));
        }

        serde_json::from_str(&payload).map_err(ApiError::Deserialize)
    }
}

#[derive(Debug, Error)]
pub enum ApiError {
    #[error("Invalid API URL: {0}")]
    InvalidUrl(url::ParseError),
    #[error("Failed to build HTTP client: {0}")]
    HttpClient(reqwest::Error),
    #[error("HTTP request failed: {0}")]
    HttpRequest(reqwest::Error),
    #[error("Unexpected status {0}: {1}")]
    HttpStatus(StatusCode, String),
    #[error("Failed to parse response: {0}")]
    Deserialize(serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DependencyFileRequest {
    pub file_id: Option<String>,
    pub file_content: String,
    pub ecosystem: String,
    pub filename: Option<String>,
    pub workspace_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct BatchDependencyAnalysisRequest {
    pub files: Vec<DependencyFileRequest>,
    #[serde(default = "default_true")]
    pub enable_cache: bool,
    #[serde(default)]
    pub compact_mode: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BatchDependencyAnalysisResponse {
    pub results: Vec<FileAnalysisResult>,
    pub metadata: BatchAnalysisMetadata,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct BatchAnalysisMetadata {
    pub request_id: Option<String>,
    pub total_files: usize,
    pub successful: usize,
    pub failed: usize,
    pub duration_ms: u64,
    pub total_vulnerabilities: usize,
    pub total_packages: usize,
    pub cache_hits: Option<usize>,
    pub critical_count: usize,
    pub high_count: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileAnalysisResult {
    pub file_id: Option<String>,
    pub filename: Option<String>,
    pub ecosystem: String,
    pub vulnerabilities: Vec<VulnerabilityDto>,
    pub packages: Option<Vec<PackageDto>>,
    pub dependency_graph: Option<serde_json::Value>,
    pub version_recommendations: Option<Vec<VersionRecommendationDto>>,
    pub metadata: AnalysisMetadataDto,
    pub error: Option<String>,
    pub cache_hit: Option<bool>,
    pub workspace_path: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AnalysisMetadataDto {
    pub total_packages: usize,
    pub vulnerable_packages: usize,
    pub total_vulnerabilities: usize,
    pub severity_breakdown: SeverityBreakdownDto,
    pub analysis_duration_ms: u64,
    pub sources_queried: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SeverityBreakdownDto {
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PackageDto {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VulnerabilityDto {
    pub id: String,
    pub summary: String,
    pub description: String,
    pub severity: String,
    pub affected_packages: Vec<AffectedPackageDto>,
    pub references: Vec<String>,
    pub sources: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AffectedPackageDto {
    pub name: String,
    pub version: String,
    pub ecosystem: String,
    pub vulnerable_ranges: Vec<String>,
    pub fixed_versions: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VersionRecommendationDto {
    pub package: String,
    pub ecosystem: String,
    pub current_version: Option<String>,
    pub nearest_safe_above_current: Option<String>,
    pub most_up_to_date_safe: Option<String>,
    pub next_safe_minor_within_current_major: Option<String>,
    pub nearest_impact: Option<String>,
    pub most_up_to_date_impact: Option<String>,
    pub prerelease_exclusion_applied: Option<bool>,
    pub notes: Option<Vec<String>>,
}

impl DetailLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            DetailLevel::Minimal => "minimal",
            DetailLevel::Standard => "standard",
            DetailLevel::Full => "full",
        }
    }
}
