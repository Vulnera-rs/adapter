use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::env;
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum DetailLevel {
    Minimal,
    #[default]
    Standard,
    Full,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub api_url: Url,
    pub api_key: Option<String>,
    pub detail_level: DetailLevel,
    pub compact_mode: bool,
    pub enable_cache: bool,
    pub debounce_ms: u64,
    pub user_agent: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_url: Url::parse("http://localhost:3000").expect("valid default api url"),
            api_key: None,
            detail_level: DetailLevel::Standard,
            compact_mode: false,
            enable_cache: true,
            debounce_ms: 500,
            user_agent: concat!("vulnera-adapter-lsp/", env!("CARGO_PKG_VERSION")).to_string(),
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        let mut config = Config::default();

        if let Ok(value) = env::var("VULNERA_API_URL")
            && let Ok(url) = Url::parse(&value)
        {
            config.api_url = url;
        }

        if let Ok(value) = env::var("VULNERA_API_KEY")
            && !value.trim().is_empty()
        {
            config.api_key = Some(value);
        }

        if let Ok(value) = env::var("VULNERA_DETAIL_LEVEL") {
            config.detail_level = parse_detail_level(&value).unwrap_or(DetailLevel::Standard);
        }

        if let Ok(value) = env::var("VULNERA_COMPACT_MODE") {
            config.compact_mode = value.eq_ignore_ascii_case("true");
        }

        if let Ok(value) = env::var("VULNERA_ENABLE_CACHE") {
            config.enable_cache = value.eq_ignore_ascii_case("true");
        }

        if let Ok(value) = env::var("VULNERA_DEBOUNCE_MS")
            && let Ok(parsed) = value.parse::<u64>()
        {
            config.debounce_ms = parsed;
        }

        config
    }

    pub fn apply_initialize_options(&self, options: Option<Value>) -> Self {
        let Some(options) = options else {
            return self.clone();
        };

        let mut config = self.clone();

        let scoped = options.get("vulnera").cloned().unwrap_or(options.clone());

        if let Some(api_url) = scoped.get("apiUrl").and_then(|v| v.as_str())
            && let Ok(url) = Url::parse(api_url)
        {
            config.api_url = url;
        }

        if let Some(api_key) = scoped.get("apiKey").and_then(|v| v.as_str())
            && !api_key.trim().is_empty()
        {
            config.api_key = Some(api_key.to_string());
        }

        if let Some(detail_level) = scoped.get("detailLevel").and_then(|v| v.as_str())
            && let Some(parsed) = parse_detail_level(detail_level)
        {
            config.detail_level = parsed;
        }

        if let Some(compact_mode) = scoped.get("compactMode").and_then(|v| v.as_bool()) {
            config.compact_mode = compact_mode;
        }

        if let Some(enable_cache) = scoped.get("enableCache").and_then(|v| v.as_bool()) {
            config.enable_cache = enable_cache;
        }

        if let Some(debounce_ms) = scoped.get("debounceMs").and_then(|v| v.as_u64()) {
            config.debounce_ms = debounce_ms;
        }

        if let Some(user_agent) = scoped.get("userAgent").and_then(|v| v.as_str())
            && !user_agent.trim().is_empty()
        {
            config.user_agent = user_agent.to_string();
        }

        config
    }
}

fn parse_detail_level(value: &str) -> Option<DetailLevel> {
    match value.to_lowercase().as_str() {
        "minimal" => Some(DetailLevel::Minimal),
        "standard" => Some(DetailLevel::Standard),
        "full" => Some(DetailLevel::Full),
        _ => None,
    }
}
