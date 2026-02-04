use crate::api::{FileAnalysisResult, VulnerabilityDto};
use regex::Regex;
use tower_lsp::lsp_types::{Diagnostic, DiagnosticSeverity, Position, Range};

pub fn build_diagnostics(
    result: &FileAnalysisResult,
    document_text: &str,
    language_id: Option<&str>,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    let lang_suffix = language_id
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!(" [lang: {}]", value))
        .unwrap_or_default();

    for vuln in &result.vulnerabilities {
        for affected in &vuln.affected_packages {
            let range = find_package_range(document_text, &result.ecosystem, &affected.name)
                .unwrap_or_else(default_range);
            let severity = map_severity(&vuln.severity);
            let message = format!(
                "{}: {} ({} {}){}",
                vuln.summary, affected.name, affected.version, vuln.id, lang_suffix
            );

            diagnostics.push(Diagnostic {
                range,
                severity: Some(severity),
                code: None,
                code_description: None,
                source: Some("vulnera".to_string()),
                message,
                related_information: None,
                tags: None,
                data: None,
            });
        }
    }

    if diagnostics.is_empty() {
        diagnostics.push(info_diagnostic(document_text, result, language_id));
    }

    diagnostics
}

fn info_diagnostic(
    document_text: &str,
    result: &FileAnalysisResult,
    language_id: Option<&str>,
) -> Diagnostic {
    let range = if document_text.is_empty() {
        default_range()
    } else {
        Range::new(Position::new(0, 0), Position::new(0, 1))
    };
    let lang_suffix = language_id
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!(" [lang: {}]", value))
        .unwrap_or_default();

    Diagnostic {
        range,
        severity: Some(DiagnosticSeverity::HINT),
        code: None,
        code_description: None,
        source: Some("vulnera".to_string()),
        message: format!(
            "Dependency scan complete: {} vulnerabilities{}",
            result.metadata.total_vulnerabilities, lang_suffix
        ),
        related_information: None,
        tags: None,
        data: None,
    }
}

fn default_range() -> Range {
    Range::new(Position::new(0, 0), Position::new(0, 0))
}

fn map_severity(severity: &str) -> DiagnosticSeverity {
    match severity.to_lowercase().as_str() {
        "critical" => DiagnosticSeverity::ERROR,
        "high" => DiagnosticSeverity::ERROR,
        "medium" => DiagnosticSeverity::WARNING,
        "low" => DiagnosticSeverity::INFORMATION,
        _ => DiagnosticSeverity::HINT,
    }
}

fn find_package_range(text: &str, ecosystem: &str, package: &str) -> Option<Range> {
    let pattern = match ecosystem.to_lowercase().as_str() {
        "npm" => format!(r#""{}"\s*:\s*"(?P<ver>[^"]+)""#, regex::escape(package)),
        "pypi" | "pip" | "python" => {
            format!(r"(?m)^\s*{}\s*[=<>!~]+\s*(?P<ver>[^\s#]+)", regex::escape(package))
        }
        "cargo" | "rust" => format!(
            r#"(?m)^\s*{}\s*=\s*"(?P<ver>[^"]+)""#,
            regex::escape(package)
        ),
        _ => return None,
    };

    let regex = Regex::new(&pattern).ok()?;
    let captures = regex.captures(text)?;
    let match_span = captures.name("ver").map(|m| (m.start(), m.end()))?;

    Some(span_to_range(text, match_span.0, match_span.1))
}

fn span_to_range(text: &str, start: usize, end: usize) -> Range {
    let (start_line, start_col) = offset_to_position(text, start);
    let (end_line, end_col) = offset_to_position(text, end);
    Range::new(Position::new(start_line, start_col), Position::new(end_line, end_col))
}

fn offset_to_position(text: &str, offset: usize) -> (u32, u32) {
    let mut line = 0u32;
    let mut col = 0u32;
    let mut count = 0usize;

    for ch in text.chars() {
        if count >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            col = 0;
        } else {
            col += 1;
        }
        count += ch.len_utf8();
    }

    (line, col)
}

pub fn summarize_vulnerabilities(vuln: &VulnerabilityDto) -> String {
    let mut parts = vec![vuln.summary.clone()];
    if !vuln.references.is_empty() {
        parts.push(format!("References: {}", vuln.references.join(", ")));
    }
    parts.join("\n")
}
