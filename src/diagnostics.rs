use crate::api::{FileAnalysisResult, VulnerabilityDto};
use crate::package_locator::find_package_version_range;
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
    find_package_version_range(text, ecosystem, package)
}

pub fn build_analysis_failure_diagnostic(message: &str) -> Diagnostic {
    Diagnostic {
        range: default_range(),
        severity: Some(DiagnosticSeverity::ERROR),
        code: None,
        code_description: None,
        source: Some("vulnera".to_string()),
        message: format!("Dependency scan failed: {}", message),
        related_information: None,
        tags: None,
        data: None,
    }
}

pub fn summarize_vulnerabilities(vuln: &VulnerabilityDto) -> String {
    let mut parts = vec![vuln.summary.clone()];
    if !vuln.references.is_empty() {
        parts.push(format!("References: {}", vuln.references.join(", ")));
    }
    parts.join("\n")
}

#[cfg(test)]
mod tests {
    use super::build_analysis_failure_diagnostic;
    use tower_lsp::lsp_types::DiagnosticSeverity;

    #[test]
    fn failure_diagnostic_is_error_and_prefixed() {
        let diagnostic = build_analysis_failure_diagnostic("upstream timeout");

        assert_eq!(diagnostic.severity, Some(DiagnosticSeverity::ERROR));
        assert!(diagnostic.message.starts_with("Dependency scan failed:"));
        assert!(diagnostic.message.contains("upstream timeout"));
    }
}
