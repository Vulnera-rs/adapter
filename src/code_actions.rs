use crate::api::VersionRecommendationDto;
use regex::Regex;
use tower_lsp::lsp_types::{
    CodeAction, CodeActionKind, Command, Range, TextEdit, Url, WorkspaceEdit,
};

pub fn build_code_actions(
    uri: &Url,
    ecosystem: &str,
    document_text: &str,
    recommendations: &[VersionRecommendationDto],
    language_id: Option<&str>,
) -> Vec<CodeAction> {
    let mut actions = Vec::new();
    let lang_suffix = language_id
        .filter(|value| !value.trim().is_empty())
        .map(|value| format!(" [{}]", value))
        .unwrap_or_default();

    for rec in recommendations {
        let title_prefix = format!("{}: {}{}", rec.ecosystem, rec.package, lang_suffix);

        if let Some(version) = rec.nearest_safe_above_current.as_ref() {
            if let Some(edit) = find_version_edit(ecosystem, &rec.package, version, document_text) {
                actions.push(make_edit_action(
                    format!("{} -> nearest safe {}", title_prefix, version),
                    uri.clone(),
                    edit,
                    true,
                ));
            } else {
                actions.push(make_command_action(
                    format!("{} -> nearest safe {}", title_prefix, version),
                    rec,
                    "nearest_safe_above_current",
                    language_id,
                ));
            }
        }

        if let Some(version) = rec.most_up_to_date_safe.as_ref() {
            if let Some(edit) = find_version_edit(ecosystem, &rec.package, version, document_text) {
                actions.push(make_edit_action(
                    format!("{} -> latest safe {}", title_prefix, version),
                    uri.clone(),
                    edit,
                    false,
                ));
            } else {
                actions.push(make_command_action(
                    format!("{} -> latest safe {}", title_prefix, version),
                    rec,
                    "most_up_to_date_safe",
                    language_id,
                ));
            }
        }

        if let Some(version) = rec.next_safe_minor_within_current_major.as_ref() {
            if let Some(edit) = find_version_edit(ecosystem, &rec.package, version, document_text) {
                actions.push(make_edit_action(
                    format!("{} -> next safe minor {}", title_prefix, version),
                    uri.clone(),
                    edit,
                    false,
                ));
            } else {
                actions.push(make_command_action(
                    format!("{} -> next safe minor {}", title_prefix, version),
                    rec,
                    "next_safe_minor_within_current_major",
                    language_id,
                ));
            }
        }
    }

    actions
}

fn make_edit_action(
    title: String,
    uri: Url,
    edit: TextEdit,
    preferred: bool,
) -> CodeAction {
    let mut changes = std::collections::HashMap::new();
    changes.insert(uri, vec![edit]);

    CodeAction {
        title,
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: None,
        edit: Some(WorkspaceEdit {
            changes: Some(changes),
            document_changes: None,
            change_annotations: None,
        }),
        command: None,
        is_preferred: Some(preferred),
        disabled: None,
        data: None,
    }
}

fn make_command_action(
    title: String,
    rec: &VersionRecommendationDto,
    strategy: &str,
    language_id: Option<&str>,
) -> CodeAction {
    let language_id = language_id
        .filter(|value| !value.trim().is_empty())
        .map(|value| value.to_string());
    let command = Command {
        title: title.clone(),
        command: "vulnera.applyRecommendation".to_string(),
        arguments: Some(vec![
            serde_json::json!({
                "package": rec.package,
                "ecosystem": rec.ecosystem,
                "strategy": strategy,
                "language_id": language_id,
                "nearest_safe_above_current": rec.nearest_safe_above_current,
                "most_up_to_date_safe": rec.most_up_to_date_safe,
                "next_safe_minor_within_current_major": rec.next_safe_minor_within_current_major,
            }),
        ]),
    };

    CodeAction {
        title,
        kind: Some(CodeActionKind::QUICKFIX),
        diagnostics: None,
        edit: None,
        command: Some(command),
        is_preferred: Some(strategy == "nearest_safe_above_current"),
        disabled: None,
        data: None,
    }
}

fn find_version_edit(
    ecosystem: &str,
    package: &str,
    new_version: &str,
    document_text: &str,
) -> Option<TextEdit> {
    let (range, _) = find_version_range(ecosystem, package, document_text)?;
    Some(TextEdit {
        range,
        new_text: new_version.to_string(),
    })
}

fn find_version_range(
    ecosystem: &str,
    package: &str,
    text: &str,
) -> Option<(Range, String)> {
    let patterns = match ecosystem.to_lowercase().as_str() {
        "npm" => vec![format!(
            r#""{}"\s*:\s*"(?P<ver>[^"]+)""#,
            regex::escape(package)
        )],
        "pypi" | "pip" | "python" => vec![format!(
            r"(?m)^\s*{}\s*[=<>!~]+\s*(?P<ver>[^\s#]+)",
            regex::escape(package)
        )],
        "cargo" | "rust" => vec![
            format!(
                r#"(?m)^\s*{}\s*=\s*"(?P<ver>[^"]+)""#,
                regex::escape(package)
            ),
            format!(
                r#"(?m)^\s*{}\s*=\s*\{{[^}}]*version\s*=\s*"(?P<ver>[^"]+)""#,
                regex::escape(package)
            ),
        ],
        _ => vec![],
    };

    for pattern in patterns {
        let regex = Regex::new(&pattern).ok()?;
        if let Some(captures) = regex.captures(text) {
            if let Some(matched) = captures.name("ver") {
                let range = span_to_range(text, matched.start(), matched.end());
                return Some((range, matched.as_str().to_string()));
            }
        }
    }

    None
}

fn span_to_range(text: &str, start: usize, end: usize) -> Range {
    let (start_line, start_col) = offset_to_position(text, start);
    let (end_line, end_col) = offset_to_position(text, end);
    Range::new(
        tower_lsp::lsp_types::Position::new(start_line, start_col),
        tower_lsp::lsp_types::Position::new(end_line, end_col),
    )
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
