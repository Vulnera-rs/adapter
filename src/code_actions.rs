use crate::api::VersionRecommendationDto;
use crate::package_locator::find_package_version_range;
use tower_lsp::lsp_types::{CodeAction, CodeActionKind, Command, TextEdit, Url, WorkspaceEdit};

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

fn make_edit_action(title: String, uri: Url, edit: TextEdit, preferred: bool) -> CodeAction {
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
        arguments: Some(vec![serde_json::json!({
            "package": rec.package,
            "ecosystem": rec.ecosystem,
            "strategy": strategy,
            "language_id": language_id,
            "nearest_safe_above_current": rec.nearest_safe_above_current,
            "most_up_to_date_safe": rec.most_up_to_date_safe,
            "next_safe_minor_within_current_major": rec.next_safe_minor_within_current_major,
        })]),
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
    let range = find_package_version_range(document_text, ecosystem, package)?;
    Some(TextEdit {
        range,
        new_text: new_version.to_string(),
    })
}
