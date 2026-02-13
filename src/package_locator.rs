use regex::Regex;
use tower_lsp::lsp_types::{Position, Range};

pub(crate) fn find_package_version_range(
    text: &str,
    ecosystem: &str,
    package: &str,
) -> Option<Range> {
    let patterns = match ecosystem.to_lowercase().as_str() {
        "npm" => vec![format!(
            r#"\"{}\"\s*:\s*\"(?P<ver>[^\"]+)\""#,
            regex::escape(package)
        )],
        "pypi" | "pip" | "python" => vec![format!(
            r"(?m)^\s*{}\s*[=<>!~]+\s*(?P<ver>[^\s#]+)",
            regex::escape(package)
        )],
        "cargo" | "rust" => vec![
            format!(
                r#"(?m)^\s*{}\s*=\s*\"(?P<ver>[^\"]+)\""#,
                regex::escape(package)
            ),
            format!(
                r#"(?m)^\s*{}\s*=\s*\{{[^}}]*version\s*=\s*\"(?P<ver>[^\"]+)\""#,
                regex::escape(package)
            ),
        ],
        _ => vec![],
    };

    for pattern in patterns {
        let regex = Regex::new(&pattern).ok()?;
        if let Some(captures) = regex.captures(text)
            && let Some(matched) = captures.name("ver")
        {
            return Some(span_to_range(text, matched.start(), matched.end()));
        }
    }

    None
}

fn span_to_range(text: &str, start: usize, end: usize) -> Range {
    let (start_line, start_col) = offset_to_position(text, start);
    let (end_line, end_col) = offset_to_position(text, end);
    Range::new(
        Position::new(start_line, start_col),
        Position::new(end_line, end_col),
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

#[cfg(test)]
mod tests {
    use super::find_package_version_range;

    #[test]
    fn finds_npm_version_range() {
        let content = r#"{
  "dependencies": {
    "lodash": "4.17.20"
  }
}"#;

        let range = find_package_version_range(content, "npm", "lodash")
            .expect("expected lodash version range");

        assert_eq!(range.start.line, 2);
        assert_eq!(range.end.line, 2);
    }

    #[test]
    fn finds_cargo_inline_table_version_range() {
        let content = r#"[dependencies]
serde = { version = "1.0.100", features = ["derive"] }
"#;

        let range = find_package_version_range(content, "cargo", "serde")
            .expect("expected serde version range");

        assert_eq!(range.start.line, 1);
        assert_eq!(range.end.line, 1);
    }
}
