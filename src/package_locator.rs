use once_cell::sync::Lazy;
use regex::Regex;
use tower_lsp::lsp_types::{Position, Range};

static NPM_DEP_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#""(?P<pkg>[^"]+)"\s*:\s*"(?P<ver>[^"]+)""#).expect("valid npm dependency regex")
});

static PYPI_DEP_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\s*(?P<pkg>[A-Za-z0-9_.\-]+)\s*[=<>!~]+\s*(?P<ver>[^\s#]+)")
        .expect("valid pypi dependency regex")
});

static CARGO_DEP_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*(?P<pkg>[A-Za-z0-9_\-]+)\s*=\s*"(?P<ver>[^"]+)""#)
        .expect("valid cargo dependency regex")
});

static CARGO_INLINE_DEP_REGEX: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"(?m)^\s*(?P<pkg>[A-Za-z0-9_\-]+)\s*=\s*\{[^}]*version\s*=\s*"(?P<ver>[^"]+)""#)
        .expect("valid cargo inline table dependency regex")
});

pub(crate) fn find_package_version_range(
    text: &str,
    ecosystem: &str,
    package: &str,
) -> Option<Range> {
    match ecosystem.to_lowercase().as_str() {
        "npm" => find_with_regex(text, package, &NPM_DEP_REGEX),
        "pypi" | "pip" | "python" => find_with_regex(text, package, &PYPI_DEP_REGEX),
        "cargo" | "rust" => find_with_regex(text, package, &CARGO_DEP_REGEX)
            .or_else(|| find_with_regex(text, package, &CARGO_INLINE_DEP_REGEX)),
        _ => None,
    }
}

fn find_with_regex(text: &str, package: &str, regex: &Regex) -> Option<Range> {
    regex.captures_iter(text).find_map(|captures| {
        let pkg = captures.name("pkg")?.as_str();
        if pkg == package {
            captures
                .name("ver")
                .map(|matched| span_to_range(text, matched.start(), matched.end()))
        } else {
            None
        }
    })
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

    #[test]
    fn returns_none_for_missing_package() {
        let content = r#"{
    "dependencies": {
        "serde": "1.0.100"
    }
}"#;

        let range = find_package_version_range(content, "npm", "tokio");
        assert!(range.is_none());
    }
}
