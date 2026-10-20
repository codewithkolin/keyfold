//! Parse and render `.env` files. Shared by the desktop app and the CLI.

/// Parse `.env` text into ordered (key, value) pairs.
/// Supports comments, blank lines, `export KEY=`, single/double quotes, and
/// `\n`, `\t`, `\"`, `\\` escapes inside double quotes.
pub fn parse_env(text: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    // Editors on Windows often start a file with a byte-order mark; it isn't part of the first key.
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").map(str::trim).unwrap_or(line);
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
        {
            continue;
        }
        let value = parse_value(v.trim());
        out.push((key.to_string(), value));
    }
    out
}

fn parse_value(v: &str) -> String {
    if let Some(inner) = v
        .strip_prefix('"')
        .and_then(|r| r.rsplit_once('"'))
        .map(|(inner, _)| inner)
    {
        return unescape(inner);
    }
    if let Some(inner) = v
        .strip_prefix('\'')
        .and_then(|r| r.rsplit_once('\''))
        .map(|(inner, _)| inner)
    {
        return inner.to_string();
    }
    // Unquoted: strip an inline comment that follows whitespace.
    let mut end = v.len();
    let bytes = v.as_bytes();
    for i in 0..bytes.len() {
        if bytes[i] == b'#' && (i == 0 || bytes[i - 1].is_ascii_whitespace()) {
            end = i;
            break;
        }
    }
    v[..end].trim().to_string()
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('"') => out.push('"'),
            Some('\\') => out.push('\\'),
            Some(other) => {
                out.push('\\');
                out.push(other);
            }
            None => out.push('\\'),
        }
    }
    out
}

/// Render pairs as `.env` text, quoting values that need it.
pub fn render_env<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut out = String::new();
    for (k, v) in pairs {
        out.push_str(k);
        out.push('=');
        if v.is_empty()
            || v.chars()
                .any(|c| c.is_whitespace() || matches!(c, '#' | '"' | '\'' | '\\' | '$' | '`'))
        {
            out.push('"');
            for c in v.chars() {
                match c {
                    '"' => out.push_str("\\\""),
                    '\\' => out.push_str("\\\\"),
                    '\n' => out.push_str("\\n"),
                    '\r' => out.push_str("\\r"),
                    '\t' => out.push_str("\\t"),
                    c => out.push(c),
                }
            }
            out.push('"');
        } else {
            out.push_str(v);
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_order_mark_is_not_part_of_the_first_key() {
        let parsed = parse_env("\u{feff}API_KEY=abc\nOTHER=1\n");
        assert_eq!(parsed[0], ("API_KEY".to_string(), "abc".to_string()));
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn parses_common_shapes() {
        let text = r#"
# comment
PLAIN=hello
export EXPORTED=world
QUOTED="with space and \"escaped\" and \n newline"
SINGLE='keep $literal #here'
INLINE=value # trailing comment
URL=https://example.com/#anchor
EMPTY=
bad line without equals
9NUM=ok
"#;
        let got = parse_env(text);
        let m: std::collections::HashMap<_, _> = got.iter().cloned().collect();
        assert_eq!(m["PLAIN"], "hello");
        assert_eq!(m["EXPORTED"], "world");
        assert_eq!(m["QUOTED"], "with space and \"escaped\" and \n newline");
        assert_eq!(m["SINGLE"], "keep $literal #here");
        assert_eq!(m["INLINE"], "value");
        assert_eq!(m["URL"], "https://example.com/#anchor");
        assert_eq!(m["EMPTY"], "");
        assert_eq!(m["9NUM"], "ok");
        assert_eq!(got.len(), 8);
    }

    #[test]
    fn render_roundtrips() {
        let pairs = [
            ("A", "plain"),
            ("B", "has space"),
            ("C", "quote\"and\\slash\nnl"),
            ("D", ""),
            ("E", "x#y"),
        ];
        let text = render_env(pairs.iter().map(|(k, v)| (*k, *v)));
        let back = parse_env(&text);
        assert_eq!(
            back,
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect::<Vec<_>>()
        );
    }
}
