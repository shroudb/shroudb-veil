/// Generate searchable tokens from plaintext.
///
/// Produces two categories of tokens:
/// - **Word tokens** (`w:{word}`): for exact word matching.
/// - **Trigram tokens** (`t:{trigram}`): for prefix/fuzzy/contains matching
///   on character subsequences.
///
/// All text is lowercased and split on non-alphanumeric boundaries.
/// Tokens are deduplicated and sorted for deterministic output.
pub fn tokenize(text: &str) -> TokenSet {
    let normalized = text.to_lowercase();
    let words: Vec<&str> = normalized
        .split(|c: char| !c.is_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();

    let mut word_tokens: Vec<String> = words.iter().map(|w| format!("w:{w}")).collect();

    let mut trigram_tokens: Vec<String> = Vec::new();
    for word in &words {
        let chars: Vec<char> = word.chars().collect();
        if chars.len() >= 3 {
            for window in chars.windows(3) {
                let tri: String = window.iter().collect();
                trigram_tokens.push(format!("t:{tri}"));
            }
        }
    }

    word_tokens.sort();
    word_tokens.dedup();
    trigram_tokens.sort();
    trigram_tokens.dedup();

    TokenSet {
        words: word_tokens,
        trigrams: trigram_tokens,
    }
}

/// Extract text from a JSON value for tokenization.
///
/// If `field` is specified, extracts that field's string value.
/// If `field` is `None`, concatenates all string values in the JSON object.
/// Falls back to treating the input as raw UTF-8.
pub fn extract_text(data: &[u8], field: Option<&str>) -> String {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return String::from_utf8_lossy(data).into_owned();
    };

    if let Some(field_name) = field {
        return value
            .get(field_name)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
    }

    // Concatenate all string values
    match &value {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Object(map) => {
            let parts: Vec<&str> = map.values().filter_map(|v| v.as_str()).collect();
            parts.join(" ")
        }
        _ => value.to_string(),
    }
}

/// A set of blind-index tokens derived from plaintext.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TokenSet {
    /// Word-level tokens (e.g., `w:hello`).
    pub words: Vec<String>,
    /// Character trigram tokens (e.g., `t:hel`, `t:ell`).
    pub trigrams: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenize_simple() {
        let ts = tokenize("Hello World");
        assert!(ts.words.contains(&"w:hello".to_string()));
        assert!(ts.words.contains(&"w:world".to_string()));
        assert_eq!(ts.words.len(), 2);
    }

    #[test]
    fn tokenize_trigrams() {
        let ts = tokenize("hello");
        assert!(ts.trigrams.contains(&"t:hel".to_string()));
        assert!(ts.trigrams.contains(&"t:ell".to_string()));
        assert!(ts.trigrams.contains(&"t:llo".to_string()));
        assert_eq!(ts.trigrams.len(), 3);
    }

    #[test]
    fn tokenize_short_words_no_trigrams() {
        let ts = tokenize("hi ok");
        assert_eq!(ts.words.len(), 2);
        assert!(ts.trigrams.is_empty());
    }

    #[test]
    fn tokenize_deduplicates() {
        let ts = tokenize("hello hello world hello");
        assert_eq!(ts.words.len(), 2);
    }

    #[test]
    fn tokenize_splits_on_punctuation() {
        let ts = tokenize("alice@example.com");
        assert!(ts.words.contains(&"w:alice".to_string()));
        assert!(ts.words.contains(&"w:example".to_string()));
        assert!(ts.words.contains(&"w:com".to_string()));
    }

    #[test]
    fn tokenize_empty() {
        let ts = tokenize("");
        assert!(ts.words.is_empty());
        assert!(ts.trigrams.is_empty());
    }

    #[test]
    fn extract_text_json_field() {
        let data = br#"{"name": "Alice", "email": "alice@test.com"}"#;
        assert_eq!(extract_text(data, Some("name")), "Alice");
        assert_eq!(extract_text(data, Some("email")), "alice@test.com");
        assert_eq!(extract_text(data, Some("missing")), "");
    }

    #[test]
    fn extract_text_all_fields() {
        let data = br#"{"name": "Alice", "city": "Portland"}"#;
        let text = extract_text(data, None);
        assert!(text.contains("Alice"));
        assert!(text.contains("Portland"));
    }

    #[test]
    fn extract_text_raw_utf8() {
        let data = b"just plain text";
        assert_eq!(extract_text(data, None), "just plain text");
    }

    #[test]
    fn tokenize_case_normalization() {
        let ts = tokenize("Hello WORLD hElLo");
        // All normalized to lowercase, deduplicated
        assert_eq!(ts.words.len(), 2);
        assert!(ts.words.contains(&"w:hello".to_string()));
        assert!(ts.words.contains(&"w:world".to_string()));
    }

    #[test]
    fn tokenize_numeric_words() {
        let ts = tokenize("user123 test456");
        assert!(ts.words.contains(&"w:user123".to_string()));
        assert!(ts.words.contains(&"w:test456".to_string()));
    }

    #[test]
    fn tokenize_only_punctuation() {
        let ts = tokenize("!@#$%^&*()");
        assert!(ts.words.is_empty());
        assert!(ts.trigrams.is_empty());
    }

    #[test]
    fn tokenize_trigrams_from_multiple_words() {
        let ts = tokenize("abc xyz");
        // "abc" produces trigram "abc"; "xyz" produces trigram "xyz"
        assert!(ts.trigrams.contains(&"t:abc".to_string()));
        assert!(ts.trigrams.contains(&"t:xyz".to_string()));
        assert_eq!(ts.trigrams.len(), 2);
    }

    #[test]
    fn tokenize_sorted_output() {
        let ts = tokenize("zebra apple mango");
        // Words should be sorted
        assert_eq!(ts.words, vec!["w:apple", "w:mango", "w:zebra"]);
    }

    #[test]
    fn extract_text_json_string_value() {
        let data = br#""just a string""#;
        let text = extract_text(data, None);
        assert_eq!(text, "just a string");
    }

    #[test]
    fn extract_text_json_number() {
        let data = b"42";
        let text = extract_text(data, None);
        assert_eq!(text, "42");
    }
}
