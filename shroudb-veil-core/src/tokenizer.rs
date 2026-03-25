//! Search token generation for encrypted index building.
//!
//! Generates deterministic tokens (trigrams + normalized words) from plaintext.
//! These tokens are encrypted with convergent encryption and stored alongside
//! ciphertexts. At search time, query tokens are encrypted the same way and
//! matched against stored tokens without decrypting the data.

/// Generate search tokens from plaintext.
///
/// Returns a deduplicated, sorted list of:
/// - Word tokens (`w:<word>`) — normalized lowercase words
/// - Trigram tokens (`t:<tri>`) — overlapping 3-character subsequences
///
/// Sorting ensures deterministic output for convergent encryption.
pub fn tokenize(text: &str) -> Vec<String> {
    let normalized = text.to_ascii_lowercase();
    let words: Vec<&str> = normalized
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .collect();

    let mut tokens = Vec::new();

    for word in &words {
        // Word token.
        tokens.push(format!("w:{word}"));

        // Trigram tokens from each word.
        let chars: Vec<char> = word.chars().collect();
        if chars.len() >= 3 {
            for window in chars.windows(3) {
                let tri: String = window.iter().collect();
                tokens.push(format!("t:{tri}"));
            }
        }
    }

    tokens.sort();
    tokens.dedup();
    tokens
}

/// Generate search tokens from a query string.
///
/// Same logic as `tokenize` — the caller encrypts these with the same
/// convergent keyring to match against stored tokens.
pub fn tokenize_query(query: &str) -> Vec<String> {
    tokenize(query)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_word() {
        let tokens = tokenize("dinner");
        assert!(tokens.contains(&"w:dinner".to_string()));
        assert!(tokens.contains(&"t:din".to_string()));
        assert!(tokens.contains(&"t:inn".to_string()));
        assert!(tokens.contains(&"t:nne".to_string()));
        assert!(tokens.contains(&"t:ner".to_string()));
    }

    #[test]
    fn multi_word() {
        let tokens = tokenize("Want to grab dinner?");
        assert!(tokens.contains(&"w:want".to_string()));
        assert!(tokens.contains(&"w:dinner".to_string()));
        assert!(tokens.contains(&"w:grab".to_string()));
        // Short words have no trigrams
        assert!(!tokens.iter().any(|t| t.starts_with("t:to")));
    }

    #[test]
    fn case_insensitive() {
        let a = tokenize("Hello World");
        let b = tokenize("hello world");
        assert_eq!(a, b);
    }

    #[test]
    fn deduplication() {
        let tokens = tokenize("the the the");
        let word_count = tokens.iter().filter(|t| *t == "w:the").count();
        assert_eq!(word_count, 1);
    }

    #[test]
    fn sorted_output() {
        let tokens = tokenize("zebra apple mango");
        let mut sorted = tokens.clone();
        sorted.sort();
        assert_eq!(tokens, sorted);
    }

    #[test]
    fn empty_string() {
        assert!(tokenize("").is_empty());
    }

    #[test]
    fn punctuation_stripped() {
        let tokens = tokenize("hello, world! foo-bar");
        assert!(tokens.contains(&"w:hello".to_string()));
        assert!(tokens.contains(&"w:world".to_string()));
        assert!(tokens.contains(&"w:foo".to_string()));
        assert!(tokens.contains(&"w:bar".to_string()));
    }

    #[test]
    fn short_words_no_trigrams() {
        let tokens = tokenize("ab cd");
        assert!(tokens.contains(&"w:ab".to_string()));
        assert!(tokens.contains(&"w:cd".to_string()));
        // No trigrams for 2-char words.
        assert!(!tokens.iter().any(|t| t.starts_with("t:")));
    }

    #[test]
    fn query_same_as_tokenize() {
        assert_eq!(tokenize("dinner"), tokenize_query("dinner"));
    }
}
