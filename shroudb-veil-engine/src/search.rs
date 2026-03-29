//! Search scoring logic for blind token comparison.

use std::collections::HashSet;

use shroudb_veil_core::matching::MatchMode;

use crate::hmac_ops::BlindTokenSet;

/// A single search result.
#[derive(Debug, Clone)]
pub struct SearchHit {
    pub id: String,
    pub score: f64,
}

/// Score a stored entry's blind tokens against query blind tokens.
///
/// Returns `Some(score)` if the entry matches, `None` if it does not.
pub fn score_entry(mode: MatchMode, query: &BlindTokenSet, entry: &BlindTokenSet) -> Option<f64> {
    match mode {
        MatchMode::Exact => score_exact(query, entry),
        MatchMode::Contains => score_contains(query, entry),
        MatchMode::Prefix => score_trigram_overlap(query, entry, 0.6),
        MatchMode::Fuzzy => score_trigram_overlap(query, entry, 0.3),
    }
}

/// Exact: ALL query word tokens must be present. Score = 1.0 on match.
fn score_exact(query: &BlindTokenSet, entry: &BlindTokenSet) -> Option<f64> {
    if query.words.is_empty() {
        return None;
    }

    let entry_words: HashSet<&str> = entry.words.iter().map(|s| s.as_str()).collect();
    let all_match = query.words.iter().all(|w| entry_words.contains(w.as_str()));

    if all_match { Some(1.0) } else { None }
}

/// Contains: at least one query word token must be present.
/// Score = matched_words / total_query_words.
fn score_contains(query: &BlindTokenSet, entry: &BlindTokenSet) -> Option<f64> {
    if query.words.is_empty() {
        return None;
    }

    let entry_words: HashSet<&str> = entry.words.iter().map(|s| s.as_str()).collect();
    let matched = query
        .words
        .iter()
        .filter(|w| entry_words.contains(w.as_str()))
        .count();

    if matched > 0 {
        Some(matched as f64 / query.words.len() as f64)
    } else {
        None
    }
}

/// Trigram overlap scoring for prefix/fuzzy modes.
/// Score = matched_trigrams / total_query_trigrams.
/// Only returns a hit if score >= threshold.
fn score_trigram_overlap(
    query: &BlindTokenSet,
    entry: &BlindTokenSet,
    threshold: f64,
) -> Option<f64> {
    if query.trigrams.is_empty() {
        // Fall back to word matching if query has no trigrams (short query)
        return score_contains(query, entry);
    }

    let entry_trigrams: HashSet<&str> = entry.trigrams.iter().map(|s| s.as_str()).collect();
    let matched = query
        .trigrams
        .iter()
        .filter(|t| entry_trigrams.contains(t.as_str()))
        .count();

    let score = matched as f64 / query.trigrams.len() as f64;

    if score >= threshold {
        Some(score)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hmac_ops::blind_token_set;
    use shroudb_crypto::SecretBytes;
    use shroudb_veil_core::tokenizer::tokenize;

    fn blind(key: &SecretBytes, text: &str) -> BlindTokenSet {
        blind_token_set(key, &tokenize(text))
    }

    #[test]
    fn exact_match() {
        let key = SecretBytes::new(vec![0x42u8; 32]);
        let query = blind(&key, "hello world");
        let entry = blind(&key, "hello world foo");

        assert!(score_entry(MatchMode::Exact, &query, &entry).is_some());
    }

    #[test]
    fn exact_no_match() {
        let key = SecretBytes::new(vec![0x42u8; 32]);
        let query = blind(&key, "hello world");
        let entry = blind(&key, "goodbye planet");

        assert!(score_entry(MatchMode::Exact, &query, &entry).is_none());
    }

    #[test]
    fn exact_partial_no_match() {
        let key = SecretBytes::new(vec![0x42u8; 32]);
        let query = blind(&key, "hello world");
        let entry = blind(&key, "hello foo");

        // Only "hello" matches, not "world" — exact requires all
        assert!(score_entry(MatchMode::Exact, &query, &entry).is_none());
    }

    #[test]
    fn contains_partial_match() {
        let key = SecretBytes::new(vec![0x42u8; 32]);
        let query = blind(&key, "hello world");
        let entry = blind(&key, "hello foo");

        let score = score_entry(MatchMode::Contains, &query, &entry).unwrap();
        assert!((score - 0.5).abs() < 0.01); // 1 of 2 words matched
    }

    #[test]
    fn contains_no_match() {
        let key = SecretBytes::new(vec![0x42u8; 32]);
        let query = blind(&key, "hello");
        let entry = blind(&key, "goodbye");

        assert!(score_entry(MatchMode::Contains, &query, &entry).is_none());
    }

    #[test]
    fn fuzzy_similar_words() {
        let key = SecretBytes::new(vec![0x42u8; 32]);
        let query = blind(&key, "hello");
        let entry = blind(&key, "hellow"); // shares trigrams hel, ell, llo

        let score = score_entry(MatchMode::Fuzzy, &query, &entry);
        assert!(score.is_some(), "fuzzy should match similar words");
    }

    #[test]
    fn prefix_shared_start() {
        let key = SecretBytes::new(vec![0x42u8; 32]);
        let query = blind(&key, "hel");
        // "hel" has no trigrams (len=3 produces one: "hel")
        let entry = blind(&key, "hello"); // shares "hel" trigram

        let score = score_entry(MatchMode::Prefix, &query, &entry);
        assert!(score.is_some(), "prefix should match shared start");
    }
}
