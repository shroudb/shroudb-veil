//! Match engine for searching decrypted plaintext.
//!
//! Lightweight, zero-dependency matching suitable for chat message search.
//! All matching is case-insensitive.

/// How to match the query against decrypted text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// Exact equality (case-insensitive).
    Exact,
    /// Query is a substring of the text (case-insensitive).
    Contains,
    /// Text starts with the query (case-insensitive, word-boundary aware).
    Prefix,
    /// Fuzzy match using Levenshtein distance on word boundaries.
    Fuzzy { max_distance: u8 },
}

/// The result of a match attempt.
#[derive(Debug, Clone)]
pub struct MatchResult {
    /// Whether the text matched the query.
    pub matched: bool,
    /// Relevance score from 0.0 (no match) to 1.0 (exact match).
    pub score: f32,
}

impl MatchResult {
    fn no_match() -> Self {
        Self {
            matched: false,
            score: 0.0,
        }
    }
}

/// Trait for pluggable match strategies.
pub trait Matcher: Send + Sync {
    fn matches(&self, query: &str, text: &str) -> MatchResult;
}

/// The default match engine implementing all built-in modes.
pub struct DefaultMatcher {
    pub mode: MatchMode,
}

impl Matcher for DefaultMatcher {
    fn matches(&self, query: &str, text: &str) -> MatchResult {
        match self.mode {
            MatchMode::Exact => match_exact(query, text),
            MatchMode::Contains => match_contains(query, text),
            MatchMode::Prefix => match_prefix(query, text),
            MatchMode::Fuzzy { max_distance } => match_fuzzy(query, text, max_distance),
        }
    }
}

impl DefaultMatcher {
    pub fn new(mode: MatchMode) -> Self {
        Self { mode }
    }
}

fn match_exact(query: &str, text: &str) -> MatchResult {
    if query.eq_ignore_ascii_case(text) {
        MatchResult {
            matched: true,
            score: 1.0,
        }
    } else {
        MatchResult::no_match()
    }
}

fn match_contains(query: &str, text: &str) -> MatchResult {
    let query_lower = query.to_ascii_lowercase();
    let text_lower = text.to_ascii_lowercase();

    if text_lower.contains(&query_lower) {
        let score = query.len() as f32 / text.len().max(1) as f32;
        MatchResult {
            matched: true,
            score: score.min(1.0),
        }
    } else {
        MatchResult::no_match()
    }
}

fn match_prefix(query: &str, text: &str) -> MatchResult {
    let query_lower = query.to_ascii_lowercase();
    let text_lower = text.to_ascii_lowercase();

    // Check if any word in the text starts with the query.
    for word in text_lower.split_whitespace() {
        if word.starts_with(&query_lower) {
            let score = query.len() as f32 / word.len().max(1) as f32;
            return MatchResult {
                matched: true,
                score: score.min(1.0),
            };
        }
    }

    // Also check if the whole text starts with the query.
    if text_lower.starts_with(&query_lower) {
        let score = query.len() as f32 / text.len().max(1) as f32;
        return MatchResult {
            matched: true,
            score: score.min(1.0),
        };
    }

    MatchResult::no_match()
}

fn match_fuzzy(query: &str, text: &str, max_distance: u8) -> MatchResult {
    let query_lower = query.to_ascii_lowercase();
    let text_lower = text.to_ascii_lowercase();

    // First check for exact contains (best score).
    if text_lower.contains(&query_lower) {
        let score = query.len() as f32 / text.len().max(1) as f32;
        return MatchResult {
            matched: true,
            score: score.min(1.0),
        };
    }

    // Check each word for Levenshtein distance.
    let mut best_score: f32 = 0.0;
    let mut found = false;

    for word in text_lower.split_whitespace() {
        let dist = levenshtein(&query_lower, word);
        if dist <= max_distance as usize {
            found = true;
            let max_len = query_lower.len().max(word.len()).max(1);
            let word_score = 1.0 - (dist as f32 / max_len as f32);
            if word_score > best_score {
                best_score = word_score;
            }
        }
    }

    if found {
        MatchResult {
            matched: true,
            score: best_score,
        }
    } else {
        MatchResult::no_match()
    }
}

/// Compute the Levenshtein edit distance between two strings.
fn levenshtein(a: &str, b: &str) -> usize {
    let a_len = a.len();
    let b_len = b.len();

    if a_len == 0 {
        return b_len;
    }
    if b_len == 0 {
        return a_len;
    }

    let mut prev_row: Vec<usize> = (0..=b_len).collect();
    let mut curr_row = vec![0usize; b_len + 1];

    for (i, a_ch) in a.chars().enumerate() {
        curr_row[0] = i + 1;
        for (j, b_ch) in b.chars().enumerate() {
            let cost = if a_ch == b_ch { 0 } else { 1 };
            curr_row[j + 1] = (prev_row[j + 1] + 1)
                .min(curr_row[j] + 1)
                .min(prev_row[j] + cost);
        }
        std::mem::swap(&mut prev_row, &mut curr_row);
    }

    prev_row[b_len]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_match() {
        let m = DefaultMatcher::new(MatchMode::Exact);
        assert!(m.matches("hello", "Hello").matched);
        assert!(!m.matches("hello", "Hello world").matched);
    }

    #[test]
    fn contains_match() {
        let m = DefaultMatcher::new(MatchMode::Contains);
        let r = m.matches("dinner", "Want to grab dinner?");
        assert!(r.matched);
        assert!(r.score > 0.0);
        assert!(r.score < 1.0);

        assert!(!m.matches("breakfast", "Want to grab dinner?").matched);
    }

    #[test]
    fn contains_full_match_scores_high() {
        let m = DefaultMatcher::new(MatchMode::Contains);
        let r = m.matches("hello", "hello");
        assert!(r.matched);
        assert!((r.score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn prefix_match() {
        let m = DefaultMatcher::new(MatchMode::Prefix);
        assert!(m.matches("din", "Want to grab dinner?").matched);
        assert!(m.matches("wan", "Want to grab dinner?").matched);
        assert!(!m.matches("rab", "Want to grab dinner?").matched);
    }

    #[test]
    fn fuzzy_match_typo() {
        let m = DefaultMatcher::new(MatchMode::Fuzzy { max_distance: 2 });
        let r = m.matches("dinnr", "Want to grab dinner?");
        assert!(r.matched);
        assert!(r.score > 0.5);
    }

    #[test]
    fn fuzzy_no_match_too_distant() {
        let m = DefaultMatcher::new(MatchMode::Fuzzy { max_distance: 1 });
        assert!(!m.matches("xyz", "Want to grab dinner?").matched);
    }

    #[test]
    fn levenshtein_basic() {
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("abc", "abc"), 0);
        assert_eq!(levenshtein("dinner", "dinnr"), 1);
    }
}
