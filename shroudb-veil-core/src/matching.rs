/// How to match query tokens against stored tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMode {
    /// All query word tokens must be present in the entry.
    Exact,
    /// At least one query word token must be present.
    Contains,
    /// Match using trigram overlap — captures prefix similarity.
    Prefix,
    /// Match using trigram overlap with a lower threshold — captures edit-distance similarity.
    Fuzzy,
}

impl MatchMode {
    /// Parse from a wire string (case-insensitive).
    pub fn parse(s: &str) -> Result<Self, String> {
        match s.to_lowercase().as_str() {
            "exact" => Ok(Self::Exact),
            "contains" => Ok(Self::Contains),
            "prefix" => Ok(Self::Prefix),
            "fuzzy" => Ok(Self::Fuzzy),
            _ => Err(format!(
                "unknown match mode: {s} (expected exact, contains, prefix, or fuzzy)"
            )),
        }
    }

    pub fn wire_name(&self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Contains => "contains",
            Self::Prefix => "prefix",
            Self::Fuzzy => "fuzzy",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_match_modes() {
        assert_eq!(MatchMode::parse("exact").unwrap(), MatchMode::Exact);
        assert_eq!(MatchMode::parse("CONTAINS").unwrap(), MatchMode::Contains);
        assert_eq!(MatchMode::parse("Prefix").unwrap(), MatchMode::Prefix);
        assert_eq!(MatchMode::parse("fuzzy").unwrap(), MatchMode::Fuzzy);
        assert!(MatchMode::parse("nope").is_err());
    }

    #[test]
    fn wire_names() {
        assert_eq!(MatchMode::Exact.wire_name(), "exact");
        assert_eq!(MatchMode::Contains.wire_name(), "contains");
        assert_eq!(MatchMode::Prefix.wire_name(), "prefix");
        assert_eq!(MatchMode::Fuzzy.wire_name(), "fuzzy");
    }
}
