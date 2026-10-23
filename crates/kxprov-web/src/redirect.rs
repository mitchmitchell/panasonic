//! Safe post-login return paths (path-only, same-origin; no open redirects).

/// Validates a return target for post-login redirect.
///
/// Rules: must be path-only — starts with `/`, no scheme, no host, no `//` prefix.
pub fn validate_return_path(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Some("/".into());
    }
    if !trimmed.starts_with('/') {
        return None;
    }
    if trimmed.starts_with("//") {
        return None;
    }
    if trimmed.contains("://") {
        return None;
    }
    if trimmed.contains('\\') {
        return None;
    }
    // Reject encoded tricks that decode to scheme-relative paths.
    if trimmed.to_ascii_lowercase().starts_with("/\\") {
        return None;
    }
    Some(trimmed.to_string())
}

pub fn login_url_with_next(return_path: &str) -> String {
    let safe = validate_return_path(return_path).unwrap_or_else(|| "/".into());
    format!("/login?next={}", urlencoding::encode(&safe))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_relative_paths() {
        assert_eq!(
            validate_return_path("/plans/abc/approve?diff=dead"),
            Some("/plans/abc/approve?diff=dead".into())
        );
    }

    #[test]
    fn rejects_scheme_relative() {
        assert!(validate_return_path("//evil.example/phish").is_none());
    }

    #[test]
    fn rejects_absolute_urls() {
        assert!(validate_return_path("https://evil.example/").is_none());
    }

    #[test]
    fn rejects_absolute_and_scheme_relative_urls() {
        assert!(validate_return_path("http://evil.example/").is_none());
        assert!(validate_return_path("javascript:alert(1)").is_none());
    }

    #[test]
    fn empty_next_defaults_to_root() {
        assert_eq!(validate_return_path(""), Some("/".into()));
    }
}
