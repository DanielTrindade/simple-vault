use url::Url;

/// Decides whether an operation target is covered by the targets the human authorized for an entry.
pub struct TargetPolicy;

impl TargetPolicy {
    pub fn is_target_allowed(authorized_targets: &[String], operation_target: &str) -> bool {
        if authorized_targets.is_empty() || operation_target.trim().is_empty() {
            return false;
        }

        if Self::is_url(operation_target) {
            return authorized_targets
                .iter()
                .filter(|t| Self::is_url(t))
                .any(|allowed| Self::url_covers(allowed, operation_target));
        }

        let executable = Self::normalize_path(operation_target);
        authorized_targets
            .iter()
            .filter(|t| !Self::is_url(t))
            .any(|allowed| Self::path_covers(allowed, executable))
    }

    pub fn is_url(value: &str) -> bool {
        let bytes = value.as_bytes();
        (bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"http://"))
            || (bytes.len() >= 8 && bytes[..8].eq_ignore_ascii_case(b"https://"))
    }

    fn url_covers(allowed: &str, target: &str) -> bool {
        let (Ok(allowed_uri), Ok(target_uri)) = (Url::parse(allowed), Url::parse(target)) else {
            return false;
        };

        if !Self::is_clean(&allowed_uri)
            || !Self::is_clean(&target_uri)
            || !allowed_uri.scheme().eq_ignore_ascii_case(target_uri.scheme())
            || !Self::hosts_equal(&allowed_uri, &target_uri)
            || allowed_uri.port_or_known_default() != target_uri.port_or_known_default()
        {
            return false;
        }

        let allowed_path = allowed_uri.path().trim_end_matches('/');
        let target_path = target_uri.path().trim_end_matches('/');
        let path_matches = allowed_path.is_empty()
            || target_path == allowed_path
            || (target_path.starts_with(allowed_path)
                && target_path.as_bytes().get(allowed_path.len()) == Some(&b'/'));
        if !path_matches {
            return false;
        }

        let allowed_query = Self::raw_query_with_mark(&allowed_uri);
        allowed_query.is_empty() || allowed_query == Self::raw_query_with_mark(&target_uri)
    }

    pub fn are_equivalent_urls(left: &str, right: &str) -> bool {
        let (Ok(left_uri), Ok(right_uri)) = (Url::parse(left), Url::parse(right)) else {
            return false;
        };
        if !Self::is_clean(&left_uri) || !Self::is_clean(&right_uri) {
            return false;
        }

        left_uri.scheme().eq_ignore_ascii_case(right_uri.scheme())
            && Self::hosts_equal(&left_uri, &right_uri)
            && left_uri.port_or_known_default() == right_uri.port_or_known_default()
            && left_uri.path() == right_uri.path()
            && Self::raw_query_with_mark(&left_uri) == Self::raw_query_with_mark(&right_uri)
    }

    fn is_clean(uri: &Url) -> bool {
        uri.username().is_empty() && uri.password().is_none() && uri.fragment().is_none()
    }

    fn hosts_equal(left: &Url, right: &Url) -> bool {
        match (left.host_str(), right.host_str()) {
            (Some(a), Some(b)) if !a.is_empty() => a.eq_ignore_ascii_case(b),
            _ => false,
        }
    }

    fn raw_query_with_mark(uri: &Url) -> String {
        match uri.query() {
            Some(q) if !q.is_empty() => format!("?{q}"),
            _ => String::new(),
        }
    }

    fn path_covers(allowed: &str, target: &str) -> bool {
        let normalized_allowed = Self::normalize_path(allowed);
        if normalized_allowed.ends_with(std::path::MAIN_SEPARATOR) {
            target
                .get(..normalized_allowed.len())
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(normalized_allowed))
        } else {
            normalized_allowed.eq_ignore_ascii_case(target)
        }
    }

    fn normalize_path(path: &str) -> &str {
        path.trim().trim_end_matches('/')
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_policy_preserves_case_sensitive_path_and_rejects_userinfo_and_fragment() {
        let allowed = vec!["https://example.com/Admin".to_owned()];
        assert!(!TargetPolicy::is_target_allowed(&allowed, "https://example.com/admin"));
        assert!(TargetPolicy::is_target_allowed(&allowed, "HTTPS://EXAMPLE.COM/Admin?x=1"));
        assert!(TargetPolicy::is_target_allowed(&allowed, "https://example.com/Admin/sub"));
        assert!(!TargetPolicy::is_target_allowed(&allowed, "https://example.com/Admin2"));
        assert!(!TargetPolicy::is_target_allowed(&allowed, "https://user@example.com/Admin"));
        assert!(!TargetPolicy::is_target_allowed(&allowed, "https://example.com/Admin#frag"));
    }
}
