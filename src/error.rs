use serde::{Deserialize, Serialize};

/// Detailed rate limit information extracted from HTTP 429 response headers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RateLimitError {
    /// Recommended retry wait duration in seconds (from `Retry-After`).
    pub retry_after: Option<u64>,
    /// Request limit quota per window (from `RateLimit-Limit`).
    pub limit: Option<u64>,
    /// Remaining request quota in current window (from `RateLimit-Remaining`).
    pub remaining: Option<u64>,
    /// Window reset time in Unix timestamp (seconds since epoch) (from `RateLimit-Reset`).
    pub reset: Option<u64>,
}

/// Error type returned by the XYO SDK client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientError {
    pub message: String,
    pub code: u16,
    pub rate_limit: Option<RateLimitError>,
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref rl) = self.rate_limit {
            write!(
                f,
                "ClientError (code {}): {} [rate_limit: retry_after={:?}, limit={:?}, remaining={:?}, reset={:?}]",
                self.code, self.message, rl.retry_after, rl.limit, rl.remaining, rl.reset
            )
        } else {
            write!(f, "ClientError (code {}): {}", self.code, self.message)
        }
    }
}

impl std::error::Error for ClientError {}

impl ClientError {
    /// Construct a new `ClientError` without rate limit details.
    pub fn new(code: u16, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            rate_limit: None,
        }
    }

    /// Construct a new `ClientError` with rate limit details.
    pub fn with_rate_limit(
        code: u16,
        message: impl Into<String>,
        rate_limit: RateLimitError,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            rate_limit: Some(rate_limit),
        }
    }

    /// Returns true if this error represents an authentication or authorization failure (HTTP 401 or 403).
    pub fn is_auth(&self) -> bool {
        self.code == 401 || self.code == 403
    }

    /// Returns true if this error represents a rate limit or throttle (HTTP 429).
    pub fn is_rate_limited(&self) -> bool {
        self.code == 429
    }

    /// Returns true if this error represents a resource not found (HTTP 404).
    pub fn is_not_found(&self) -> bool {
        self.code == 404
    }

    /// Returns true if this error represents an internal server error (HTTP 5xx).
    pub fn is_server_error(&self) -> bool {
        (500..600).contains(&self.code)
    }

    /// Returns true if the operation is transient and safe to retry.
    pub fn is_retryable(&self) -> bool {
        self.is_rate_limited()
            || self.is_server_error()
            || (self.code == 0
                && (self.message.to_ascii_lowercase().contains("timed out")
                    || self.message.to_ascii_lowercase().contains("timeout")
                    || self.message.to_ascii_lowercase().contains("connection reset")
                    || self.message.to_ascii_lowercase().contains("network stream error")))
    }
}

/// Parse a `Retry-After` header value which can be either an integer duration in seconds or an HTTP-date string.
pub fn parse_retry_after(s: &str) -> Option<u64> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(secs) = trimmed.parse::<u64>() {
        return Some(secs);
    }
    if let Ok(system_time) = httpdate::parse_http_date(trimmed) {
        let now = std::time::SystemTime::now();
        let secs = system_time
            .duration_since(now)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        return Some(secs);
    }
    None
}

/// Helper to extract RateLimit header values from an HTTP response HeaderMap into `RateLimitError`.
pub fn extract_rate_limit_headers(headers: &reqwest::header::HeaderMap) -> Option<RateLimitError> {
    let parse_u64 = |keys: &[&str]| -> Option<u64> {
        for &k in keys {
            if let Some(val) = headers.get(k) {
                if let Ok(s) = val.to_str() {
                    let trimmed = s.trim();
                    if !trimmed.is_empty() {
                        if let Ok(n) = trimmed.parse::<u64>() {
                            return Some(n);
                        }
                    }
                }
            }
        }
        None
    };

    let parse_retry_after_from_headers = |keys: &[&str]| -> Option<u64> {
        for &k in keys {
            if let Some(val) = headers.get(k) {
                if let Ok(s) = val.to_str() {
                    if let Some(secs) = parse_retry_after(s) {
                        return Some(secs);
                    }
                }
            }
        }
        None
    };

    let retry_after = parse_retry_after_from_headers(&["retry-after", "x-retry-after"]);
    let limit = parse_u64(&["ratelimit-limit", "x-ratelimit-limit", "x-rate-limit-limit"]);
    let remaining = parse_u64(&["ratelimit-remaining", "x-ratelimit-remaining", "x-rate-limit-remaining"]);
    let reset = parse_u64(&["ratelimit-reset", "x-ratelimit-reset", "x-rate-limit-reset"]);

    if retry_after.is_some() || limit.is_some() || remaining.is_some() || reset.is_some() {
        Some(RateLimitError {
            retry_after,
            limit,
            remaining,
            reset,
        })
    } else {
        None
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_error_display() {
        let err = ClientError::new(404, "Not Found");
        assert_eq!(format!("{}", err), "ClientError (code 404): Not Found");
    }

    #[test]
    fn test_client_error_debug() {
        let err = ClientError::new(500, "Internal Error");
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("500"));
        assert!(debug_str.contains("Internal Error"));
    }

    #[test]
    fn test_client_error_classification_methods() {
        let auth_err = ClientError::new(401, "Unauthorized");
        assert!(auth_err.is_auth());
        assert!(!auth_err.is_server_error());
        assert!(!auth_err.is_retryable());

        let forbidden_err = ClientError::new(403, "Forbidden");
        assert!(forbidden_err.is_auth());

        let rate_err = ClientError::new(429, "Too Many Requests");
        assert!(rate_err.is_rate_limited());
        assert!(rate_err.is_retryable());

        let server_err = ClientError::new(503, "Service Unavailable");
        assert!(server_err.is_server_error());
        assert!(server_err.is_retryable());

        let timeout_err = ClientError::new(0, "operation timed out after 30s");
        assert!(timeout_err.is_retryable());
    }

    #[test]
    fn test_client_error_clone_and_eq() {
        let err1 = ClientError::new(400, "Bad Request");
        let err2 = err1.clone();
        assert_eq!(err1, err2);
        assert_eq!(err1.code, 400);
        assert_eq!(err1.message, "Bad Request");

        let err3 = ClientError::new(401, "Unauthorized");
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_client_error_implements_std_error() {
        let err: Box<dyn std::error::Error> = Box::new(ClientError::new(403, "Forbidden"));
        assert_eq!(format!("{}", err), "ClientError (code 403): Forbidden");
        assert!(err.source().is_none());
    }

    #[test]
    fn test_extract_rate_limit_headers() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Retry-After", "60".parse().unwrap());
        headers.insert("RateLimit-Limit", "1000".parse().unwrap());
        headers.insert("RateLimit-Remaining", "5".parse().unwrap());
        headers.insert("RateLimit-Reset", "1700000000".parse().unwrap());

        let rl = extract_rate_limit_headers(&headers).expect("should extract rate limit headers");
        assert_eq!(rl.retry_after, Some(60));
        assert_eq!(rl.limit, Some(1000));
        assert_eq!(rl.remaining, Some(5));
        assert_eq!(rl.reset, Some(1700000000));

        let err_with_rl = ClientError::with_rate_limit(429, "Rate limit exceeded", rl);
        assert!(err_with_rl.is_rate_limited());
        assert!(err_with_rl.rate_limit.is_some());
        assert_eq!(err_with_rl.rate_limit.as_ref().unwrap().retry_after, Some(60));
        assert!(format!("{}", err_with_rl).contains("[rate_limit: retry_after=Some(60)"));
    }

    #[test]
    fn test_parse_retry_after_http_date() {
        assert_eq!(parse_retry_after("120"), Some(120));
        assert_eq!(parse_retry_after("Wed, 21 Oct 2015 07:28:00 GMT"), Some(0));

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert("Retry-After", "Wed, 21 Oct 2015 07:28:00 GMT".parse().unwrap());
        let rl = extract_rate_limit_headers(&headers).expect("should parse HTTP-date Retry-After");
        assert_eq!(rl.retry_after, Some(0));
    }
}


