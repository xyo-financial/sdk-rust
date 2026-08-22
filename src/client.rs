//! XYO Financial SDK – thin async wrapper over the OpenAPI-generated client.
//!
//! # Example
//! ```no_run
//! use xyo_sdk::client::{Client, EnrichmentRequest};
//!
//! #[tokio::main]
//! async fn main() {
//!     let client = Client::new("your-bearer-token", None).unwrap();
//!     let resp = client.enrich_transaction("COSTA PICKUP", "GB").await.unwrap();
//!     println!("{}", resp.merchant);
//! }
//! ```

use std::time::Duration;
use xyo_openapi_client::apis::configuration::Configuration;
use xyo_openapi_client::apis::enrichment_api;
use xyo_openapi_client::models::{EnrichmentRequest as ApiEnrichmentRequest, EnrichTransactionsRequestInner};
use serde::{Deserialize, Serialize};

use crate::error::{extract_rate_limit_headers, ClientError, RateLimitError};

/// Optional per-request configuration options (e.g. distributed tracing headers, tenant user ID).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RequestOptions {
    /// Distributed tracing correlation identifier (`X-Correlation-ID` header).
    pub correlation_id: Option<String>,
    /// Distributed tracing traceparent header (`traceparent` header, W3C format).
    pub traceparent: Option<String>,
    /// Optional tenant user identifier (`x-api-user` header).
    ///
    /// Note: `api_user` is specifically used for bulk/batch operations (e.g. `enrich_transactions` and `get_enrichment_status`).
    pub api_user: Option<String>,
}

impl RequestOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }

    pub fn traceparent(mut self, traceparent: impl Into<String>) -> Self {
        self.traceparent = Some(traceparent.into());
        self
    }

    pub fn api_user(mut self, api_user: impl Into<String>) -> Self {
        self.api_user = Some(api_user.into());
        self
    }
}

// ── Null-safe string deserialization ──────────────────────────────────────────

fn deserialize_null_as_empty_string<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let opt = Option::<String>::deserialize(deserializer)?;
    Ok(opt.unwrap_or_default())
}

// ── Re-exported response types ────────────────────────────────────────────────

/// Response from a single-transaction enrichment.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrichmentResponse {
    #[serde(default, deserialize_with = "deserialize_null_as_empty_string")]
    pub merchant: String,
    #[serde(default, deserialize_with = "deserialize_null_as_empty_string")]
    pub description: String,
    #[serde(default)]
    pub categories: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_null_as_empty_string")]
    pub logo: String,
    /// Empty string when the API returns null / empty.
    #[serde(default, deserialize_with = "deserialize_null_as_empty_string")]
    pub location: String,
    /// Empty string when the API returns null / empty.
    #[serde(default, deserialize_with = "deserialize_null_as_empty_string")]
    pub address: String,
}

/// Response from a bulk enrichment submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichTransactionCollectionResponse {
    /// Work-item ID used to poll for completion.
    pub id: String,
    /// URL of the downloadable tar.gz results archive.
    pub link: String,
}

/// Processing state of a bulk enrichment job.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EnrichmentStatus {
    Ready,
    Pending,
    Failed,
}

/// A single transaction to submit for enrichment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentRequest {
    /// Payment description (max 128 chars).
    pub content: String,
    /// ISO 3166-1 alpha-2 country code (e.g. "GB").
    pub country_code: String,
}

impl EnrichmentRequest {
    /// Construct a new enrichment request.
    pub fn new(content: impl Into<String>, country_code: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            country_code: country_code.into(),
        }
    }

    /// Validate client-side field constraints before submission.
    pub fn validate(&self) -> Result<(), ClientError> {
        let content = self.content.trim();
        if content.is_empty() {
            return Err(ClientError::new(0, "request content must not be empty"));
        }
        if content.chars().count() > 128 {
            return Err(ClientError::new(
                0,
                "request content exceeds maximum length of 128 characters",
            ));
        }
        let country = self.country_code.trim();
        if country.is_empty() {
            return Err(ClientError::new(
                0,
                "request country_code must not be empty",
            ));
        }
        if country.chars().count() != 2 {
            return Err(ClientError::new(
                0,
                "request country_code must be a 2-letter ISO 3166-1 alpha-2 code",
            ));
        }
        Ok(())
    }
}

// ── Security Policy & Constants ───────────────────────────────────────────────

pub const DEFAULT_MAX_TAR_ENTRIES: usize = 50_000;
pub const DEFAULT_MAX_ENTRY_BYTES: u64 = 10 * 1024 * 1024; // 10 MiB
pub const DEFAULT_MAX_ARCHIVE_BYTES: usize = 100 * 1024 * 1024; // 100 MiB
pub const DEFAULT_USER_AGENT: &str = "xyo-sdk-rust/2.0.0";

/// Security policy governing permitted hosts for archive downloads.
#[derive(Debug, Clone)]
pub struct DownloadSecurityPolicy {
    /// List of explicitly allowed hostnames or domain suffixes.
    pub allowed_hosts: Vec<String>,
    /// Automatically allow downloading from the configured API base host.
    pub allow_same_origin: bool,
}

impl Default for DownloadSecurityPolicy {
    fn default() -> Self {
        Self {
            allowed_hosts: vec![
                "api.xyo.financial".to_string(),
                "download.xyo.financial".to_string(),
            ],
            allow_same_origin: true,
        }
    }
}

impl DownloadSecurityPolicy {
    /// Checks whether `target_host` is permitted under this policy.
    pub fn is_allowed(&self, target_host: &str, api_host: &str) -> bool {
        let target_lower = target_host.to_ascii_lowercase();
        if self.allow_same_origin && !api_host.is_empty() && target_lower.eq_ignore_ascii_case(api_host) {
            return true;
        }
        for allowed in &self.allowed_hosts {
            let allowed_lower = allowed.to_ascii_lowercase();
            if target_lower == allowed_lower
                || target_lower.ends_with(&format!(".{}", allowed_lower))
            {
                return true;
            }
        }
        false
    }
}

/// Sanitizes tar entry name for error messages to prevent CWE-117 log injection.
fn sanitize_entry_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_control() { '_' } else { c })
        .collect()
}

fn validate_header_value(val: Option<&str>) -> Result<(), ClientError> {
    if let Some(v) = val {
        if v.contains('\r') || v.contains('\n') {
            return Err(ClientError::new(
                0,
                "header value contains invalid CRLF characters",
            ));
        }
    }
    Ok(())
}

fn validate_api_user(api_user: Option<&str>) -> Result<(), ClientError> {
    validate_header_value(api_user)
}

type TokenSupplier = std::sync::Arc<dyn Fn() -> String + Send + Sync>;

// ── ClientBuilder ─────────────────────────────────────────────────────────────

/// Builder for creating and customizing an async [`Client`].
pub struct ClientBuilder {
    bearer_token: Option<String>,
    token_supplier: Option<TokenSupplier>,
    base_url: Option<String>,
    user_agent: Option<String>,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    download_policy: DownloadSecurityPolicy,
    custom_http_client: Option<reqwest::Client>,
    correlation_id: Option<String>,
    traceparent: Option<String>,
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl ClientBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            bearer_token: None,
            token_supplier: None,
            base_url: None,
            user_agent: Some(DEFAULT_USER_AGENT.to_string()),
            timeout: Some(Duration::from_secs(30)),
            connect_timeout: Some(Duration::from_secs(10)),
            download_policy: DownloadSecurityPolicy::default(),
            custom_http_client: None,
            correlation_id: None,
            traceparent: None,
        }
    }

    /// Set static Bearer API token.
    pub fn token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    /// Set dynamic Bearer token rotation supplier.
    pub fn token_supplier<F>(mut self, supplier: F) -> Self
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        self.token_supplier = Some(std::sync::Arc::new(supplier));
        self
    }

    /// Override the API base URL.
    pub fn base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = Some(base_url.into());
        self
    }

    /// Set custom User-Agent header string.
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Set request timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Set connect timeout.
    pub fn connect_timeout(mut self, connect_timeout: Duration) -> Self {
        self.connect_timeout = Some(connect_timeout);
        self
    }

    /// Add an explicitly permitted host for archive downloads.
    pub fn allow_download_host(mut self, host: impl Into<String>) -> Self {
        self.download_policy.allowed_hosts.push(host.into());
        self
    }

    /// Replace the entire archive download security policy.
    pub fn download_policy(mut self, policy: DownloadSecurityPolicy) -> Self {
        self.download_policy = policy;
        self
    }

    /// Provide a custom pre-configured `reqwest::Client`.
    pub fn custom_http_client(mut self, client: reqwest::Client) -> Self {
        self.custom_http_client = Some(client);
        self
    }

    /// Set default distributed tracing correlation ID (`X-Correlation-ID` header).
    pub fn correlation_id(mut self, correlation_id: impl Into<String>) -> Self {
        self.correlation_id = Some(correlation_id.into());
        self
    }

    /// Set default distributed tracing traceparent header (`traceparent` header, W3C format).
    pub fn traceparent(mut self, traceparent: impl Into<String>) -> Self {
        self.traceparent = Some(traceparent.into());
        self
    }

    /// Build the configured [`Client`].
    pub fn build(self) -> Result<Client, ClientError> {
        let http_client = if let Some(client) = self.custom_http_client {
            client
        } else {
            let mut builder = reqwest::Client::builder();
            if let Some(to) = self.timeout {
                builder = builder.timeout(to);
            }
            if let Some(cto) = self.connect_timeout {
                builder = builder.connect_timeout(cto);
            }
            builder.build().map_err(|e| ClientError::new(0, format!("Failed to build HTTP client: {}", e)))?
        };

        let mut configuration = Configuration::new();
        configuration.client = http_client;
        configuration.bearer_access_token = self.bearer_token;
        configuration.user_agent = self.user_agent;

        let effective_url = self
            .base_url
            .or_else(|| std::env::var("XYO_API_BASE_URL").ok())
            .unwrap_or_else(|| "https://api.xyo.financial".to_string());
        configuration.base_path = effective_url.trim_end_matches('/').to_string();

        Ok(Client {
            configuration,
            token_supplier: self.token_supplier,
            download_policy: self.download_policy,
            default_correlation_id: self.correlation_id,
            default_traceparent: self.traceparent,
        })
    }
}

impl std::fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("base_url", &self.base_url)
            .field("bearer_token", &"[REDACTED]")
            .field("user_agent", &self.user_agent)
            .field("timeout", &self.timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("download_policy", &self.download_policy)
            .field("correlation_id", &self.correlation_id)
            .field("traceparent", &self.traceparent)
            .finish()
    }
}

// ── Client ────────────────────────────────────────────────────────────────────

/// Async client for the XYO Financial Transaction Enrichment API.
#[derive(Clone)]
pub struct Client {
    configuration: Configuration,
    token_supplier: Option<TokenSupplier>,
    download_policy: DownloadSecurityPolicy,
    default_correlation_id: Option<String>,
    default_traceparent: Option<String>,
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("base_url", &self.configuration.base_path)
            .field("bearer_token", &"[REDACTED]")
            .field("user_agent", &self.configuration.user_agent)
            .field("download_policy", &self.download_policy)
            .finish()
    }
}

impl Client {
    /// Construct a new client builder.
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    /// Construct a new client with default settings.
    ///
    /// * `bearer_token` – the API Bearer token.
    /// * `base_url`     – override the server URL (default: XYO_API_BASE_URL env or `https://api.xyo.financial`).
    pub fn new(bearer_token: impl Into<String>, base_url: Option<String>) -> Result<Self, ClientError> {
        let mut builder = Client::builder().token(bearer_token);
        if let Some(url) = base_url {
            builder = builder.base_url(url);
        }
        builder.build()
    }

    /// Construct a new client with dynamic token rotation supplier.
    pub fn with_token_supplier<F>(supplier: F, base_url: Option<String>) -> Result<Self, ClientError>
    where
        F: Fn() -> String + Send + Sync + 'static,
    {
        let mut builder = Client::builder().token_supplier(supplier);
        if let Some(url) = base_url {
            builder = builder.base_url(url);
        }
        builder.build()
    }

    fn get_effective_config(&self) -> Configuration {
        let mut config = self.configuration.clone();
        if let Some(ref supplier) = self.token_supplier {
            config.bearer_access_token = Some(supplier());
        }
        config
    }

    // ── enrichTransaction ─────────────────────────────────────────────────────

    /// Enrich a single financial transaction synchronously.
    pub async fn enrich_transaction(
        &self,
        content: impl Into<String>,
        country_code: impl Into<String>,
    ) -> Result<EnrichmentResponse, ClientError> {
        self.enrich_transaction_with_options(content, country_code, None).await
    }

    /// Enrich a single financial transaction synchronously with per-request options (distributed tracing, tenant user ID).
    pub async fn enrich_transaction_with_options(
        &self,
        content: impl Into<String>,
        country_code: impl Into<String>,
        options: Option<&RequestOptions>,
    ) -> Result<EnrichmentResponse, ClientError> {
        let content_str = content.into();
        let country_str = country_code.into();
        let req = EnrichmentRequest::new(&content_str, &country_str);
        req.validate()?;

        if let Some(opts) = options {
            if opts.api_user.is_some() {
                return Err(ClientError::new(
                    0,
                    "`api_user` is only applicable to bulk operations",
                ));
            }
        }

        let corr_id = options
            .and_then(|o| o.correlation_id.as_deref())
            .or(self.default_correlation_id.as_deref());
        let traceparent = options
            .and_then(|o| o.traceparent.as_deref())
            .or(self.default_traceparent.as_deref());

        validate_header_value(corr_id)?;
        validate_header_value(traceparent)?;

        tracing::debug!(country = %country_str, ?corr_id, ?traceparent, "enrich_transaction executing");

        let body = ApiEnrichmentRequest::new(content_str, country_str);
        let config = self.get_effective_config();

        let resp = enrichment_api::enrich_transaction(&config, body, corr_id, traceparent)
            .await
            .map_err(map_error)?;

        Ok(EnrichmentResponse {
            merchant: resp.merchant,
            description: resp.description,
            categories: resp.categories,
            logo: resp.logo,
            location: resp.location,
            address: resp.address,
        })
    }

    // ── enrichTransactions ────────────────────────────────────────────────────

    /// Enrich a collection of financial transactions asynchronously.
    ///
    /// Returns a job `id` that can be polled with [`Client::get_enrichment_status`].
    pub async fn enrich_transactions(
        &self,
        requests: impl IntoIterator<Item = EnrichmentRequest>,
        api_user: Option<&str>,
    ) -> Result<EnrichTransactionCollectionResponse, ClientError> {
        let mut opts = RequestOptions::default();
        if let Some(user) = api_user {
            opts = opts.api_user(user);
        }
        self.enrich_transactions_with_options(requests, Some(&opts)).await
    }

    /// Enrich a collection of financial transactions asynchronously with per-request options.
    pub async fn enrich_transactions_with_options(
        &self,
        requests: impl IntoIterator<Item = EnrichmentRequest>,
        options: Option<&RequestOptions>,
    ) -> Result<EnrichTransactionCollectionResponse, ClientError> {
        let api_user = options.and_then(|o| o.api_user.as_deref());
        validate_api_user(api_user)?;

        let corr_id = options
            .and_then(|o| o.correlation_id.as_deref())
            .or(self.default_correlation_id.as_deref());
        let traceparent = options
            .and_then(|o| o.traceparent.as_deref())
            .or(self.default_traceparent.as_deref());

        validate_header_value(corr_id)?;
        validate_header_value(traceparent)?;

        let iter = requests.into_iter();
        let (lower, upper) = iter.size_hint();
        let initial_capacity = upper.unwrap_or(lower).min(DEFAULT_MAX_TAR_ENTRIES);
        let mut items = Vec::with_capacity(initial_capacity);

        for (i, req) in iter.enumerate() {
            if i >= DEFAULT_MAX_TAR_ENTRIES {
                return Err(ClientError::new(
                    0,
                    format!(
                        "requests batch size exceeds maximum allowed limit of {} items",
                        DEFAULT_MAX_TAR_ENTRIES
                    ),
                ));
            }
            req.validate().map_err(|e| ClientError::new(
                0,
                format!("request at index {} is invalid: {}", i, e.message),
            ))?;
            items.push(EnrichTransactionsRequestInner {
                content: req.content,
                country_code: req.country_code,
            });
        }

        if items.is_empty() {
            return Err(ClientError::new(0, "requests batch cannot be empty"));
        }

        tracing::debug!(batch_size = items.len(), user = ?api_user, ?corr_id, ?traceparent, "enrich_transactions batch submission");

        let config = self.get_effective_config();

        let resp = enrichment_api::enrich_transactions(&config, items, api_user, corr_id, traceparent)
            .await
            .map_err(map_error)?;

        Ok(EnrichTransactionCollectionResponse {
            id: resp.id,
            link: resp.link,
        })
    }

    // ── getEnrichmentStatus ───────────────────────────────────────────────────

    /// Get the status of an asynchronous bulk enrichment job.
    pub async fn get_enrichment_status(
        &self,
        id: &str,
        api_user: Option<&str>,
    ) -> Result<EnrichmentStatus, ClientError> {
        let mut opts = RequestOptions::default();
        if let Some(user) = api_user {
            opts = opts.api_user(user);
        }
        self.get_enrichment_status_with_options(id, Some(&opts)).await
    }

    /// Get the status of an asynchronous bulk enrichment job with per-request options.
    pub async fn get_enrichment_status_with_options(
        &self,
        id: &str,
        options: Option<&RequestOptions>,
    ) -> Result<EnrichmentStatus, ClientError> {
        let api_user = options.and_then(|o| o.api_user.as_deref());
        validate_api_user(api_user)?;

        let corr_id = options
            .and_then(|o| o.correlation_id.as_deref())
            .or(self.default_correlation_id.as_deref());
        let traceparent = options
            .and_then(|o| o.traceparent.as_deref())
            .or(self.default_traceparent.as_deref());

        validate_header_value(corr_id)?;
        validate_header_value(traceparent)?;

        tracing::debug!(job_id = %id, user = ?api_user, ?corr_id, ?traceparent, "get_enrichment_status polling");

        let config = self.get_effective_config();
        let resp = enrichment_api::get_enrichment_status(&config, id, api_user, corr_id, traceparent)
            .await
            .map_err(map_error)?;

        use xyo_openapi_client::models::enrichment_collection_status_response::Status;
        Ok(match resp.status {
            Status::Ready => EnrichmentStatus::Ready,
            Status::Pending => EnrichmentStatus::Pending,
            Status::Failed => EnrichmentStatus::Failed,
        })
    }

    // ── downloadEnrichmentCollection ──────────────────────────────────────────

    /// Download and unpack an enrichment collection archive (`.tar.gz`) from a bulk job.
    ///
    /// Performs an HTTP GET request to `download_url` with host-isolated Bearer authentication
    /// and multi-MIME stream negotiation, decompresses the archive with decompression bomb
    /// and Zip Slip defenses, and parses each `.json` file into an [`EnrichmentResponse`].
    pub async fn download_enrichment_collection(
        &self,
        download_url: &str,
    ) -> Result<Vec<EnrichmentResponse>, ClientError> {
        let trimmed_url = download_url.trim();
        if trimmed_url.is_empty() {
            return Err(ClientError::new(0, "download_url cannot be empty"));
        }

        let parsed_download_url = if let Ok(parsed) = url::Url::parse(trimmed_url) {
            if parsed.scheme() == "http" || parsed.scheme() == "https" {
                parsed
            } else if !parsed.scheme().is_empty() && (trimmed_url.contains("://") || trimmed_url.starts_with("javascript:") || trimmed_url.starts_with("data:")) {
                return Err(ClientError::new(
                    0,
                    format!("Unsupported URL scheme {:?} (only http and https are permitted)", parsed.scheme()),
                ));
            } else {
                let base_clean = self.configuration.base_path.trim_end_matches('/');
                let rel_clean = trimmed_url.trim_start_matches('/');
                url::Url::parse(&format!("{}/{}", base_clean, rel_clean)).map_err(|e| ClientError::new(
                    0,
                    format!("Invalid download URL: {}", e),
                ))?
            }
        } else {
            let base_clean = self.configuration.base_path.trim_end_matches('/');
            let rel_clean = trimmed_url.trim_start_matches('/');
            url::Url::parse(&format!("{}/{}", base_clean, rel_clean)).map_err(|e| ClientError::new(
                0,
                format!("Invalid download URL: {}", e),
            ))?
        };

        let scheme = parsed_download_url.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(ClientError::new(
                0,
                format!("Unsupported URL scheme {:?} (only http and https are permitted)", scheme),
            ));
        }

        let mut req_builder = self.configuration.client.get(parsed_download_url.as_str());

        if let Some(ref user_agent) = self.configuration.user_agent {
            req_builder = req_builder.header(reqwest::header::USER_AGENT, user_agent);
        }

        // Validate permitted domain for secure archive download policy and attach auth only for same-origin API host
        let mut attach_auth = false;
        let down_host = parsed_download_url.host_str().unwrap_or("");
        let base_url_parsed = url::Url::parse(&self.configuration.base_path).ok();
        let api_host = base_url_parsed
            .as_ref()
            .and_then(|u| u.host_str())
            .unwrap_or("");

        if !self.download_policy.is_allowed(down_host, api_host) {
            return Err(ClientError::new(
                0,
                format!("domain {:?} is not permitted for secure archive downloads", down_host),
            ));
        }

        if let Some(ref base_parsed) = base_url_parsed {
            if let Some(base_h) = base_parsed.host_str() {
                let down_port = parsed_download_url.port_or_known_default();
                let base_port = base_parsed.port_or_known_default();
                if down_host.eq_ignore_ascii_case(base_h) && down_port == base_port {
                    attach_auth = true;
                }
            }
        }

        if attach_auth {
            let current_token = self
                .token_supplier
                .as_ref()
                .map(|s| s())
                .or_else(|| self.configuration.bearer_access_token.clone());
            if let Some(ref token) = current_token {
                req_builder = req_builder.bearer_auth(token);
            }
        }

        req_builder = req_builder.header(
            reqwest::header::ACCEPT,
            "application/gzip, application/x-tar, application/octet-stream;q=0.9, */*;q=0.8",
        );

        let resp = req_builder.send().await.map_err(|e| ClientError::new(
            e.status().map(|s| s.as_u16()).unwrap_or(0),
            e.to_string(),
        ))?;

        let status = resp.status();
        if status.is_client_error() || status.is_server_error() {
            let code = status.as_u16();
            let rate_limit = extract_rate_limit_headers(resp.headers())
                .or_else(|| if code == 429 { Some(RateLimitError::default()) } else { None });
            let message = resp.text().await.unwrap_or_default();
            return Err(ClientError {
                code,
                message,
                rate_limit,
            });
        }

        // Validate Content-Type header to diagnose intermediate proxy/WAF challenge pages
        let content_type = resp
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if let Some(ref ct_str) = content_type {
            let ct_lower = ct_str.to_lowercase();
            if !ct_lower.contains("gzip")
                && !ct_lower.contains("tar")
                && !ct_lower.contains("octet-stream")
                && !ct_lower.contains("binary")
            {
                return Err(ClientError::new(
                    status.as_u16(),
                    format!(
                        "Unexpected Content-Type {:?} received when expecting binary archive",
                        ct_str
                    ),
                ));
            }
        }

        // Early check for Content-Length header to prevent buffering oversized payloads
        if let Some(content_length) = resp.content_length() {
            if content_length > DEFAULT_MAX_ARCHIVE_BYTES as u64 {
                return Err(ClientError::new(
                    0,
                    format!(
                        "Content-Length ({} bytes) exceeds maximum limit of {} bytes",
                        content_length, DEFAULT_MAX_ARCHIVE_BYTES
                    ),
                ));
            }
        }

        // Stream chunks into buffer with strict byte limit guard
        let initial_capacity = resp
            .content_length()
            .and_then(|l| usize::try_from(l).ok())
            .unwrap_or(0)
            .min(DEFAULT_MAX_ARCHIVE_BYTES);
        let mut buffer = Vec::with_capacity(initial_capacity);

        let mut resp = resp;
        while let Some(chunk) = resp.chunk().await.map_err(|e| ClientError::new(
            e.status().map(|s| s.as_u16()).unwrap_or(0),
            format!("Network stream error: {}", e),
        ))? {
            if buffer.len() + chunk.len() > DEFAULT_MAX_ARCHIVE_BYTES {
                return Err(ClientError::new(
                    0,
                    format!(
                        "Compressed archive exceeded maximum allowed size of {} bytes",
                        DEFAULT_MAX_ARCHIVE_BYTES
                    ),
                ));
            }
            buffer.extend_from_slice(&chunk);
        }

        // Offload synchronous CPU-intensive gzip decompression, tar unpacking, and JSON deserialization to blocking threadpool
        let results = tokio::task::spawn_blocking(move || -> Result<Vec<EnrichmentResponse>, ClientError> {
            let gz_decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(buffer));
            let mut archive = tar::Archive::new(gz_decoder);

            let entries = archive.entries().map_err(|e| ClientError::new(
                0,
                format!("Failed to read tar archive: {}", e),
            ))?;

            let mut results = Vec::new();
            let mut entry_count: usize = 0;

            for entry_res in entries {
                entry_count += 1;
                if entry_count > DEFAULT_MAX_TAR_ENTRIES {
                    return Err(ClientError::new(
                        0,
                        format!("Archive contains too many entries (exceeded limit of {})", DEFAULT_MAX_TAR_ENTRIES),
                    ));
                }

                let mut entry = entry_res.map_err(|e| ClientError::new(
                    0,
                    format!("Failed to read tar entry: {}", e),
                ))?;

                let entry_size = entry.header().size().unwrap_or(0);
                if entry_size > DEFAULT_MAX_ENTRY_BYTES {
                    let name = entry.path().map(|p| p.display().to_string()).unwrap_or_default();
                    return Err(ClientError::new(
                        0,
                        format!("Entry {:?} size ({} bytes) exceeds limit of {} bytes", sanitize_entry_name(&name), entry_size, DEFAULT_MAX_ENTRY_BYTES),
                    ));
                }

                let is_file = entry.header().entry_type().is_file();
                let path_buf = entry
                    .path()
                    .map_err(|e| ClientError::new(
                        0,
                        format!("Failed to read tar entry path: {}", e),
                    ))?
                    .into_owned();

                // Zip-Slip and path traversal protection
                let path_str = path_buf.to_string_lossy();
                if path_str.contains("..") || path_str.starts_with('/') || path_str.starts_with('\\') {
                    continue;
                }

                if is_file {
                    if let Some(ext) = path_buf.extension() {
                        if ext == "json" {
                            let item: EnrichmentResponse = serde_json::from_reader(&mut entry).map_err(|e| ClientError::new(
                                0,
                                format!("Failed to parse JSON from {}: {}", sanitize_entry_name(&path_buf.display().to_string()), e),
                            ))?;
                            results.push(item);
                        }
                    }
                }
            }

            Ok(results)
        })
        .await
        .map_err(|join_err| ClientError::new(
            0,
            format!("Decompression task failed: {}", join_err),
        ))??;

        Ok(results)
    }
}

// ── Error mapping ─────────────────────────────────────────────────────────────

fn map_error<T: std::fmt::Debug>(err: xyo_openapi_client::apis::Error<T>) -> ClientError {
    match err {
        xyo_openapi_client::apis::Error::ResponseError(rc) => {
            let code = rc.status.as_u16();
            let rate_limit = extract_rate_limit_headers(&rc.headers)
                .or_else(|| if code == 429 { Some(RateLimitError::default()) } else { None });
            ClientError {
                code,
                message: rc.content,
                rate_limit,
            }
        }
        xyo_openapi_client::apis::Error::Reqwest(e) => ClientError::new(
            e.status().map(|s| s.as_u16()).unwrap_or(0),
            e.to_string(),
        ),
        xyo_openapi_client::apis::Error::Serde(e) => ClientError::new(0, e.to_string()),
        xyo_openapi_client::apis::Error::Io(e) => ClientError::new(0, e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xyo_openapi_client::apis::ResponseContent;

    #[test]
    fn test_client_new_default_base_url() {
        let client = Client::new("my-token", None).expect("Client::new should succeed");
        assert_eq!(client.configuration.base_path, "https://api.xyo.financial");
        assert_eq!(
            client.configuration.bearer_access_token,
            Some("my-token".to_string())
        );
    }

    #[test]
    fn test_client_new_custom_base_url() {
        let client = Client::new("my-token", Some("https://sandbox.api.xyo.financial".to_string()))
            .expect("Client::new with custom URL should succeed");
        assert_eq!(
            client.configuration.base_path,
            "https://sandbox.api.xyo.financial"
        );
        assert_eq!(
            client.configuration.bearer_access_token,
            Some("my-token".to_string())
        );
    }

    #[test]
    fn test_client_new_with_string_and_str() {
        let token_str = "token-1";
        let token_string = "token-2".to_string();

        let client1 = Client::new(token_str, None).expect("client1 should succeed");
        let client2 = Client::new(token_string, None).expect("client2 should succeed");

        assert_eq!(
            client1.configuration.bearer_access_token,
            Some("token-1".to_string())
        );
        assert_eq!(
            client2.configuration.bearer_access_token,
            Some("token-2".to_string())
        );
    }

    #[test]
    fn test_client_builder_customization() {
        let client = Client::builder()
            .token("custom-builder-token")
            .base_url("https://custom.api.xyo.financial")
            .user_agent("custom-app/1.0.0")
            .timeout(Duration::from_secs(45))
            .connect_timeout(Duration::from_secs(15))
            .allow_download_host("custom-cdn.internal")
            .build()
            .expect("builder should succeed");

        assert_eq!(client.configuration.base_path, "https://custom.api.xyo.financial");
        assert_eq!(client.configuration.bearer_access_token, Some("custom-builder-token".to_string()));
        assert_eq!(client.configuration.user_agent, Some("custom-app/1.0.0".to_string()));
        assert!(client.download_policy.is_allowed("custom-cdn.internal", "custom.api.xyo.financial"));
    }

    #[test]
    fn test_client_debug_token_redaction() {
        let client = Client::new("super-secret-key-123", None).expect("Client::new should succeed");
        let debug_str = format!("{:?}", client);
        assert!(!debug_str.contains("super-secret-key-123"));
        assert!(debug_str.contains("[REDACTED]"));
    }

    #[test]
    fn test_enrichment_response_serde_with_nulls() {
        let json_str = r#"{
            "merchant": "Uber",
            "description": "Ridesharing service",
            "categories": ["Transportation", "Taxi"],
            "logo": null,
            "location": null,
            "address": null
        }"#;

        let parsed: EnrichmentResponse = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed.merchant, "Uber");
        assert_eq!(parsed.description, "Ridesharing service");
        assert_eq!(parsed.categories, vec!["Transportation", "Taxi"]);
        assert_eq!(parsed.logo, "");
        assert_eq!(parsed.location, "");
        assert_eq!(parsed.address, "");
    }

    #[test]
    fn test_enrich_transaction_collection_response_serde() {
        let json_str = r#"{
            "id": "work-item-12345",
            "link": "https://download.xyo.financial/file.tar.gz"
        }"#;

        let parsed: EnrichTransactionCollectionResponse = serde_json::from_str(json_str).unwrap();
        assert_eq!(parsed.id, "work-item-12345");
        assert_eq!(parsed.link, "https://download.xyo.financial/file.tar.gz");

        let serialized = serde_json::to_string(&parsed).unwrap();
        assert!(serialized.contains("work-item-12345"));
    }

    #[test]
    fn test_enrichment_status_serde_and_variants() {
        let ready = EnrichmentStatus::Ready;
        let pending = EnrichmentStatus::Pending;
        let failed = EnrichmentStatus::Failed;

        let json_ready = serde_json::to_string(&ready).unwrap();
        let json_pending = serde_json::to_string(&pending).unwrap();
        let json_failed = serde_json::to_string(&failed).unwrap();

        assert_eq!(
            serde_json::from_str::<EnrichmentStatus>(&json_ready).unwrap(),
            EnrichmentStatus::Ready
        );
        assert_eq!(
            serde_json::from_str::<EnrichmentStatus>(&json_pending).unwrap(),
            EnrichmentStatus::Pending
        );
        assert_eq!(
            serde_json::from_str::<EnrichmentStatus>(&json_failed).unwrap(),
            EnrichmentStatus::Failed
        );
    }

    #[test]
    fn test_enrichment_request_serde() {
        let req = EnrichmentRequest {
            content: "COSTA COFFEE".to_string(),
            country_code: "GB".to_string(),
        };

        let json_str = serde_json::to_string(&req).unwrap();
        let parsed: EnrichmentRequest = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed.content, "COSTA COFFEE");
        assert_eq!(parsed.country_code, "GB");
    }

    #[test]
    fn test_map_error_response_error() {
        let err: xyo_openapi_client::apis::Error<()> =
            xyo_openapi_client::apis::Error::ResponseError(ResponseContent {
                status: reqwest::StatusCode::FORBIDDEN,
                content: "Forbidden action".to_string(),
                entity: None,
                headers: reqwest::header::HeaderMap::new(),
            });

        let client_err = map_error(err);
        assert_eq!(client_err.code, 403);
        assert_eq!(client_err.message, "Forbidden action");
    }

    #[test]
    fn test_map_error_serde() {
        let serde_err: serde_json::Error = serde_json::from_str::<i32>("not an integer").unwrap_err();
        let err: xyo_openapi_client::apis::Error<()> = xyo_openapi_client::apis::Error::Serde(serde_err);

        let client_err = map_error(err);
        assert_eq!(client_err.code, 0);
        assert!(!client_err.message.is_empty());
    }

    #[test]
    fn test_map_error_io() {
        let io_err = std::io::Error::new(std::io::ErrorKind::ConnectionReset, "connection reset");
        let err: xyo_openapi_client::apis::Error<()> = xyo_openapi_client::apis::Error::Io(io_err);

        let client_err = map_error(err);
        assert_eq!(client_err.code, 0);
        assert!(client_err.message.contains("connection reset"));
    }

    #[test]
    fn test_sanitize_entry_name() {
        let malicious = "test\r\nmalicious\x00entry\x1b[31m.json";
        let sanitized = sanitize_entry_name(malicious);
        assert_eq!(sanitized, "test__malicious_entry_[31m.json");
    }

    #[test]
    fn test_client_builder_custom_base_url() {
        let client = Client::builder()
            .token("test-token")
            .base_url("https://env.api.xyo.financial")
            .build()
            .expect("builder with custom base_url should succeed");
        assert_eq!(client.configuration.base_path, "https://env.api.xyo.financial");
    }

    #[test]
    fn test_enrichment_request_validate() {
        let valid_req = EnrichmentRequest {
            content: "COSTA COFFEE".to_string(),
            country_code: "GB".to_string(),
        };
        assert!(valid_req.validate().is_ok());

        let empty_content = EnrichmentRequest {
            content: "".to_string(),
            country_code: "GB".to_string(),
        };
        assert_eq!(
            empty_content.validate().unwrap_err().message,
            "request content must not be empty"
        );

        let long_content = EnrichmentRequest {
            content: "A".repeat(129),
            country_code: "GB".to_string(),
        };
        assert_eq!(
            long_content.validate().unwrap_err().message,
            "request content exceeds maximum length of 128 characters"
        );

        let empty_country = EnrichmentRequest {
            content: "Valid".to_string(),
            country_code: "".to_string(),
        };
        assert_eq!(
            empty_country.validate().unwrap_err().message,
            "request country_code must not be empty"
        );

        let invalid_country = EnrichmentRequest {
            content: "Valid".to_string(),
            country_code: "USA".to_string(),
        };
        assert_eq!(
            invalid_country.validate().unwrap_err().message,
            "request country_code must be a 2-letter ISO 3166-1 alpha-2 code"
        );
    }

    #[test]
    fn test_validate_api_user_crlf_rejection() {
        assert!(validate_api_user(Some("valid-user-123")).is_ok());
        assert!(validate_api_user(None).is_ok());

        let crlf1 = validate_api_user(Some("user\r\ninjected-header: val"));
        assert!(crlf1.is_err());
        assert!(crlf1.unwrap_err().message.contains("CRLF"));

        let crlf2 = validate_api_user(Some("user\ninjected-header: val"));
        assert!(crlf2.is_err());
    }

    #[tokio::test]
    async fn test_enrich_transaction_rejects_api_user() {
        let client = Client::new("test-token", Some("https://api.xyo.financial".to_string())).unwrap();
        let opts = RequestOptions::new().api_user("user-123");
        let err = client
            .enrich_transaction_with_options("COSTA", "GB", Some(&opts))
            .await
            .expect_err("api_user should be rejected for single transaction");
        assert_eq!(err.message, "`api_user` is only applicable to bulk operations");
    }

    #[test]
    fn test_client_with_token_supplier() {
        let key_holder = std::sync::Arc::new(std::sync::Mutex::new("key-1".to_string()));
        let key_clone = key_holder.clone();

        let client = Client::with_token_supplier(
            move || key_clone.lock().unwrap().clone(),
            Some("https://api.xyo.financial".to_string()),
        )
        .expect("Client::with_token_supplier should succeed");

        let cfg1 = client.get_effective_config();
        assert_eq!(cfg1.bearer_access_token, Some("key-1".to_string()));

        *key_holder.lock().unwrap() = "rotated-key-2".to_string();
        let cfg2 = client.get_effective_config();
        assert_eq!(cfg2.bearer_access_token, Some("rotated-key-2".to_string()));
    }

    #[test]
    fn test_validate_header_value_crlf_rejection() {
        assert!(validate_header_value(Some("valid-header-val")).is_ok());
        assert!(validate_header_value(None).is_ok());

        let crlf1 = validate_header_value(Some("val\r\ninjected-header: bad"));
        assert!(crlf1.is_err());
        assert_eq!(
            crlf1.unwrap_err().message,
            "header value contains invalid CRLF characters"
        );

        let crlf2 = validate_header_value(Some("val\ninjected-header: bad"));
        assert!(crlf2.is_err());
    }

    #[tokio::test]
    async fn test_enrich_transactions_lazy_iterator_limit() {
        let client = Client::new("test-token", Some("https://api.xyo.financial".to_string())).unwrap();

        let infinite_requests = std::iter::repeat_with(|| EnrichmentRequest {
            content: "COSTA COFFEE".to_string(),
            country_code: "GB".to_string(),
        });

        let err = client
            .enrich_transactions(infinite_requests, None)
            .await
            .expect_err("infinite requests iterator should terminate early with error");

        assert!(err.message.contains("requests batch size exceeds maximum allowed limit"));
    }
}
