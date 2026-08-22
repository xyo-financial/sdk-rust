use wiremock::matchers::{bearer_token, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};
use xyo_sdk::client::{Client, DownloadSecurityPolicy, EnrichmentRequest, EnrichmentStatus, RequestOptions};

#[tokio::test]
async fn test_client_new_configuration() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token-123", Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .and(bearer_token("test-token-123"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "merchant": "Test Merchant",
            "description": "Test Description",
            "categories": ["Retail"],
            "logo": "logo-data",
            "location": "London, UK",
            "address": "123 High St"
        })))
        .mount(&mock_server)
        .await;

    let result = client.enrich_transaction("TEST PURCHASE", "GB").await;
    assert!(result.is_ok());
    let response = result.unwrap();
    assert_eq!(response.merchant, "Test Merchant");
    assert_eq!(response.description, "Test Description");
    assert_eq!(response.categories, vec!["Retail".to_string()]);
    assert_eq!(response.logo, "logo-data");
    assert_eq!(response.location, "London, UK");
    assert_eq!(response.address, "123 High St");
}

#[tokio::test]
async fn test_enrich_transaction_success() {
    let mock_server = MockServer::start().await;
    let token = "xyo-secret-bearer-token";
    let client = Client::new(token, Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .and(bearer_token(token))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "merchant": "Costa Coffee",
            "description": "British coffeehouse chain",
            "categories": ["Food & Beverage", "Coffee"],
            "logo": "data:image/png;base64,iVBORw0KGgoAAAANS",
            "location": "London, United Kingdom",
            "address": "Unit 4, Station Rd"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let resp = client
        .enrich_transaction("COSTA PICKUP", "GB")
        .await
        .expect("enrich_transaction should succeed");

    assert_eq!(resp.merchant, "Costa Coffee");
    assert_eq!(resp.description, "British coffeehouse chain");
    assert_eq!(resp.categories, vec!["Food & Beverage", "Coffee"]);
    assert_eq!(resp.logo, "data:image/png;base64,iVBORw0KGgoAAAANS");
    assert_eq!(resp.location, "London, United Kingdom");
    assert_eq!(resp.address, "Unit 4, Station Rd");
}

#[tokio::test]
async fn test_enrich_transaction_empty_optional_fields() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "merchant": "Online Store",
            "description": "Digital goods vendor",
            "categories": ["E-Commerce"],
            "logo": "data:image/png;base64,abc",
            "location": "",
            "address": ""
        })))
        .mount(&mock_server)
        .await;

    let resp = client
        .enrich_transaction("DIGITAL GOODS", "US")
        .await
        .expect("enrich_transaction should handle empty optional fields");

    assert_eq!(resp.merchant, "Online Store");
    assert_eq!(resp.location, "");
    assert_eq!(resp.address, "");
}

#[tokio::test]
async fn test_enrich_transaction_400_bad_request() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    let error_body = serde_json::json!({
        "errors": [{
            "type": "https://xyo.financial/errors/invalid-country",
            "title": "Invalid country code",
            "status": 400,
            "detail": "Country code 'XYZ' is not a valid ISO 3166-1 alpha-2 code",
            "instance": "/v1/ai/finance/enrichment/transaction"
        }]
    });

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_json(&error_body)
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let err = client
        .enrich_transaction("TEST CONTENT", "ZZ")
        .await
        .expect_err("should return ClientError for 400");

    assert_eq!(err.code, 400);
    assert!(err.message.contains("Invalid country code"));
}

#[tokio::test]
async fn test_enrich_transaction_401_unauthorized() {
    let mock_server = MockServer::start().await;
    let client = Client::new("invalid-token", Some(mock_server.uri())).unwrap();

    let error_body = serde_json::json!({
        "errors": [{
            "type": "https://xyo.financial/errors/unauthorized",
            "title": "Unauthorized",
            "status": 401,
            "detail": "Missing or invalid bearer authentication token",
            "instance": "/v1/ai/finance/enrichment/transaction"
        }]
    });

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_json(&error_body)
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let err = client
        .enrich_transaction("COSTA", "GB")
        .await
        .expect_err("should return ClientError for 401");

    assert_eq!(err.code, 401);
    assert!(err.message.contains("Unauthorized"));
}

#[tokio::test]
async fn test_enrich_transaction_404_not_found() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Not Found"))
        .mount(&mock_server)
        .await;

    let err = client
        .enrich_transaction("UNKNOWN", "GB")
        .await
        .expect_err("should return ClientError for 404");

    assert_eq!(err.code, 404);
    assert_eq!(err.message, "Not Found");
}

#[tokio::test]
async fn test_enrich_transaction_422_unprocessable_entity() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .respond_with(
            ResponseTemplate::new(422)
                .set_body_string("{\"error\":\"Unprocessable Entity\"}")
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let err = client
        .enrich_transaction("UNPROCESSABLE TRANSACTION", "GB")
        .await
        .expect_err("should return ClientError for 422");

    assert_eq!(err.code, 422);
    assert!(err.message.contains("Unprocessable Entity"));
}

#[tokio::test]
async fn test_enrich_transaction_500_internal_server_error() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let err = client
        .enrich_transaction("SOME TX", "GB")
        .await
        .expect_err("should return ClientError for 500");

    assert_eq!(err.code, 500);
    assert_eq!(err.message, "Internal Server Error");
}

#[tokio::test]
async fn test_enrich_transactions_bulk_with_api_user() {
    let mock_server = MockServer::start().await;
    let token = "test-token";
    let client = Client::new(token, Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transactions"))
        .and(bearer_token(token))
        .and(header("x-api-user", "tenant-user-42"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "job-bulk-999",
            "link": "https://api.xyo.financial/downloads/job-bulk-999.tar.gz"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let requests = vec![
        EnrichmentRequest {
            content: "UBER TRIP".to_string(),
            country_code: "GB".to_string(),
        },
        EnrichmentRequest {
            content: "NETFLIX".to_string(),
            country_code: "US".to_string(),
        },
    ];

    let resp = client
        .enrich_transactions(requests, Some("tenant-user-42"))
        .await
        .expect("enrich_transactions with api_user should succeed");

    assert_eq!(resp.id, "job-bulk-999");
    assert_eq!(
        resp.link,
        "https://api.xyo.financial/downloads/job-bulk-999.tar.gz"
    );
}

#[tokio::test]
async fn test_enrich_transactions_bulk_without_api_user() {
    let mock_server = MockServer::start().await;
    let token = "test-token";
    let client = Client::new(token, Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transactions"))
        .and(bearer_token(token))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "job-no-user-123",
            "link": "https://api.xyo.financial/downloads/job-no-user-123.tar.gz"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let requests = vec![EnrichmentRequest {
        content: "STARBUCKS".to_string(),
        country_code: "US".to_string(),
    }];

    let resp = client
        .enrich_transactions(requests, None)
        .await
        .expect("enrich_transactions without api_user should succeed");

    assert_eq!(resp.id, "job-no-user-123");
    assert_eq!(
        resp.link,
        "https://api.xyo.financial/downloads/job-no-user-123.tar.gz"
    );
}

#[tokio::test]
async fn test_enrich_transactions_empty_list() {
    let client = Client::new("test-token", Some("https://api.xyo.financial".to_string())).unwrap();

    let empty_requests: Vec<EnrichmentRequest> = vec![];
    let err = client
        .enrich_transactions(empty_requests, None)
        .await
        .expect_err("empty requests list should return error");

    assert_eq!(err.message, "requests batch cannot be empty");
}

#[tokio::test]
async fn test_enrich_transactions_400_error() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transactions"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string("{\"error\":\"Invalid batch payload\"}")
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let requests = vec![EnrichmentRequest {
        content: "BAD DATA".to_string(),
        country_code: "XX".to_string(),
    }];

    let err = client
        .enrich_transactions(requests, None)
        .await
        .expect_err("should return ClientError for 400");

    assert_eq!(err.code, 400);
    assert!(err.message.contains("Invalid batch payload"));
}

#[tokio::test]
async fn test_enrich_transactions_500_error() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transactions"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let requests = vec![EnrichmentRequest {
        content: "TX".to_string(),
        country_code: "GB".to_string(),
    }];

    let err = client
        .enrich_transactions(requests, None)
        .await
        .expect_err("should return ClientError for 500");

    assert_eq!(err.code, 500);
    assert_eq!(err.message, "Internal Server Error");
}

#[tokio::test]
async fn test_get_enrichment_status_ready() {
    let mock_server = MockServer::start().await;
    let token = "test-token";
    let client = Client::new(token, Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/v1/ai/finance/enrichment/status/job-ready-123"))
        .and(bearer_token(token))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "READY"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let status = client
        .get_enrichment_status("job-ready-123", None)
        .await
        .expect("get_enrichment_status READY should succeed");

    assert_eq!(status, EnrichmentStatus::Ready);
}

#[tokio::test]
async fn test_get_enrichment_status_pending() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/v1/ai/finance/enrichment/status/job-pending-456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "PENDING"
        })))
        .mount(&mock_server)
        .await;

    let status = client
        .get_enrichment_status("job-pending-456", None)
        .await
        .expect("get_enrichment_status PENDING should succeed");

    assert_eq!(status, EnrichmentStatus::Pending);
}

#[tokio::test]
async fn test_get_enrichment_status_failed() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/v1/ai/finance/enrichment/status/job-failed-789"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "FAILED"
        })))
        .mount(&mock_server)
        .await;

    let status = client
        .get_enrichment_status("job-failed-789", None)
        .await
        .expect("get_enrichment_status FAILED should succeed");

    assert_eq!(status, EnrichmentStatus::Failed);
}

#[tokio::test]
async fn test_get_enrichment_status_with_api_user() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/v1/ai/finance/enrichment/status/job-user-111"))
        .and(header("x-api-user", "custom-user-99"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "READY"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let status = client
        .get_enrichment_status("job-user-111", Some("custom-user-99"))
        .await
        .expect("get_enrichment_status with api_user should succeed");

    assert_eq!(status, EnrichmentStatus::Ready);
}

#[tokio::test]
async fn test_get_enrichment_status_url_encoded_id() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/v1/ai/finance/enrichment/status/job%2Fspecial%3Aid"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "READY"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let status = client
        .get_enrichment_status("job/special:id", None)
        .await
        .expect("get_enrichment_status with special chars in id should succeed");

    assert_eq!(status, EnrichmentStatus::Ready);
}

#[tokio::test]
async fn test_get_enrichment_status_404_not_found() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/v1/ai/finance/enrichment/status/nonexistent-job"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_string("Job not found")
                .insert_header("content-type", "text/plain"),
        )
        .mount(&mock_server)
        .await;

    let err = client
        .get_enrichment_status("nonexistent-job", None)
        .await
        .expect_err("should return ClientError for 404");

    assert_eq!(err.code, 404);
    assert_eq!(err.message, "Job not found");
}

#[tokio::test]
async fn test_enrich_transaction_payload_verification() {
    let mock_server = MockServer::start().await;
    let token = "verified-token";
    let client = Client::new(token, Some(mock_server.uri())).unwrap();

    let expected_body = serde_json::json!({
        "content": "SPOTIFY PREMIUM",
        "countryCode": "SE"
    });

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .and(bearer_token(token))
        .and(wiremock::matchers::body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "merchant": "Spotify",
            "description": "Audio streaming service",
            "categories": ["Entertainment", "Music"],
            "logo": "spotify-logo-base64",
            "location": "Stockholm, Sweden",
            "address": "Regeringsgatan 19"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let resp = client
        .enrich_transaction("SPOTIFY PREMIUM", "SE")
        .await
        .expect("enrich_transaction with verified body should succeed");

    assert_eq!(resp.merchant, "Spotify");
    assert_eq!(resp.description, "Audio streaming service");
    assert_eq!(resp.categories, vec!["Entertainment", "Music"]);
}

#[tokio::test]
async fn test_enrich_transaction_empty_categories() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "merchant": "Unknown Shop",
            "description": "N/A",
            "categories": [],
            "logo": "",
            "location": "",
            "address": ""
        })))
        .mount(&mock_server)
        .await;

    let resp = client
        .enrich_transaction("UNKNOWN SHOP", "US")
        .await
        .expect("enrich_transaction with empty categories should succeed");

    assert_eq!(resp.merchant, "Unknown Shop");
    assert!(resp.categories.is_empty());
}

#[tokio::test]
async fn test_enrich_transactions_payload_verification() {
    let mock_server = MockServer::start().await;
    let token = "bulk-token";
    let client = Client::new(token, Some(mock_server.uri())).unwrap();

    let expected_body = serde_json::json!([
        {
            "content": "AMAZON UK",
            "countryCode": "GB"
        },
        {
            "content": "APPLE STORE",
            "countryCode": "US"
        }
    ]);


    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transactions"))
        .and(bearer_token(token))
        .and(wiremock::matchers::body_json(&expected_body))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "job-payload-verified-123",
            "link": "https://api.xyo.financial/downloads/job-payload-verified-123.tar.gz"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let items = vec![
        EnrichmentRequest {
            content: "AMAZON UK".to_string(),
            country_code: "GB".to_string(),
        },
        EnrichmentRequest {
            content: "APPLE STORE".to_string(),
            country_code: "US".to_string(),
        },
    ];

    let resp = client
        .enrich_transactions(items, None)
        .await
        .expect("enrich_transactions with verified payload should succeed");

    assert_eq!(resp.id, "job-payload-verified-123");
}

#[tokio::test]
async fn test_enrich_transactions_401_unauthorized() {
    let mock_server = MockServer::start().await;
    let client = Client::new("invalid-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transactions"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string("{\"error\":\"Unauthorized\"}")
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let items = vec![EnrichmentRequest {
        content: "TX".to_string(),
        country_code: "GB".to_string(),
    }];

    let err = client
        .enrich_transactions(items, None)
        .await
        .expect_err("should return ClientError 401");

    assert_eq!(err.code, 401);
    assert!(err.message.contains("Unauthorized"));
}

#[tokio::test]
async fn test_get_enrichment_status_401_unauthorized() {
    let mock_server = MockServer::start().await;
    let client = Client::new("invalid-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/v1/ai/finance/enrichment/status/job-123"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string("{\"error\":\"Unauthorized\"}")
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let err = client
        .get_enrichment_status("job-123", None)
        .await
        .expect_err("should return ClientError 401");

    assert_eq!(err.code, 401);
    assert!(err.message.contains("Unauthorized"));
}

#[tokio::test]
async fn test_get_enrichment_status_500_internal_server_error() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/v1/ai/finance/enrichment/status/job-err"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let err = client
        .get_enrichment_status("job-err", None)
        .await
        .expect_err("should return ClientError 500");

    assert_eq!(err.code, 500);
    assert_eq!(err.message, "Internal Server Error");
}

#[tokio::test]
async fn test_connection_failure_maps_to_client_error() {
    // Port 1 is reserved and typically nothing is listening
    let client = Client::new("test-token", Some("http://127.0.0.1:1".to_string())).unwrap();

    let err = client
        .enrich_transaction("TX", "GB")
        .await
        .expect_err("connection failure should return ClientError");

    assert_eq!(err.code, 0);
    assert!(!err.message.is_empty());
}

// ── Helper for creating in-memory .tar.gz archives ────────────────────────────

fn create_test_tar_gz(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use tar::Builder;

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    {
        let mut tar_builder = Builder::new(&mut encoder);
        for (name, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_path(name).unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            tar_builder.append(&header, *data).unwrap();
        }
        tar_builder.finish().unwrap();
    }
    encoder.finish().unwrap()
}

// ── download_enrichment_collection tests ──────────────────────────────────────

#[tokio::test]
async fn test_download_enrichment_collection_success() {
    let mock_server = MockServer::start().await;
    let token = "download-secret-token";
    let client = Client::new(token, Some(mock_server.uri())).unwrap();

    let tx0_json = serde_json::to_vec(&serde_json::json!({
        "merchant": "Costa Coffee",
        "description": "British coffeehouse chain",
        "categories": ["Food & Beverage", "Coffee"],
        "logo": "data:image/png;base64,costa_logo",
        "location": "London, UK",
        "address": "123 High St"
    }))
    .unwrap();

    let tx1_json = serde_json::to_vec(&serde_json::json!({
        "merchant": "Uber",
        "description": "Ridesharing app",
        "categories": ["Transportation"],
        "logo": "data:image/png;base64,uber_logo",
        "location": "San Francisco, CA",
        "address": "1455 Market St"
    }))
    .unwrap();

    let archive = create_test_tar_gz(&[
        ("transaction_0.json", &tx0_json),
        ("transaction_1.json", &tx1_json),
    ]);

    Mock::given(method("GET"))
        .and(path("/v1/ai/finance/enrichment/download/batch-999.tar.gz"))
        .and(bearer_token(token))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(archive)
                .insert_header("content-type", "application/gzip"),
        )
        .expect(1)
        .mount(&mock_server)
        .await;

    let download_url = format!("{}/v1/ai/finance/enrichment/download/batch-999.tar.gz", mock_server.uri());
    let results = client
        .download_enrichment_collection(&download_url)
        .await
        .expect("download_enrichment_collection should succeed");

    assert_eq!(results.len(), 2);
    assert_eq!(results[0].merchant, "Costa Coffee");
    assert_eq!(results[0].description, "British coffeehouse chain");
    assert_eq!(results[0].categories, vec!["Food & Beverage", "Coffee"]);
    assert_eq!(results[0].logo, "data:image/png;base64,costa_logo");
    assert_eq!(results[0].location, "London, UK");
    assert_eq!(results[0].address, "123 High St");

    assert_eq!(results[1].merchant, "Uber");
    assert_eq!(results[1].description, "Ridesharing app");
    assert_eq!(results[1].categories, vec!["Transportation"]);
    assert_eq!(results[1].logo, "data:image/png;base64,uber_logo");
    assert_eq!(results[1].location, "San Francisco, CA");
    assert_eq!(results[1].address, "1455 Market St");
}

#[tokio::test]
async fn test_download_enrichment_collection_relative_url() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    let tx_json = serde_json::to_vec(&serde_json::json!({
        "merchant": "Syniol Limited",
        "description": "AI Financial Software",
        "categories": ["Technology", "Fintech"],
        "logo": "syniol_logo",
        "location": "London, UK",
        "address": "1 Finsbury Square"
    }))
    .unwrap();

    let archive = create_test_tar_gz(&[("result.json", &tx_json)]);

    Mock::given(method("GET"))
        .and(path("/downloads/batch-rel.tar.gz"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(archive)
                .insert_header("content-type", "application/gzip"),
        )
        .mount(&mock_server)
        .await;

    let results = client
        .download_enrichment_collection("/downloads/batch-rel.tar.gz")
        .await
        .expect("relative download URL should succeed");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].merchant, "Syniol Limited");
}

#[tokio::test]
async fn test_download_enrichment_collection_filters_non_json_files() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    let tx_json = serde_json::to_vec(&serde_json::json!({
        "merchant": "Starbucks",
        "description": "Coffee",
        "categories": ["Food"],
        "logo": "",
        "location": "",
        "address": ""
    }))
    .unwrap();

    let text_file = b"This is a manifest file, not JSON";
    let subfolder_json = serde_json::to_vec(&serde_json::json!({
        "merchant": "Netflix",
        "description": "Streaming",
        "categories": ["Entertainment"],
        "logo": "",
        "location": "",
        "address": ""
    }))
    .unwrap();

    let archive = create_test_tar_gz(&[
        ("manifest.txt", text_file),
        ("README.md", b"# Results"),
        ("item_0.json", &tx_json),
        ("nested/item_1.json", &subfolder_json),
    ]);

    Mock::given(method("GET"))
        .and(path("/downloads/filter-test.tar.gz"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(archive)
                .insert_header("content-type", "application/gzip"),
        )
        .mount(&mock_server)
        .await;

    let results = client
        .download_enrichment_collection("/downloads/filter-test.tar.gz")
        .await
        .expect("should succeed and ignore non-json files");

    assert_eq!(results.len(), 2);
    let merchants: Vec<&str> = results.iter().map(|r| r.merchant.as_str()).collect();
    assert!(merchants.contains(&"Starbucks"));
    assert!(merchants.contains(&"Netflix"));
}

#[tokio::test]
async fn test_download_enrichment_collection_401_unauthorized() {
    let mock_server = MockServer::start().await;
    let client = Client::new("invalid-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/downloads/unauthorized.tar.gz"))
        .respond_with(
            ResponseTemplate::new(401)
                .set_body_string("{\"error\":\"Unauthorized\"}")
                .insert_header("content-type", "application/json"),
        )
        .mount(&mock_server)
        .await;

    let err = client
        .download_enrichment_collection("/downloads/unauthorized.tar.gz")
        .await
        .expect_err("should return ClientError 401");

    assert_eq!(err.code, 401);
    assert!(err.message.contains("Unauthorized"));
}

#[tokio::test]
async fn test_download_enrichment_collection_404_not_found() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/downloads/nonexistent.tar.gz"))
        .respond_with(ResponseTemplate::new(404).set_body_string("Archive not found"))
        .mount(&mock_server)
        .await;

    let err = client
        .download_enrichment_collection("/downloads/nonexistent.tar.gz")
        .await
        .expect_err("should return ClientError 404");

    assert_eq!(err.code, 404);
    assert_eq!(err.message, "Archive not found");
}

#[tokio::test]
async fn test_download_enrichment_collection_500_internal_server_error() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/downloads/server-error.tar.gz"))
        .respond_with(ResponseTemplate::new(500).set_body_string("Internal Server Error"))
        .mount(&mock_server)
        .await;

    let err = client
        .download_enrichment_collection("/downloads/server-error.tar.gz")
        .await
        .expect_err("should return ClientError 500");

    assert_eq!(err.code, 500);
    assert_eq!(err.message, "Internal Server Error");
}

#[tokio::test]
async fn test_download_enrichment_collection_corrupt_gzip() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/downloads/corrupt.tar.gz"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(b"not a valid gzip archive content".to_vec())
                .insert_header("content-type", "application/gzip"),
        )
        .mount(&mock_server)
        .await;

    let err = client
        .download_enrichment_collection("/downloads/corrupt.tar.gz")
        .await
        .expect_err("corrupt gzip should return ClientError");

    assert_eq!(err.code, 0);
    assert!(!err.message.is_empty());
}

#[tokio::test]
async fn test_download_enrichment_collection_invalid_json() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    let invalid_json = b"{\"merchant\": \"incomplete...";
    let archive = create_test_tar_gz(&[("bad_data.json", invalid_json)]);

    Mock::given(method("GET"))
        .and(path("/downloads/bad-json.tar.gz"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(archive)
                .insert_header("content-type", "application/gzip"),
        )
        .mount(&mock_server)
        .await;

    let err = client
        .download_enrichment_collection("/downloads/bad-json.tar.gz")
        .await
        .expect_err("invalid json entry should return ClientError");

    assert_eq!(err.code, 0);
    assert!(err.message.contains("Failed to parse JSON"));
}

#[tokio::test]
async fn test_download_enrichment_collection_transport_failure() {
    let client = Client::new("test-token", Some("http://127.0.0.1:1".to_string())).unwrap();

    let err = client
        .download_enrichment_collection("http://127.0.0.1:1/nonexistent.tar.gz")
        .await
        .expect_err("connection refusal should return ClientError");

    assert_eq!(err.code, 0);
    assert!(!err.message.is_empty());
}

#[tokio::test]
async fn test_download_enrichment_collection_ssrf_protection() {
    let client = Client::new("test-token", None).unwrap();

    let err1 = client
        .download_enrichment_collection("file:///etc/passwd")
        .await
        .expect_err("file scheme should be rejected");
    assert!(err1.message.contains("Unsupported URL scheme"));

    let err2 = client
        .download_enrichment_collection("ftp://example.com/archive.tar.gz")
        .await
        .expect_err("ftp scheme should be rejected");
    assert!(err2.message.contains("Unsupported URL scheme"));
}

#[tokio::test]
async fn test_download_enrichment_collection_waf_challenge() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("GET"))
        .and(path("/downloads/job.tar.gz"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(b"<html><body><h1>Cloudflare / WAF Challenge</h1></body></html>".as_slice())
                .insert_header("content-type", "text/html; charset=UTF-8"),
        )
        .mount(&mock_server)
        .await;

    let err = client
        .download_enrichment_collection(&format!("{}/downloads/job.tar.gz", mock_server.uri()))
        .await
        .expect_err("WAF html response should fail with descriptive error");

    assert!(err.message.contains("Unexpected Content-Type"));
    assert!(err.message.contains("text/html"));
}

struct HeaderMissingMatcher(&'static str);
impl wiremock::Match for HeaderMissingMatcher {
    fn matches(&self, request: &wiremock::Request) -> bool {
        !request.headers.contains_key(&wiremock::http::HeaderName::from_static(self.0))
    }
}

#[tokio::test]
async fn test_download_enrichment_collection_domain_validation_and_auth() {
    let api_server = MockServer::start().await;
    let client = Client::new("secret-token-123", Some(api_server.uri())).unwrap();

    let json_bytes = br#"{"merchant":"Starbucks","description":"Coffee","categories":["Food"],"logo":"url"}"#;
    let archive = create_test_tar_gz(&[("result.json", json_bytes)]);

    // 1. Download from same API server host succeeds
    Mock::given(method("GET"))
        .and(path("/downloads/results.tar.gz"))
        .and(bearer_token("secret-token-123"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_bytes(archive)
                .insert_header("content-type", "application/gzip"),
        )
        .expect(1)
        .mount(&api_server)
        .await;

    let results = client
        .download_enrichment_collection(&format!("{}/downloads/results.tar.gz", api_server.uri()))
        .await
        .expect("download from api host should succeed");

    assert_eq!(results.len(), 1);
    assert_eq!(results[0].merchant, "Starbucks");

    // 2. Download from untrusted rogue domain is rejected
    let err = client
        .download_enrichment_collection("https://evil-untrusted-domain.com/data.tar.gz")
        .await
        .expect_err("untrusted domain should be rejected");

    assert!(err.message.contains("not permitted for secure archive downloads"));
}

#[tokio::test]
async fn test_client_builder_integration() {
    let mock_server = MockServer::start().await;
    let client = Client::builder()
        .token("builder-token-xyz")
        .base_url(mock_server.uri())
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .expect("builder should construct client");

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .and(bearer_token("builder-token-xyz"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "merchant": "Builder Corp",
            "description": "Integration test",
            "categories": ["Tech"],
            "logo": "",
            "location": "",
            "address": ""
        })))
        .mount(&mock_server)
        .await;

    let resp = client
        .enrich_transaction("BUILDER CORP", "US")
        .await
        .expect("enrich_transaction with builder client should succeed");

    assert_eq!(resp.merchant, "Builder Corp");
    assert_eq!(resp.logo, "");
    assert_eq!(resp.location, "");
    assert_eq!(resp.address, "");
}

#[tokio::test]
async fn test_download_security_policy_custom_allowed_host() {
    let policy = DownloadSecurityPolicy {
        allowed_hosts: vec!["custom.storage.enterprise.io".to_string()],
        allow_same_origin: true,
    };

    assert!(policy.is_allowed("custom.storage.enterprise.io", "api.xyo.financial"));
    assert!(policy.is_allowed("subdomain.custom.storage.enterprise.io", "api.xyo.financial"));
    assert!(policy.is_allowed("api.xyo.financial", "api.xyo.financial"));
    assert!(!policy.is_allowed("rogue-server.io", "api.xyo.financial"));
}

#[tokio::test]
async fn test_enrich_transaction_client_side_validation() {
    let client = Client::new("test-token", Some("https://api.xyo.financial".to_string())).unwrap();

    let err_empty = client.enrich_transaction("", "GB").await.unwrap_err();
    assert_eq!(err_empty.message, "request content must not be empty");

    let err_country = client.enrich_transaction("COSTA", "USA").await.unwrap_err();
    assert_eq!(err_country.message, "request country_code must be a 2-letter ISO 3166-1 alpha-2 code");
}

#[tokio::test]
async fn test_enrich_transactions_client_side_batch_item_validation() {
    let client = Client::new("test-token", Some("https://api.xyo.financial".to_string())).unwrap();

    let requests = vec![
        EnrichmentRequest { content: "VALID".to_string(), country_code: "GB".to_string() },
        EnrichmentRequest { content: "".to_string(), country_code: "US".to_string() },
    ];
    let err = client.enrich_transactions(requests, None).await.unwrap_err();
    assert!(err.message.contains("request at index 1 is invalid"));
}

#[tokio::test]
async fn test_tracing_headers_enrich_transaction() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    let cid = "123e4567-e89b-12d3-a456-426614174000";
    let tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .and(header("X-Correlation-ID", cid))
        .and(header("traceparent", tp))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "merchant": "Costa Coffee",
            "description": "British coffeehouse chain",
            "categories": ["Food & Beverage"],
            "logo": "",
            "location": "London",
            "address": "High St"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let opts = RequestOptions::new()
        .correlation_id(cid)
        .traceparent(tp);

    let resp = client
        .enrich_transaction_with_options("COSTA", "GB", Some(&opts))
        .await
        .expect("enrich_transaction_with_options should succeed with tracing headers");

    assert_eq!(resp.merchant, "Costa Coffee");
}

#[tokio::test]
async fn test_tracing_headers_enrich_transactions() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    let cid = "corr-bulk-999";
    let tp = "00-traceparent-bulk-01";
    let user = "tenant-user-77";

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transactions"))
        .and(header("X-Correlation-ID", cid))
        .and(header("traceparent", tp))
        .and(header("x-api-user", user))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "job-bulk-tracing",
            "link": "https://api.xyo.financial/download.tar.gz"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let opts = RequestOptions::new()
        .correlation_id(cid)
        .traceparent(tp)
        .api_user(user);

    let reqs = vec![EnrichmentRequest::new("UBER TRIP", "GB")];

    let resp = client
        .enrich_transactions_with_options(reqs, Some(&opts))
        .await
        .expect("enrich_transactions_with_options should succeed with tracing headers");

    assert_eq!(resp.id, "job-bulk-tracing");
}

#[tokio::test]
async fn test_tracing_headers_get_enrichment_status() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    let cid = "corr-status-111";
    let tp = "00-traceparent-status-01";

    Mock::given(method("GET"))
        .and(path("/v1/ai/finance/enrichment/status/job-status-trace"))
        .and(header("X-Correlation-ID", cid))
        .and(header("traceparent", tp))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "status": "READY"
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let opts = RequestOptions::new()
        .correlation_id(cid)
        .traceparent(tp);

    let status = client
        .get_enrichment_status_with_options("job-status-trace", Some(&opts))
        .await
        .expect("get_enrichment_status_with_options should succeed with tracing headers");

    assert_eq!(status, EnrichmentStatus::Ready);
}

#[tokio::test]
async fn test_client_builder_default_tracing_headers() {
    let mock_server = MockServer::start().await;
    let client = Client::builder()
        .token("test-token")
        .base_url(mock_server.uri())
        .correlation_id("builder-cid-123")
        .traceparent("builder-tp-456")
        .build()
        .unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .and(header("X-Correlation-ID", "builder-cid-123"))
        .and(header("traceparent", "builder-tp-456"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "merchant": "Default Tracing Store",
            "description": "Desc",
            "categories": [],
            "logo": "",
            "location": "",
            "address": ""
        })))
        .expect(1)
        .mount(&mock_server)
        .await;

    let resp = client
        .enrich_transaction("COSTA", "GB")
        .await
        .expect("should automatically attach default builder tracing headers");

    assert_eq!(resp.merchant, "Default Tracing Store");
}

#[tokio::test]
async fn test_rate_limit_429_header_parsing() {
    let mock_server = MockServer::start().await;
    let client = Client::new("test-token", Some(mock_server.uri())).unwrap();

    Mock::given(method("POST"))
        .and(path("/v1/ai/finance/enrichment/transaction"))
        .respond_with(
            ResponseTemplate::new(429)
                .set_body_string("{\"error\":\"Rate limit exceeded\"}")
                .insert_header("content-type", "application/json")
                .insert_header("Retry-After", "120")
                .insert_header("RateLimit-Limit", "5000")
                .insert_header("RateLimit-Remaining", "0")
                .insert_header("RateLimit-Reset", "1700001000"),
        )
        .mount(&mock_server)
        .await;

    let err = client
        .enrich_transaction("COSTA", "GB")
        .await
        .expect_err("should return ClientError for 429");

    assert_eq!(err.code, 429);
    assert!(err.is_rate_limited());
    assert!(err.is_retryable());

    let rl = err.rate_limit.expect("rate_limit info should be extracted");
    assert_eq!(rl.retry_after, Some(120));
    assert_eq!(rl.limit, Some(5000));
    assert_eq!(rl.remaining, Some(0));
    assert_eq!(rl.reset, Some(1700001000));
}

#[tokio::test]
async fn test_batch_size_upper_bounds_validation() {
    let client = Client::new("test-token", Some("https://api.xyo.financial".to_string())).unwrap();

    let oversized_requests: Vec<EnrichmentRequest> = (0..50_001)
        .map(|i| EnrichmentRequest {
            content: format!("TX {}", i),
            country_code: "GB".to_string(),
        })
        .collect();

    let err = client
        .enrich_transactions(oversized_requests, None)
        .await
        .expect_err("oversized batch (> 50,000 items) should fail validation");

    assert_eq!(err.code, 0);
    assert!(err.message.contains("exceeds maximum allowed limit of 50000 items"));
}
