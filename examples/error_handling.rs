use xyo_sdk::client::Client;

#[tokio::main]
async fn main() {
    // Example using an invalid token to demonstrate structured error handling
    let client = Client::new("invalid-token", None).expect("failed to construct client");

    println!("Attempting API call with invalid authentication...");

    match client.enrich_transaction("SPOTIFY PREMIUM", "SE").await {
        Ok(resp) => {
            println!("Enrichment succeeded: {}", resp.merchant);
        }
        Err(err) => {
            println!("Encountered ClientError:");
            println!("  HTTP Status Code: {}", err.code);
            println!("  Error Message:    {}", err.message);
            if let Some(rl) = &err.rate_limit {
                println!("  RateLimit Info:   Retry-After={:?}, Limit={:?}, Remaining={:?}, Reset={:?}", rl.retry_after, rl.limit, rl.remaining, rl.reset);
            }

            match err.code {
                401 => eprintln!("  Resolution: Verify your API key at https://xyo.financial/dashboard"),
                400 | 422 => eprintln!("  Resolution: Check transaction content and ISO country code format"),
                404 => eprintln!("  Resolution: Merchant or resource not found"),
                500..=599 => eprintln!("  Resolution: XYO API server error - retry with exponential backoff"),
                0 => eprintln!("  Resolution: Network/transport error - verify internet connection and DNS"),
                _ => eprintln!("  Resolution: Unexpected error code"),
            }
        }
    }
}
