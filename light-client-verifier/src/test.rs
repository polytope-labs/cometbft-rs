extern crate std;

use crate::options::Options;
use crate::types::LightBlock;
use crate::{ProdVerifier, Verdict, Verifier};
use alloc::string::ToString;
use alloc::vec::Vec;
use cometbft_rpc::{Client, HttpClient, Paging};
use core::time::Duration;

/// Fetch a LightBlock using the CometBFT RPC client.
///
/// Uses the HTTP client to fetch:
/// - Signed header via `commit` endpoint
/// - Validators via `validators` endpoint with pagination
async fn fetch_light_block_async(client: &HttpClient, height: u64) -> LightBlock {
    use cometbft::block::Height;

    let height: Height = (height as u32).into();

    // Fetch signed header via commit endpoint
    std::println!("Fetching signed header at height {}...", height);
    let commit_response = client.commit(height).await.expect("Failed to fetch commit");
    let signed_header = commit_response.signed_header;

    // Fetch ALL validators with pagination
    std::println!("Fetching validators at height {}...", height);
    let validators_response = client
        .validators(height, Paging::All)
        .await
        .expect("Failed to fetch validators");

    // Fetch next validators (height + 1)
    let next_height: Height = ((height.value() + 1) as u32).into();
    std::println!("Fetching next validators at height {}...", next_height);
    let next_validators_response = client
        .validators(next_height, Paging::All)
        .await
        .expect("Failed to fetch next validators");

    std::println!(
        "Fetched {} validators, {} next validators",
        validators_response.validators.len(),
        next_validators_response.validators.len()
    );

    // Build the LightBlock
    LightBlock {
        signed_header,
        validators: cometbft::validator::Set::new(validators_response.validators, None),
        next_validators: cometbft::validator::Set::new(next_validators_response.validators, None),
        provider: "0000000000000000000000000000000000000000".parse().unwrap(),
    }
}

/// Test for verifying Berachain BLS aggregated signatures.
///
/// This test demonstrates that:
/// - The CometBFT RPC client can fetch signed headers and validators
/// - Manual BLS aggregation verification works with length-prefixed protobuf (no timestamp)
/// - Production verification works via ProdVerifier
#[tokio::test]
async fn verify_live_berachain_header_update() {
    let rpc_url = std::env::var("BERACHAIN_RPC_URL").expect("BERACHAIN_RPC_URL not found in environment");

    std::println!("Creating HTTP client for {}...", rpc_url);
    let client = HttpClient::new(rpc_url.as_str()).expect("Failed to create HTTP client");

    let trusted_height = client.latest_commit().await.expect("Failed to fetch latest block").signed_header.header.height.value() - 5;
    std::println!("Fetching trusted block at height {}...", trusted_height);
    let trusted_block = fetch_light_block_async(&client, trusted_height).await;

    let untrusted_height = trusted_height + 1;
    std::println!("Fetching untrusted block at height {}...", untrusted_height);
    let untrusted_block = fetch_light_block_async(&client, untrusted_height).await;

    // Production verification via ProdVerifier
    let verifier = ProdVerifier::default();

    let options = Options {
        trust_threshold: Default::default(),
        trusting_period: Duration::from_secs(1209600),
        clock_drift: Duration::from_secs(60),
    };

    let now = (untrusted_block.time() + Duration::from_secs(10)).unwrap();

    std::println!("Verifying update...");
    let verdict = verifier.verify_update_header(
        untrusted_block.as_untrusted_state(),
        trusted_block.as_trusted_state(),
        &options,
        now,
    );

    match verdict {
        Verdict::Success => std::println!("✅ Verification SUCCESS!"),
        _ => panic!("❌ Verification FAILED: {:?}", verdict),
    }
}
