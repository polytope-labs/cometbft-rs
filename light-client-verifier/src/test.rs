extern crate std;

use crate::options::Options;
use crate::types::LightBlock;
use crate::{ProdVerifier, Verdict, Verifier};
use alloc::string::ToString;
use alloc::vec::Vec;
use cometbft::block::CommitSig;
use cometbft_rpc::{Client, HttpClient, Paging};
use core::time::Duration;

use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;
use prost::Message;

// --- Protobuf Definitions matching Berachain Spec (No Timestamp) ---
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanonicalVote {
    #[prost(int32, tag = "1")]
    pub r#type: i32, // SignedMsgType (2 for Precommit)

    #[prost(sfixed64, tag = "2")]
    pub height: i64,

    #[prost(sfixed64, tag = "3")]
    pub round: i64,

    #[prost(message, optional, tag = "4")]
    pub block_id: Option<CanonicalBlockID>,

    // Field 5 (Timestamp) is removed/reserved in Berachain
    #[prost(string, tag = "6")]
    pub chain_id: alloc::string::String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanonicalBlockID {
    #[prost(bytes = "vec", tag = "1")]
    pub hash: Vec<u8>,

    #[prost(message, optional, tag = "2")]
    pub part_set_header: Option<CanonicalPartSetHeader>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanonicalPartSetHeader {
    #[prost(uint32, tag = "1")]
    pub total: u32,

    #[prost(bytes = "vec", tag = "2")]
    pub hash: Vec<u8>,
}

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

/// Synchronous wrapper for fetch_light_block_async
fn fetch_light_block(client: &HttpClient, height: u64) -> LightBlock {
    let rt = tokio::runtime::Runtime::new().expect("Failed to create tokio runtime");
    rt.block_on(fetch_light_block_async(client, height))
}

// Convert 96-byte Uncompressed G1 -> 48-byte Compressed G1
fn compress_pk_naive(k: &[u8]) -> Vec<u8> {
    if k.len() == 96 {
        let mut compressed = k[0..48].to_vec();
        // Set compressed bit (0x80)
        compressed[0] |= 0x80;
        return compressed;
    }
    k.to_vec()
}

fn construct_canonical_vote_prost(light_block: &LightBlock) -> Vec<u8> {
    let header = &light_block.signed_header.header;
    let commit = &light_block.signed_header.commit;

    let part_set_header = CanonicalPartSetHeader {
        total: commit.block_id.part_set_header.total,
        hash: commit.block_id.part_set_header.hash.as_bytes().to_vec(),
    };

    let block_id = CanonicalBlockID {
        hash: commit.block_id.hash.as_bytes().to_vec(),
        part_set_header: Some(part_set_header),
    };

    let vote = CanonicalVote {
        r#type: 2, // PRECOMMIT
        height: header.height.value() as i64,
        round: commit.round.value() as i64,
        block_id: Some(block_id),
        chain_id: header.chain_id.as_str().to_string(),
    };

    let mut buf = Vec::new();
    vote.encode(&mut buf).unwrap();
    buf
}

fn verify_bls_aggregation(light_block: &LightBlock) {
    std::println!("--- STARTING MANUAL BLS AGGREGATION CHECK ---");

    let validators = light_block.validators.validators();
    let signatures = &light_block.signed_header.commit.signatures;

    std::println!("Validators Count: {}", validators.len());
    std::println!("Signatures Count: {}", signatures.len());

    // Hash check
    let computed_val_hash = light_block.validators.hash();
    let header_val_hash = light_block.signed_header.header.validators_hash;
    if computed_val_hash != header_val_hash {
        std::println!(
            "❌ VALIDATOR HASH MISMATCH! The local validator set does not match the header."
        );
        return;
    }
    std::println!("Validator hash matches header");

    let mut participating_pks_all = Vec::new();
    let mut collected_signatures = Vec::new();

    // Helper to find validator by address
    let find_validator = |addr: &cometbft::account::Id| -> Option<&cometbft::validator::Info> {
        validators.iter().find(|v| &v.address == addr)
    };

    // Iterate through signatures and look up validators by address (not by index!)
    for (i, sig) in signatures.iter().enumerate() {
        let validator_address = match sig.validator_address() {
            Some(addr) => addr,
            None => continue, // Skip absent signatures
        };

        let val = match find_validator(&validator_address) {
            Some(v) => v,
            None => {
                std::println!(
                    "Signature[{}]: Validator {} not found in set",
                    i,
                    validator_address
                );
                continue;
            },
        };

        if i < 3 {
            std::println!(
                "Sig[{}]: Validator {} found with power {}",
                i,
                val.address,
                val.power
            );
        }

        match sig {
            CommitSig::BlockIdFlagAggCommit { signature, .. } => {
                if let cometbft::PublicKey::Bls12_381(k) = &val.pub_key {
                    if let Ok(pk) = PublicKey::from_bytes(k) {
                        participating_pks_all.push(pk);
                    } else {
                        let k_comp = compress_pk_naive(k);
                        if let Ok(pk) = PublicKey::from_bytes(&k_comp) {
                            participating_pks_all.push(pk);
                        }
                    }
                }

                if let Some(sig_bytes) = signature {
                    if let Ok(sig) = Signature::from_bytes(sig_bytes.as_ref()) {
                        collected_signatures.push(sig);
                    }
                }
            },
            CommitSig::BlockIdFlagAggCommitAbsent { .. } => {
                if let cometbft::PublicKey::Bls12_381(k) = &val.pub_key {
                    if let Ok(pk) = PublicKey::from_bytes(k) {
                        participating_pks_all.push(pk);
                    } else {
                        let k_comp = compress_pk_naive(k);
                        if let Ok(pk) = PublicKey::from_bytes(&k_comp) {
                            participating_pks_all.push(pk);
                        }
                    }
                }
            },
            CommitSig::BlockIdFlagAggNil { signature, .. } => {
                if let cometbft::PublicKey::Bls12_381(k) = &val.pub_key {
                    if let Ok(pk) = PublicKey::from_bytes(k) {
                        participating_pks_all.push(pk);
                    } else {
                        let k_comp = compress_pk_naive(k);
                        if let Ok(pk) = PublicKey::from_bytes(&k_comp) {
                            participating_pks_all.push(pk);
                        }
                    }
                }

                if let Some(sig_bytes) = signature {
                    if let Ok(sig) = Signature::from_bytes(sig_bytes.as_ref()) {
                        collected_signatures.push(sig);
                    }
                }
            },
            CommitSig::BlockIdFlagAggNilAbsent { .. } => {
                if let cometbft::PublicKey::Bls12_381(k) = &val.pub_key {
                    if let Ok(pk) = PublicKey::from_bytes(k) {
                        participating_pks_all.push(pk);
                    } else {
                        let k_comp = compress_pk_naive(k);
                        if let Ok(pk) = PublicKey::from_bytes(&k_comp) {
                            participating_pks_all.push(pk);
                        }
                    }
                }
            },
            _ => {},
        }
    }

    if collected_signatures.is_empty() {
        std::println!("Missing signatures!");
        return;
    }

    let agg_sig = collected_signatures[0].clone();
    std::println!("Participating Keys: {}", participating_pks_all.len());

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

    // Construct message via Protobuf (without timestamp)
    let msg_proto = construct_canonical_vote_prost(light_block);

    // Create length-prefixed version (CometBFT style - varint length prefix)
    let mut msg_with_prefix = Vec::new();
    let len = msg_proto.len();
    if len < 128 {
        msg_with_prefix.push(len as u8);
    } else {
        msg_with_prefix.push(((len & 0x7F) | 0x80) as u8);
        msg_with_prefix.push((len >> 7) as u8);
    }
    msg_with_prefix.extend_from_slice(&msg_proto);

    let pk_refs: Vec<&PublicKey> = participating_pks_all.iter().collect();

    // Verify with length-prefixed protobuf (no timestamp)
    let result = agg_sig.fast_aggregate_verify(false, &msg_with_prefix, dst, &pk_refs);
    if result == BLST_ERROR::BLST_SUCCESS {
        std::println!("BLS aggregation verification SUCCESS!");
    } else {
        std::println!("BLS aggregation verification FAILED: {:?}", result);
    }

    std::println!("--- END MANUAL CHECK ---");
}

/// Test for verifying Berachain BLS aggregated signatures.
///
/// This test demonstrates that:
/// - The CometBFT RPC client can fetch signed headers and validators
/// - Manual BLS aggregation verification works with length-prefixed protobuf (no timestamp)
/// - Production verification works via ProdVerifier
#[test]
#[ignore]
fn verify_live_berachain_header_update() {
    let rpc_url =
        std::env::var("RPC_URL").unwrap_or_else(|_| "".to_string());

    std::println!("Creating HTTP client for {}...", rpc_url);
    let client = HttpClient::new(rpc_url.as_str()).expect("Failed to create HTTP client");

    let trusted_height = 14737892;
    std::println!("Fetching trusted block at height {}...", trusted_height);
    let trusted_block = fetch_light_block(&client, trusted_height);

    let untrusted_height = trusted_height + 1;
    std::println!("Fetching untrusted block at height {}...", untrusted_height);
    let untrusted_block = fetch_light_block(&client, untrusted_height);

    // Manual BLS verification check
    verify_bls_aggregation(&untrusted_block);

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
