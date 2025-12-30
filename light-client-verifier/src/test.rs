extern crate std;

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use core::time::Duration;
use core::convert::TryInto;
use cometbft::block::CommitSig;
use cometbft_testgen::{
    light_block::LightBlock as TestgenLightBlock, Generator,
};
use serde_json::Value;
use crate::options::Options;
use crate::{ProdVerifier, Verdict, Verifier};
use crate::types::LightBlock;

use blst::min_pk::{PublicKey, Signature};
use blst::BLST_ERROR;
use prost::Message;

// --- Protobuf Definitions matching Berachain Spec (No Timestamp) ---
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanonicalVote {
    #[prost(int32, tag="1")]
    pub r#type: i32, // SignedMsgType (2 for Precommit)

    #[prost(sfixed64, tag="2")]
    pub height: i64,

    #[prost(sfixed64, tag="3")]
    pub round: i64,

    #[prost(message, optional, tag="4")]
    pub block_id: Option<CanonicalBlockID>,

    // Field 5 (Timestamp) is removed/reserved in Berachain

    #[prost(string, tag="6")]
    pub chain_id: String,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanonicalBlockID {
    #[prost(bytes="vec", tag="1")]
    pub hash: Vec<u8>,

    #[prost(message, optional, tag="2")]
    pub part_set_header: Option<CanonicalPartSetHeader>,
}

#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CanonicalPartSetHeader {
    #[prost(uint32, tag="1")]
    pub total: u32,

    #[prost(bytes="vec", tag="2")]
    pub hash: Vec<u8>,
}

fn fetch_light_block(height: u64) -> LightBlock {
    let client = reqwest::blocking::Client::new();

    let rpc_url = std::env::var("RPC_URL")
        .unwrap_or_else(|_| "https://hyperbridge.rpc-mainnet.berachain.com".to_string());
    let api_key = std::env::var("API_KEY")
        .unwrap_or_else(|_| "".to_string());

    let commit_url = format!("{}/commit?height={}&apikey={}", rpc_url, height, api_key);
    let commit_resp: Value = client.get(&commit_url).send().unwrap().json().unwrap();

    // Fetch ALL Validators
    let mut all_vals_json = Vec::new();
    let mut page = 1;
    let per_page = 100;

    loop {
        let vals_url = format!("{}/validators?height={}&per_page={}&page={}&apikey={}", rpc_url, height, per_page, page, api_key);
        std::println!("Fetching validators page {}: {}", page, vals_url);

        let vals_resp: Value = client.get(&vals_url).send().unwrap().json().unwrap();
        let result = &vals_resp["result"];

        if let Some(vals) = result["validators"].as_array() {
            all_vals_json.extend_from_slice(vals);
        }

        let total_str = result["total"].as_str().unwrap_or("0");
        let total: usize = total_str.parse().unwrap_or(0);

        if all_vals_json.len() >= total || result["validators"].as_array().map_or(true, |v| v.is_empty()) {
            break;
        }
        page += 1;
    }

    // Fetch ALL next validators (same pagination logic as current validators)
    let mut all_next_vals_json = Vec::new();
    let mut next_page = 1;
    loop {
        let next_vals_url = format!("{}/validators?height={}&per_page={}&page={}&apikey={}", rpc_url, height + 1, per_page, next_page, api_key);
        std::println!("Fetching next validators page {}: {}", next_page, next_vals_url);

        let next_vals_resp: Value = client.get(&next_vals_url).send().unwrap().json().unwrap();
        let result = &next_vals_resp["result"];

        if let Some(vals) = result["validators"].as_array() {
            all_next_vals_json.extend_from_slice(vals);
        }

        let total_str = result["total"].as_str().unwrap_or("0");
        let total: usize = total_str.parse().unwrap_or(0);

        if all_next_vals_json.len() >= total || result["validators"].as_array().map_or(true, |v| v.is_empty()) {
            break;
        }
        next_page += 1;
    }

    let json_header = &commit_resp["result"]["signed_header"]["header"];
    let json_commit = &commit_resp["result"]["signed_header"]["commit"];

    let mut light_block: LightBlock = TestgenLightBlock::new_default(1)
        .generate()
        .expect("failed to generate scaffold")
        .into();

    let parse_u64 = |v: &Value| -> u64 {
        if let Some(s) = v.as_str() {
            s.parse().unwrap()
        } else if let Some(n) = v.as_u64() {
            n
        } else if v.is_null() {
            0
        } else {
            panic!("Expected string or u64 for json field, got: {:?}", v);
        }
    };

    light_block.signed_header.header.version.block = parse_u64(&json_header["version"]["block"]);
    light_block.signed_header.header.version.app = parse_u64(&json_header["version"]["app"]);

    light_block.signed_header.header.chain_id = json_header["chain_id"].as_str().unwrap().parse().unwrap();
    light_block.signed_header.header.height = (parse_u64(&json_header["height"]) as u32).into();

    let time_str = json_header["time"].as_str().unwrap();
    let vote_time: cometbft::Time = time_str.parse().expect("Failed to parse header time");
    light_block.signed_header.header.time = vote_time;

    let lb_id = &json_header["last_block_id"];
    light_block.signed_header.header.last_block_id = if lb_id["hash"].as_str().unwrap_or("").is_empty() {
        None
    } else {
        Some(cometbft::block::Id {
            hash: lb_id["hash"].as_str().unwrap().parse().unwrap(),
            part_set_header: cometbft::block::parts::Header::new(
                lb_id["parts"]["total"].as_u64().unwrap() as u32,
                lb_id["parts"]["hash"].as_str().unwrap().parse().unwrap(),
            ).unwrap(),
        })
    };

    light_block.signed_header.header.last_commit_hash = json_header["last_commit_hash"].as_str().filter(|s| !s.is_empty()).map(|s| s.parse().unwrap());
    light_block.signed_header.header.data_hash = json_header["data_hash"].as_str().filter(|s| !s.is_empty()).map(|s| s.parse().unwrap());
    light_block.signed_header.header.validators_hash = json_header["validators_hash"].as_str().unwrap().parse().unwrap();
    light_block.signed_header.header.next_validators_hash = json_header["next_validators_hash"].as_str().unwrap().parse().unwrap();
    light_block.signed_header.header.consensus_hash = json_header["consensus_hash"].as_str().unwrap().parse().unwrap();
    light_block.signed_header.header.app_hash = json_header["app_hash"].as_str().unwrap().parse().unwrap();
    light_block.signed_header.header.last_results_hash = json_header["last_results_hash"].as_str().filter(|s| !s.is_empty()).map(|s| s.parse().unwrap());
    light_block.signed_header.header.evidence_hash = json_header["evidence_hash"].as_str().filter(|s| !s.is_empty()).map(|s| s.parse().unwrap());
    light_block.signed_header.header.proposer_address = json_header["proposer_address"].as_str().unwrap().parse().unwrap();

    light_block.signed_header.commit.height = (parse_u64(&json_commit["height"]) as u32).into();
    light_block.signed_header.commit.round = (parse_u64(&json_commit["round"]) as u16).into();

    light_block.signed_header.commit.block_id.hash = json_commit["block_id"]["hash"].as_str().unwrap().parse().unwrap();
    light_block.signed_header.commit.block_id.part_set_header = cometbft::block::parts::Header::new(
        json_commit["block_id"]["parts"]["total"].as_u64().unwrap() as u32,
        json_commit["block_id"]["parts"]["hash"].as_str().unwrap().parse().unwrap(),
    ).unwrap();

    let raw_sigs = json_commit["signatures"].as_array().unwrap();
    let mut new_sigs = Vec::new();

    for sig in raw_sigs {
        let flag = sig["block_id_flag"].as_u64().unwrap();
        let addr_str = sig["validator_address"].as_str().unwrap_or("");

        let addr = if addr_str.is_empty() {
            cometbft::account::Id::new([0u8; 20])
        } else {
            addr_str.parse().unwrap()
        };

        let signature_bytes = if let Some(s) = sig["signature"].as_str() {
            use base64::{Engine as _, engine::general_purpose};
            general_purpose::STANDARD.decode(s).expect("Failed to decode signature base64")
        } else {
            Vec::new()
        };

        let parsed_sig = match flag {
            2 => CommitSig::BlockIdFlagCommit {
                validator_address: addr,
                timestamp: vote_time,
                signature: Some(signature_bytes.try_into().unwrap()),
            },
            4 => CommitSig::BlockIdFlagAggCommit {
                validator_address: addr,
                timestamp: vote_time,
                signature: Some(signature_bytes.try_into().unwrap()),
            },
            5 => CommitSig::BlockIdFlagAggCommitAbsent {
                validator_address: addr,
                timestamp: vote_time,
                signature: None,
            },
            1 => CommitSig::BlockIdFlagAbsent,
            _ => CommitSig::BlockIdFlagAbsent,
        };
        new_sigs.push(parsed_sig);
    }
    light_block.signed_header.commit.signatures = new_sigs;

    let parse_vals = |json_vals: &[Value]| -> Vec<cometbft::validator::Info> {
        let mut vals = Vec::new();
        for v in json_vals {
            let address = v["address"].as_str().unwrap().parse().unwrap();
            let voting_power: u64 = v["voting_power"].as_str().unwrap().parse().unwrap();
            let proposer_priority: i64 = v["proposer_priority"].as_str().unwrap().parse().unwrap();

            let pub_key: cometbft::PublicKey = serde_json::from_value(v["pub_key"].clone())
                .unwrap_or_else(|e| panic!("Failed to parse public key: {:?} Error: {}", v["pub_key"], e));

            let val = cometbft::validator::Info {
                address,
                pub_key,
                power: voting_power.try_into().unwrap(),
                proposer_priority: proposer_priority.into(),
                name: None,
            };
            vals.push(val);
        }
        vals
    };

    // Strict CometBFT Sorting: Power Descending, then Address Ascending
    light_block.validators = cometbft::validator::Set::new(parse_vals(&all_vals_json), None);
    light_block.next_validators = cometbft::validator::Set::new(parse_vals(&all_next_vals_json), None);
    light_block.provider = "0000000000000000000000000000000000000000".parse().unwrap();

    light_block
}

// Convert 96-byte Uncompressed G1 -> 48-byte Compressed G1
// Naive implementation: take X coordinate, set high bit.
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
        std::println!("❌ VALIDATOR HASH MISMATCH! The local validator set does not match the header.");
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
                std::println!("Signature[{}]: Validator {} not found in set", i, validator_address);
                continue;
            }
        };

        if i < 3 {
            std::println!("Sig[{}]: Validator {} found with power {}", i, val.address, val.power);
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
            _ => {}
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
/// Manual BLS aggregation verification WORKS with length-prefixed protobuf (no timestamp)
///
/// For aggregated BLS signatures, the canonical vote should NOT include timestamp (field 5),
/// and the verification should aggregate all participating validators' public keys before
/// verifying against the single aggregated signature.
#[test]
#[ignore]
fn verify_live_berachain_header_update() {
    let trusted_height = 14737892;
    std::println!("Fetching trusted block at height {}...", trusted_height);
    let trusted_block = fetch_light_block(trusted_height);

    let untrusted_height = trusted_height + 1;
    std::println!("Fetching untrusted block at height {}...", untrusted_height);
    let untrusted_block = fetch_light_block(untrusted_height);

    // This manual check should pass - it uses the correct message format
    // (length-prefixed protobuf without timestamp)
    verify_bls_aggregation(&untrusted_block);

    // Note: Production verification currently fails because:
    // 1. sign_bytes include timestamp which aggregated BLS signatures don't use
    // 2. It tries to verify individual signatures instead of the aggregated signature
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