extern crate std;

use alloc::{format, vec};
use alloc::vec::Vec;
use core::time::Duration;
use core::convert::TryInto;
use core::cmp::Ordering;
use cometbft::block::CommitSig;
use cometbft_testgen::{
    light_block::LightBlock as TestgenLightBlock, Generator, Validator,
};
use serde_json::Value;
use crate::options::Options;
use crate::{ProdVerifier, Verdict, Verifier};
use crate::types::LightBlock;

use blst::min_pk::{PublicKey, Signature, AggregatePublicKey, AggregateSignature};
use blst::BLST_ERROR;
use sha2::{Sha256, Digest};

const RPC_URL: &str = "https://hyperbridge.rpc-mainnet.berachain.com";
const API_KEY: &str = "jOcJswRvCglHgKVcnnTLBFE";

fn fetch_light_block(height: u64) -> LightBlock {
    let client = reqwest::blocking::Client::new();

    let commit_url = format!("{}/commit?height={}&apikey={}", RPC_URL, height, API_KEY);
    let commit_resp: Value = client.get(&commit_url).send().unwrap().json().unwrap();

    // 2. Fetch ALL Validators (Pagination Loop)
    let mut all_vals_json = Vec::new();
    let mut page = 1;
    let per_page = 100;

    loop {
        let vals_url = format!("{}/validators?height={}&per_page={}&page={}&apikey={}", RPC_URL, height, per_page, page, API_KEY);
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
    std::println!("Total Validators Fetched: {}", all_vals_json.len());

    // 3. Fetch NEXT Validators (Pagination)
    let mut next_vals_json = Vec::new();
    page = 1;
    loop {
        let vals_url = format!("{}/validators?height={}&per_page={}&page={}&apikey={}", RPC_URL, height + 1, per_page, page, API_KEY);
        std::println!("Fetching validators page {}: {}", page, vals_url);

        let vals_resp: Value = client.get(&vals_url).send().unwrap().json().unwrap();
        let result = &vals_resp["result"];

        if let Some(vals) = result["validators"].as_array() {
            next_vals_json.extend_from_slice(vals);
        }

        let total_str = result["total"].as_str().unwrap_or("0");
        let total: usize = total_str.parse().unwrap_or(0);

        if next_vals_json.len() >= total || result["validators"].as_array().map_or(true, |v| v.is_empty()) {
            break;
        }
        page += 1;
    }
    std::println!("Total Validators Fetched for height {}: {}", height + 1, next_vals_json.len());


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

        let timestamp = vote_time;

        let signature_bytes = if let Some(s) = sig["signature"].as_str() {
            use base64::{Engine as _, engine::general_purpose};
            general_purpose::STANDARD.decode(s).expect("Failed to decode signature base64")
        } else {
            Vec::new()
        };

        let parsed_sig = match flag {
            2 => CommitSig::BlockIdFlagCommit {
                validator_address: addr,
                timestamp,
                signature: Some(signature_bytes.try_into().unwrap()),
            },
            4 => CommitSig::BlockIdFlagAggCommit {
                validator_address: addr,
                timestamp,
                signature: Some(signature_bytes.try_into().unwrap()),
            },
            5 => CommitSig::BlockIdFlagAggCommitAbsent {
                validator_address: addr,
                timestamp,
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

        // Strict CometBFT Sorting: Power Descending, then Address Ascending
        vals.sort_by(|a, b| {
            let power_cmp = b.power.cmp(&a.power);
            if power_cmp == Ordering::Equal {
                a.address.cmp(&b.address)
            } else {
                power_cmp
            }
        });
        vals
    };

    // Use manually sorted lists to ensure order matches Commit Signatures
    light_block.validators = cometbft::validator::Set::new(parse_vals(&all_vals_json), None);
    light_block.next_validators = cometbft::validator::Set::new(parse_vals(&next_vals_json), None);
    light_block.provider = "0000000000000000000000000000000000000000".parse().unwrap();

    light_block
}

fn to_varint(mut n: u64) -> Vec<u8> {
    let mut buf = Vec::new();
    loop {
        let mut b = (n & 0x7F) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
        }
        buf.push(b);
        if n == 0 {
            break;
        }
    }
    buf
}

#[derive(Clone, Copy, Debug)]
struct MsgConfig {
    msg_type: u8,
    include_msg_type: bool,
    force_round_serialization: bool,
    force_part_set_header_tag: bool,
    include_timestamp: bool,
    timestamp_is_zero: bool,
    include_chain_id: bool,
    chain_id_field_tag: u8,
    include_block_id: bool,
}

fn construct_canonical_vote_bytes(light_block: &LightBlock, timestamp: Option<cometbft::Time>, config: MsgConfig) -> Vec<u8> {
    let header = &light_block.signed_header.header;
    let commit = &light_block.signed_header.commit;

    let mut msg = Vec::new();

    // 1. type
    if config.include_msg_type {
        msg.push(0x08);
        msg.push(config.msg_type);
    }

    // 2. height
    msg.push(0x11);
    let h = header.height.value();
    msg.extend_from_slice(&h.to_le_bytes());

    // 3. round
    let r = commit.round.value() as u64;
    if config.force_round_serialization || r > 0 {
        msg.push(0x19);
        msg.extend_from_slice(&r.to_le_bytes());
    }

    // 4. block_id
    if config.include_block_id {
        let block_id = &commit.block_id;
        let mut block_id_bytes = Vec::new();

        if !block_id.hash.as_bytes().is_empty() {
            block_id_bytes.push(0x0a);
            block_id_bytes.extend(to_varint(block_id.hash.as_bytes().len() as u64));
            block_id_bytes.extend_from_slice(block_id.hash.as_bytes());
        }

        let mut parts_bytes = Vec::new();
        if block_id.part_set_header.total > 0 {
            parts_bytes.push(0x08);
            parts_bytes.extend(to_varint(block_id.part_set_header.total as u64));
        }
        if !block_id.part_set_header.hash.as_bytes().is_empty() {
            parts_bytes.push(0x12);
            parts_bytes.extend(to_varint(block_id.part_set_header.hash.as_bytes().len() as u64));
            parts_bytes.extend_from_slice(block_id.part_set_header.hash.as_bytes());
        }

        if !parts_bytes.is_empty() {
            block_id_bytes.push(0x12);
            block_id_bytes.extend(to_varint(parts_bytes.len() as u64));
            block_id_bytes.extend(parts_bytes);
        } else if config.force_part_set_header_tag {
            // gogoproto.nullable = false implies struct always exists.
            // If empty, it's 0x12 0x00
            block_id_bytes.push(0x12);
            block_id_bytes.push(0x00);
        }

        if !block_id_bytes.is_empty() {
            msg.push(0x22);
            msg.extend(to_varint(block_id_bytes.len() as u64));
            msg.extend(block_id_bytes);
        }
    }

    // 5. Timestamp
    if config.include_timestamp {
        if let Some(ts) = timestamp {
            let mut time_bytes = Vec::new();
            if !config.timestamp_is_zero {
                let seconds = ts.unix_timestamp();
                let nanos = (ts.unix_timestamp_nanos() % 1_000_000_000) as u32;

                if seconds > 0 {
                    time_bytes.push(0x08);
                    time_bytes.extend(to_varint(seconds as u64));
                }
                if nanos > 0 {
                    time_bytes.push(0x10);
                    time_bytes.extend(to_varint(nanos as u64));
                }
            }

            if !time_bytes.is_empty() {
                msg.push(0x2a); // Field 5
                msg.extend(to_varint(time_bytes.len() as u64));
                msg.extend(time_bytes);
            } else if config.timestamp_is_zero {
                msg.push(0x2a);
                msg.push(0x00);
            }
        }
    }

    // 6. chain_id
    if config.include_chain_id {
        let chain_id = header.chain_id.as_str();
        if !chain_id.is_empty() {
            msg.push(config.chain_id_field_tag);
            msg.extend(to_varint(chain_id.len() as u64));
            msg.extend_from_slice(chain_id.as_bytes());
        }
    }

    msg
}

fn verify_bls_aggregation(light_block: &LightBlock) {
    std::println!("--- STARTING MANUAL BLS AGGREGATION CHECK ---");

    let validators = light_block.validators.validators();
    let signatures = &light_block.signed_header.commit.signatures;

    std::println!("Validators Count: {}", validators.len());
    std::println!("Signatures Count: {}", signatures.len());

    let computed_val_hash = light_block.validators.hash();
    let header_val_hash = light_block.signed_header.header.validators_hash;
    std::println!("Computed Val Hash: {}", computed_val_hash);
    std::println!("Header Val Hash:   {}", header_val_hash);

    if computed_val_hash != header_val_hash {
        std::println!("❌ VALIDATOR HASH MISMATCH! The local validator set does not match the header.");
        return;
    }

    if validators.len() != signatures.len() {
        std::println!("❌ Length mismatch: Vals={} Sigs={}", validators.len(), signatures.len());
        return;
    }

    let mut participating_pks_all = Vec::new();
    let mut collected_signatures = Vec::new();
    let mut commit_timestamp: Option<cometbft::Time> = None;

    for (i, sig) in signatures.iter().enumerate() {
        let val = &validators[i];

        // Debug address alignment for first few
        if i < 3 {
            if let Some(sig_addr) = sig.validator_address() {
                let match_sym = if sig_addr == val.address { "==" } else { "!=" };
                std::println!("Align[{}]: Val {} {} Sig {}", i, val.address, match_sym, sig_addr);
            }
        }

        match sig {
            CommitSig::BlockIdFlagAggCommit { signature, timestamp, .. } => {
                if commit_timestamp.is_none() {
                    commit_timestamp = Some(*timestamp);
                }

                if let cometbft::PublicKey::Bls12_381(k) = &val.pub_key {
                    if let Ok(pk) = PublicKey::from_bytes(k) {
                        participating_pks_all.push(pk);
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
                    }
                }
            },
            _ => {}
        }
    }

    if collected_signatures.is_empty() {
        std::println!("❌ Missing signatures!");
        return;
    }

    let agg_sig = collected_signatures[0].clone();
    std::println!("Participating Keys: {}", participating_pks_all.len());

    if let Some(ts) = commit_timestamp {
        std::println!("Commit Timestamp: {:?}", ts);
    } else {
        std::println!("⚠️ No Commit Timestamp found.");
    }

    let dsts = vec![
        ("NUL", b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_".as_slice()),
        ("POP", b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_".as_slice()),
    ];

    let round_options = vec![false, true];
    let ps_options = vec![false, true];
    let ts_options = vec![(false, false), (true, false)]; // (Included, IsZero)
    let type_options = vec![2];
    let chain_id_inc_options = vec![true];
    let block_id_inc_options = vec![true, false];
    let include_msg_type_options = vec![true];

    let pk_refs: Vec<&PublicKey> = participating_pks_all.iter().collect();

    for (dst_name, dst) in &dsts {
        for force_round in &round_options {
            for force_ps in &ps_options {
                for (include_ts, ts_zero) in &ts_options {
                    for msg_type in &type_options {
                        for inc_chain_id in &chain_id_inc_options {
                            for inc_block_id in &block_id_inc_options {
                                for inc_msg_type in &include_msg_type_options {

                                    let chain_opts = if *inc_chain_id {
                                        if *include_ts { vec![0x32] } else { vec![0x32, 0x2a] }
                                    } else {
                                        vec![0x00]
                                    };

                                    for chain_tag in chain_opts {
                                        let config = MsgConfig {
                                            msg_type: *msg_type,
                                            include_msg_type: *inc_msg_type,
                                            force_round_serialization: *force_round,
                                            force_part_set_header_tag: *force_ps,
                                            include_timestamp: *include_ts,
                                            timestamp_is_zero: *ts_zero,
                                            include_chain_id: *inc_chain_id,
                                            chain_id_field_tag: chain_tag,
                                            include_block_id: *inc_block_id,
                                        };

                                        // Use Commit Timestamp, NOT header timestamp
                                        let msg = construct_canonical_vote_bytes(light_block, commit_timestamp, config);

                                        // A: Raw Bytes
                                        let res_raw = agg_sig.fast_aggregate_verify(false, &msg, dst, &pk_refs);

                                        // B: SHA256 Pre-Hash
                                        let mut hasher = Sha256::new();
                                        hasher.update(&msg);
                                        let msg_sha = hasher.finalize();
                                        let res_sha = agg_sig.fast_aggregate_verify(true, &msg_sha, dst, &pk_refs);

                                        if res_raw == BLST_ERROR::BLST_SUCCESS {
                                            std::println!("✅ SUCCESS FOUND (RAW MSG)!");
                                            std::println!("   DST: {}", dst_name);
                                            std::println!("   Config: R:{}, PS:{}, TS:{}, Zero:{}, CT:{}",
                                                          force_round, force_ps, include_ts, ts_zero, chain_tag);
                                            std::println!("   Hex: {}", hex::encode(&msg));
                                            return;
                                        }

                                        if res_sha == BLST_ERROR::BLST_SUCCESS {
                                            std::println!("✅ SUCCESS FOUND (SHA256 HASHED MSG)!");
                                            std::println!("   DST: {}", dst_name);
                                            std::println!("   Config: R:{}, PS:{}, TS:{}, Zero:{}, CT:{}",
                                                          force_round, force_ps, include_ts, ts_zero, chain_tag);
                                            std::println!("   Hex (Pre-Hash): {}", hex::encode(&msg));
                                            return;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    std::println!("❌ ALL COMBINATIONS FAILED.");
    std::println!("--- END MANUAL CHECK ---");
}

#[test]
#[ignore]
fn verify_live_berachain_header_update() {
    let trusted_height = 14737892;
    std::println!("Fetching trusted block at height {}...", trusted_height);
    let trusted_block = fetch_light_block(trusted_height);

    let untrusted_height = trusted_height + 1;
    std::println!("Fetching untrusted block at height {}...", untrusted_height);
    let untrusted_block = fetch_light_block(untrusted_height);

    verify_bls_aggregation(&untrusted_block);

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