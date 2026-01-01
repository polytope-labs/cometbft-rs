//! CommitSig within Commit

use cometbft_proto::google::protobuf::Timestamp;

use crate::{account, prelude::*, Signature, Time};

/// The special zero timestamp is to be used for absent votes,
/// where there is no timestamp to speak of.
///
/// It is not the standard UNIX epoch at 0 seconds, ie. 1970-01-01 00:00:00 UTC,
/// but a custom CometBFT-specific one for 1-1-1 00:00:00 UTC
///
/// From the corresponding CometBFT `Time` struct:
///
/// The zero value for a Time is defined to be
/// January 1, year 1, 00:00:00.000000000 UTC
/// which (1) looks like a zero, or as close as you can get in a date
/// (1-1-1 00:00:00 UTC), (2) is unlikely enough to arise in practice to
/// be a suitable "not set" sentinel, unlike Jan 1 1970, and (3) has a
/// non-negative year even in time zones west of UTC, unlike 1-1-0
/// 00:00:00 UTC, which would be 12-31-(-1) 19:00:00 in New York.
const ZERO_TIMESTAMP: Timestamp = Timestamp {
    seconds: -62135596800,
    nanos: 0,
};

/// CommitSig represents a signature of a validator.
/// It's a part of the Commit and can be used to reconstruct the vote set given the validator set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CommitSig {
    /// no vote was received from a validator.
    BlockIdFlagAbsent,
    /// voted for the Commit.BlockID.
    BlockIdFlagCommit {
        /// Validator address
        validator_address: account::Id,
        /// Timestamp of vote
        timestamp: Time,
        /// Signature of vote
        signature: Option<Signature>,
    },
    /// voted for nil.
    BlockIdFlagNil {
        /// Validator address
        validator_address: account::Id,
        /// Timestamp of vote
        timestamp: Time,
        /// Signature of vote
        signature: Option<Signature>,
    },
    BlockIdFlagAggCommit {
        validator_address: account::Id,
        timestamp: Time,
        signature: Option<Signature>,
    },
    BlockIdFlagAggCommitAbsent {
        validator_address: account::Id,
        timestamp: Time,
        signature: Option<Signature>,
    },
    BlockIdFlagAggNil {
        validator_address: account::Id,
        timestamp: Time,
        signature: Option<Signature>,
    },
    BlockIdFlagAggNilAbsent {
        validator_address: account::Id,
        timestamp: Time,
        signature: Option<Signature>,
    },
}

impl CommitSig {
    /// Get the address of this validator if a vote was received.
    pub fn validator_address(&self) -> Option<account::Id> {
        match self {
            Self::BlockIdFlagCommit {
                validator_address, ..
            } => Some(*validator_address),
            Self::BlockIdFlagNil {
                validator_address, ..
            } => Some(*validator_address),
            Self::BlockIdFlagAggCommit {
                validator_address, ..
            } => Some(*validator_address),
            Self::BlockIdFlagAggCommitAbsent {
                validator_address, ..
            } => Some(*validator_address),
            Self::BlockIdFlagAggNil {
                validator_address, ..
            } => Some(*validator_address),
            Self::BlockIdFlagAggNilAbsent {
                validator_address, ..
            } => Some(*validator_address),
            _ => None,
        }
    }

    /// Whether this signature is absent (no vote was received from validator)
    pub fn is_absent(&self) -> bool {
        self == &Self::BlockIdFlagAbsent
    }

    /// Whether this signature is a commit  (validator voted for the Commit.BlockId)
    pub fn is_commit(&self) -> bool {
        matches!(
            self,
            Self::BlockIdFlagCommit { .. }
                | Self::BlockIdFlagAggCommit { .. }
                | Self::BlockIdFlagAggCommitAbsent { .. }
        )
    }

    /// Whether this signature is nil (validator voted for nil)
    pub fn is_nil(&self) -> bool {
        matches!(
            self,
            Self::BlockIdFlagNil { .. }
                | Self::BlockIdFlagAggNil { .. }
                | Self::BlockIdFlagAggNilAbsent { .. }
        )
    }
}

cometbft_old_pb_modules! {
    use super::{CommitSig, ZERO_TIMESTAMP};
    use crate::{error::Error, prelude::*, Signature};

    use pb::types::{BlockIdFlag, CommitSig as RawCommitSig};

    impl TryFrom<RawCommitSig> for CommitSig {
        type Error = Error;

        fn try_from(value: RawCommitSig) -> Result<Self, Self::Error> {
            if value.block_id_flag == BlockIdFlag::Absent as i32 {
                if value.timestamp.is_some() {
                    let timestamp = value.timestamp.unwrap();
                    // 0001-01-01T00:00:00.000Z translates to EPOCH-62135596800 seconds
                    if timestamp.nanos != 0 || timestamp.seconds != -62135596800 {
                        return Err(Error::invalid_timestamp(
                            "absent commitsig has non-zero timestamp".to_string(),
                        ));
                    }
                }

                if !value.signature.is_empty() {
                    return Err(Error::invalid_signature(
                        "expected empty signature for absent commitsig".to_string(),
                    ));
                }

                return Ok(CommitSig::BlockIdFlagAbsent);
            }

            if value.block_id_flag == BlockIdFlag::Commit as i32 {
                if value.signature.is_empty() {
                    return Err(Error::invalid_signature(
                        "expected non-empty signature for regular commitsig".to_string(),
                    ));
                }

                if value.validator_address.is_empty() {
                    return Err(Error::invalid_validator_address());
                }

                let timestamp = value
                    .timestamp
                    .ok_or_else(Error::missing_timestamp)?
                    .try_into()?;

                return Ok(CommitSig::BlockIdFlagCommit {
                    validator_address: value.validator_address.try_into()?,
                    timestamp,
                    signature: Signature::new(value.signature)?,
                });
            }
            if value.block_id_flag == BlockIdFlag::Nil as i32 {
                if value.signature.is_empty() {
                    return Err(Error::invalid_signature(
                        "nil commitsig has no signature".to_string(),
                    ));
                }
                if value.validator_address.is_empty() {
                    return Err(Error::invalid_validator_address());
                }
                return Ok(CommitSig::BlockIdFlagNil {
                    validator_address: value.validator_address.try_into()?,
                    timestamp: value
                        .timestamp
                        .ok_or_else(Error::missing_timestamp)?
                        .try_into()?,
                    signature: Signature::new(value.signature)?,
                });
            }
            Err(Error::block_id_flag())
        }
    }

    impl From<CommitSig> for RawCommitSig {
        fn from(commit: CommitSig) -> RawCommitSig {
            match commit {
                CommitSig::BlockIdFlagAbsent => RawCommitSig {
                    block_id_flag: BlockIdFlag::Absent as i32,
                    validator_address: Vec::new(),
                    timestamp: Some(ZERO_TIMESTAMP),
                    signature: Vec::new(),
                },
                CommitSig::BlockIdFlagNil {
                    validator_address,
                    timestamp,
                    signature,
                } => RawCommitSig {
                    block_id_flag: BlockIdFlag::Nil as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagCommit {
                    validator_address,
                    timestamp,
                    signature,
                } => RawCommitSig {
                    block_id_flag: BlockIdFlag::Commit as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagAggCommit {
                    validator_address,
                    timestamp,
                    signature,
                } => RawCommitSig {
                    block_id_flag: BlockIdFlag::Commit as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagAggCommitAbsent {
                    validator_address,
                    timestamp,
                    signature,
                } => RawCommitSig {
                    block_id_flag: BlockIdFlag::Commit as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagAggNil {
                    validator_address,
                    timestamp,
                    signature,
                } => RawCommitSig {
                    block_id_flag: BlockIdFlag::Nil as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagAggNilAbsent {
                    validator_address,
                    timestamp,
                    signature,
                } => RawCommitSig {
                    block_id_flag: BlockIdFlag::Nil as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
            }
        }
    }

    #[test]
    #[cfg(test)]
    fn test_block_id_flag_absent_serialization() {
        let absent = CommitSig::BlockIdFlagAbsent;
        let raw_absent = RawCommitSig::from(absent);
        let expected = r#"{"block_id_flag":1,"validator_address":"","timestamp":"0001-01-01T00:00:00Z","signature":""}"#;
        let output = serde_json::to_string(&raw_absent).unwrap();
        assert_eq!(expected, &output);
    }

    #[test]
    #[cfg(test)]
    fn test_block_id_flag_absent_deserialization() {
        let json = r#"{"block_id_flag":1,"validator_address":"","timestamp":"0001-01-01T00:00:00Z","signature":""}"#;
        let raw_commit_sg = serde_json::from_str::<RawCommitSig>(json).unwrap();
        let commit_sig = CommitSig::try_from(raw_commit_sg).unwrap();
        assert_eq!(commit_sig, CommitSig::BlockIdFlagAbsent);
    }
}

mod v1 {
    use super::{CommitSig, ZERO_TIMESTAMP};
    use crate::{error::Error, prelude::*, Signature};
    use cometbft_proto::types::v1::{self as pb, BlockIdFlag};

    impl TryFrom<pb::CommitSig> for CommitSig {
        type Error = Error;

        fn try_from(value: pb::CommitSig) -> Result<Self, Self::Error> {
            if value.block_id_flag == BlockIdFlag::Absent as i32 {
                if value.timestamp.is_some() {
                    let timestamp = value.timestamp.unwrap();
                    // 0001-01-01T00:00:00.000Z translates to EPOCH-62135596800 seconds
                    if timestamp.nanos != 0 || timestamp.seconds != -62135596800 {
                        return Err(Error::invalid_timestamp(
                            "absent commitsig has non-zero timestamp".to_string(),
                        ));
                    }
                }

                if !value.signature.is_empty() {
                    return Err(Error::invalid_signature(
                        "expected empty signature for absent commitsig".to_string(),
                    ));
                }

                return Ok(CommitSig::BlockIdFlagAbsent);
            }

            if value.validator_address.is_empty() {
                return Err(Error::invalid_validator_address());
            }

            let timestamp = value
                .timestamp
                .ok_or_else(Error::missing_timestamp)?
                .try_into()?;

            let signature = if !value.signature.is_empty() {
                Some(Signature::new(value.signature)?)
            } else {
                None
            };

            let signature = signature.flatten();

            let validator_address = value.validator_address.try_into()?;

            match value.block_id_flag {
                x if x == BlockIdFlag::Commit as i32 => {
                    if signature.is_none() {
                        return Err(Error::invalid_signature(
                            "expected non-empty signature for regular commitsig".to_string(),
                        ));
                    }
                    Ok(CommitSig::BlockIdFlagCommit {
                        validator_address,
                        timestamp,
                        signature,
                    })
                },
                x if x == BlockIdFlag::Nil as i32 => {
                    if signature.is_none() {
                        return Err(Error::invalid_signature(
                            "nil commitsig has no signature".to_string(),
                        ));
                    }
                    Ok(CommitSig::BlockIdFlagNil {
                        validator_address,
                        timestamp,
                        signature,
                    })
                },
                x if x == BlockIdFlag::AggCommit as i32 => Ok(CommitSig::BlockIdFlagAggCommit {
                    validator_address,
                    timestamp,
                    signature,
                }),
                x if x == BlockIdFlag::AggCommitAbsent as i32 => {
                    Ok(CommitSig::BlockIdFlagAggCommitAbsent {
                        validator_address,
                        timestamp,
                        signature,
                    })
                },
                x if x == BlockIdFlag::AggNil as i32 => Ok(CommitSig::BlockIdFlagAggNil {
                    validator_address,
                    timestamp,
                    signature,
                }),
                x if x == BlockIdFlag::AggNilAbsent as i32 => {
                    Ok(CommitSig::BlockIdFlagAggNilAbsent {
                        validator_address,
                        timestamp,
                        signature,
                    })
                },
                _ => Err(Error::block_id_flag()),
            }
        }
    }

    impl From<CommitSig> for pb::CommitSig {
        fn from(commit: CommitSig) -> pb::CommitSig {
            match commit {
                CommitSig::BlockIdFlagAbsent => pb::CommitSig {
                    block_id_flag: BlockIdFlag::Absent as i32,
                    validator_address: Vec::new(),
                    timestamp: Some(ZERO_TIMESTAMP),
                    signature: Vec::new(),
                },
                CommitSig::BlockIdFlagNil {
                    validator_address,
                    timestamp,
                    signature,
                } => pb::CommitSig {
                    block_id_flag: BlockIdFlag::Nil as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagCommit {
                    validator_address,
                    timestamp,
                    signature,
                } => pb::CommitSig {
                    block_id_flag: BlockIdFlag::Commit as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagAggCommit {
                    validator_address,
                    timestamp,
                    signature,
                } => pb::CommitSig {
                    block_id_flag: BlockIdFlag::AggCommit as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagAggCommitAbsent {
                    validator_address,
                    timestamp,
                    signature,
                } => pb::CommitSig {
                    block_id_flag: BlockIdFlag::AggCommitAbsent as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagAggNil {
                    validator_address,
                    timestamp,
                    signature,
                } => pb::CommitSig {
                    block_id_flag: BlockIdFlag::AggNil as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagAggNilAbsent {
                    validator_address,
                    timestamp,
                    signature,
                } => pb::CommitSig {
                    block_id_flag: BlockIdFlag::AggNilAbsent as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
            }
        }
    }

    #[test]
    #[cfg(test)]
    fn test_block_id_flag_absent_serialization() {
        let absent = CommitSig::BlockIdFlagAbsent;
        let raw_absent = pb::CommitSig::from(absent);
        let expected = r#"{"block_id_flag":1,"validator_address":"","timestamp":"0001-01-01T00:00:00Z","signature":""}"#;
        let output = serde_json::to_string(&raw_absent).unwrap();
        assert_eq!(expected, &output);
    }

    #[test]
    #[cfg(test)]
    fn test_block_id_flag_absent_deserialization() {
        let json = r#"{"block_id_flag":1,"validator_address":"","timestamp":"0001-01-01T00:00:00Z","signature":""}"#;
        let raw_commit_sg = serde_json::from_str::<pb::CommitSig>(json).unwrap();
        let commit_sig = CommitSig::try_from(raw_commit_sg).unwrap();
        assert_eq!(commit_sig, CommitSig::BlockIdFlagAbsent);
    }
}

mod v1beta1 {
    use super::{CommitSig, ZERO_TIMESTAMP};
    use crate::{error::Error, prelude::*, Signature};
    use cometbft_proto::types::v1beta1::{self as pb, BlockIdFlag};

    impl TryFrom<pb::CommitSig> for CommitSig {
        type Error = Error;

        fn try_from(value: pb::CommitSig) -> Result<Self, Self::Error> {
            if value.block_id_flag == BlockIdFlag::Absent as i32 {
                if value.timestamp.is_some() {
                    let timestamp = value.timestamp.unwrap();
                    // 0001-01-01T00:00:00.000Z translates to EPOCH-62135596800 seconds
                    if timestamp.nanos != 0 || timestamp.seconds != -62135596800 {
                        return Err(Error::invalid_timestamp(
                            "absent commitsig has non-zero timestamp".to_string(),
                        ));
                    }
                }

                if !value.signature.is_empty() {
                    return Err(Error::invalid_signature(
                        "expected empty signature for absent commitsig".to_string(),
                    ));
                }

                return Ok(CommitSig::BlockIdFlagAbsent);
            }

            if value.validator_address.is_empty() {
                return Err(Error::invalid_validator_address());
            }

            let timestamp = value
                .timestamp
                .ok_or_else(Error::missing_timestamp)?
                .try_into()?;

            let signature = if !value.signature.is_empty() {
                Some(Signature::new(value.signature)?)
            } else {
                None
            };

            let signature = signature.flatten();

            let validator_address = value.validator_address.try_into()?;

            match value.block_id_flag {
                x if x == cometbft_proto::types::v1::BlockIdFlag::Commit as i32 => {
                    if signature.is_none() {
                        return Err(Error::invalid_signature(
                            "expected non-empty signature for regular commitsig".to_string(),
                        ));
                    }
                    Ok(CommitSig::BlockIdFlagCommit {
                        validator_address,
                        timestamp,
                        signature,
                    })
                },
                x if x == cometbft_proto::types::v1::BlockIdFlag::Nil as i32 => {
                    if signature.is_none() {
                        return Err(Error::invalid_signature(
                            "nil commitsig has no signature".to_string(),
                        ));
                    }
                    Ok(CommitSig::BlockIdFlagNil {
                        validator_address,
                        timestamp,
                        signature,
                    })
                },
                x if x == cometbft_proto::types::v1::BlockIdFlag::AggCommit as i32 => {
                    Ok(CommitSig::BlockIdFlagAggCommit {
                        validator_address,
                        timestamp,
                        signature,
                    })
                },
                x if x == cometbft_proto::types::v1::BlockIdFlag::AggCommitAbsent as i32 => {
                    Ok(CommitSig::BlockIdFlagAggCommitAbsent {
                        validator_address,
                        timestamp,
                        signature,
                    })
                },
                x if x == cometbft_proto::types::v1::BlockIdFlag::AggNil as i32 => {
                    Ok(CommitSig::BlockIdFlagAggNil {
                        validator_address,
                        timestamp,
                        signature,
                    })
                },
                x if x == cometbft_proto::types::v1::BlockIdFlag::AggNilAbsent as i32 => {
                    Ok(CommitSig::BlockIdFlagAggNilAbsent {
                        validator_address,
                        timestamp,
                        signature,
                    })
                },
                _ => Err(Error::block_id_flag()),
            }
        }
    }

    impl From<CommitSig> for pb::CommitSig {
        fn from(commit: CommitSig) -> pb::CommitSig {
            match commit {
                CommitSig::BlockIdFlagAbsent => pb::CommitSig {
                    block_id_flag: BlockIdFlag::Absent as i32,
                    validator_address: Vec::new(),
                    timestamp: Some(ZERO_TIMESTAMP),
                    signature: Vec::new(),
                },
                CommitSig::BlockIdFlagNil {
                    validator_address,
                    timestamp,
                    signature,
                } => pb::CommitSig {
                    block_id_flag: BlockIdFlag::Nil as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagCommit {
                    validator_address,
                    timestamp,
                    signature,
                } => pb::CommitSig {
                    block_id_flag: BlockIdFlag::Commit as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagAggCommit {
                    validator_address,
                    timestamp,
                    signature,
                } => pb::CommitSig {
                    block_id_flag: cometbft_proto::types::v1::BlockIdFlag::AggCommit as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagAggCommitAbsent {
                    validator_address,
                    timestamp,
                    signature,
                } => pb::CommitSig {
                    block_id_flag: cometbft_proto::types::v1::BlockIdFlag::AggCommitAbsent as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagAggNil {
                    validator_address,
                    timestamp,
                    signature,
                } => pb::CommitSig {
                    block_id_flag: cometbft_proto::types::v1::BlockIdFlag::AggNil as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
                CommitSig::BlockIdFlagAggNilAbsent {
                    validator_address,
                    timestamp,
                    signature,
                } => pb::CommitSig {
                    block_id_flag: cometbft_proto::types::v1::BlockIdFlag::AggNilAbsent as i32,
                    validator_address: validator_address.into(),
                    timestamp: Some(timestamp.into()),
                    signature: signature.map(|s| s.into_bytes()).unwrap_or_default(),
                },
            }
        }
    }

    #[test]
    #[cfg(test)]
    fn test_block_id_flag_absent_serialization() {
        let absent = CommitSig::BlockIdFlagAbsent;
        let raw_absent = pb::CommitSig::from(absent);
        let expected = r#"{"block_id_flag":1,"validator_address":"","timestamp":"0001-01-01T00:00:00Z","signature":""}"#;
        let output = serde_json::to_string(&raw_absent).unwrap();
        assert_eq!(expected, &output);
    }

    #[test]
    #[cfg(test)]
    fn test_block_id_flag_absent_deserialization() {
        let json = r#"{"block_id_flag":1,"validator_address":"","timestamp":"0001-01-01T00:00:00Z","signature":""}"#;
        let raw_commit_sg = serde_json::from_str::<pb::CommitSig>(json).unwrap();
        let commit_sig = CommitSig::try_from(raw_commit_sg).unwrap();
        assert_eq!(commit_sig, CommitSig::BlockIdFlagAbsent);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::Commit;
    use std::dbg;

    #[test]
    fn test_parse_berachain_agg_commit() {
        let berachain_commit_json = r#"{
            "height": "14735438",
            "round": 0,
            "block_id": {
                "hash": "E1FFFD6A2DB6812B31B5AEA86ABC556F815D0A76A6268DC49F0B812AA2818693",
                "parts": {
                    "total": 1,
                    "hash": "8E512735E7E36174F840DBFE2F6A7D895BFE2EB0BA16E5FCE0AFE7CDA20C4D2F"
                }
            },
            "signatures": [
                {
                    "block_id_flag": 4,
                    "validator_address": "0EB600A5EB0DCCD405B3C71953C727975E39EDE4",
                    "timestamp": "2025-01-01T00:00:00Z",
                    "signature": "oAo+wJBh8bu4WBf2uVOtqwxH2bm5Fef2drAqoE/1YRb+rA1JhrhakJnSKJEEoCEIFJaS3qXcbQqPrF8nnz9Ayb0nTy1x6Ely73irtT+kA0zM6vnSmZyyt2siCakSY8OT"
                },
                {
                    "block_id_flag": 2,
                    "validator_address": "17348776DE5BC1F4BE6F1DB84042DAC57D71C890",
                    "timestamp": "2023-01-01T00:00:00Z",
                    "signature": "oAo+wJBh8bu4WBf2uVOtqwxH2bm5Fef2drAqoE/1YRb+rA1JhrhakJnSKJEEoCEIFJaS3qXcbQqPrF8nnz9Ayb0nTy1x6Ely73irtT+kA0zM6vnSmZyyt2siCakSY8OT"
                },
                {
                    "block_id_flag": 5,
                    "validator_address": "27219ACFC8E974C0DB5E137CC42E8427553802FC",
                    "timestamp": "2025-01-01T00:00:00Z",
                    "signature": null
                }
            ]
        }"#;

        let commit: Commit = serde_json::from_str(berachain_commit_json)
            .expect("Failed to deserialize Berachain Commit");

        assert_eq!(commit.signatures.len(), 3);
        dbg!(commit.signatures.clone());

        match &commit.signatures[0] {
            CommitSig::BlockIdFlagAggCommit {
                validator_address,
                signature,
                ..
            } => {
                let addr_hex = validator_address.to_string();
                assert_eq!(
                    addr_hex.to_uppercase(),
                    "0EB600A5EB0DCCD405B3C71953C727975E39EDE4"
                );
                assert_eq!(signature.as_ref().unwrap().as_bytes().len(), 96);
            },
            _ => panic!("First signature should be AggCommit (Flag 4)"),
        }

        match &commit.signatures[1] {
            CommitSig::BlockIdFlagCommit { .. } => {},
            _ => panic!("Second signature should be Standard Commit (Flag 2)"),
        }

        match &commit.signatures[2] {
            CommitSig::BlockIdFlagAggCommitAbsent {
                validator_address, ..
            } => {
                let addr_hex = validator_address.to_string();
                assert_eq!(
                    addr_hex.to_uppercase(),
                    "27219ACFC8E974C0DB5E137CC42E8427553802FC"
                );
            },
            _ => panic!("Third signature should be AggCommitAbsent (Flag 5)"),
        }
    }
}
