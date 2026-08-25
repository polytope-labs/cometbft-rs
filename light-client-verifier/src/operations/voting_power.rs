//! Provides an interface and default implementation for the `VotingPower` operation

use alloc::collections::BTreeSet;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::{convert::TryFrom, fmt, marker::PhantomData};

use cometbft::{
    account,
    block::CommitSig,
    chain,
    crypto::signature,
    trust_threshold::TrustThreshold as _,
    validator,
    vote::{SignedVote, ValidatorIndex, Vote},
    PublicKey, Signature,
};
use prost::Message;
use serde::{Deserialize, Serialize};

// --- Protobuf Definitions for Berachain BLS Verification (No Timestamp) ---
// These structs match the Berachain spec where the timestamp field is removed
// from the canonical vote. Using a separate struct avoids any prost encoding
// issues with Option<Time> where None might add an extra byte.

/// Domain separation tag beacon-kit signs its precommits under.
const BLS_DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

/// Canonical vote without timestamp field for BLS aggregated signature verification.
/// Used by Berachain's beacon-kit.
#[derive(Clone, PartialEq, ::prost::Message)]
struct CanonicalVoteNoTimestamp {
    /// Vote type (2 for Precommit)
    #[prost(int32, tag = "1")]
    pub r#type: i32,

    /// Block height
    #[prost(sfixed64, tag = "2")]
    pub height: i64,

    /// Voting round
    #[prost(sfixed64, tag = "3")]
    pub round: i64,

    /// Block ID being voted on
    #[prost(message, optional, tag = "4")]
    pub block_id: Option<CanonicalBlockId>,

    // Field 5 (Timestamp) is intentionally omitted for Berachain
    /// Chain ID
    #[prost(string, tag = "6")]
    pub chain_id: alloc::string::String,
}

/// Canonical block ID for BLS verification.
#[derive(Clone, PartialEq, ::prost::Message)]
struct CanonicalBlockId {
    /// Block hash
    #[prost(bytes = "vec", tag = "1")]
    pub hash: Vec<u8>,

    /// Part set header
    #[prost(message, optional, tag = "2")]
    pub part_set_header: Option<CanonicalPartSetHeader>,
}

/// Canonical part set header for BLS verification.
#[derive(Clone, PartialEq, ::prost::Message)]
struct CanonicalPartSetHeader {
    /// Total parts
    #[prost(uint32, tag = "1")]
    pub total: u32,

    /// Part set hash
    #[prost(bytes = "vec", tag = "2")]
    pub hash: Vec<u8>,
}

use crate::{
    errors::VerificationError,
    prelude::*,
    types::{Commit, SignedHeader, TrustThreshold, ValidatorSet},
};

/// Tally for the voting power computed by the `VotingPowerCalculator`
#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize, Eq)]
pub struct VotingPowerTally {
    /// Total voting power
    pub total: u64,
    /// Tallied voting power
    pub tallied: u64,
    /// Trust threshold for voting power
    pub trust_threshold: TrustThreshold,
}

impl VotingPowerTally {
    fn new(total: u64, trust_threshold: TrustThreshold) -> Self {
        Self {
            total,
            tallied: 0,
            trust_threshold,
        }
    }

    /// Adds given amount of power to tallied voting power amount.
    fn tally(&mut self, power: u64) {
        self.tallied += power;
        debug_assert!(self.tallied <= self.total);
    }

    /// Checks whether tallied amount meets trust threshold.
    fn check(&self) -> Result<(), Self> {
        if self
            .trust_threshold
            .is_enough_power(self.tallied, self.total)
        {
            Ok(())
        } else {
            Err(*self)
        }
    }
}

impl fmt::Display for VotingPowerTally {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "VotingPower(total={} tallied={} trust_threshold={})",
            self.total, self.tallied, self.trust_threshold
        )
    }
}

/// Computes the voting power in a commit against a validator set.
///
/// This trait provides default implementation of some helper functions.
pub trait VotingPowerCalculator: Send + Sync {
    /// Compute the total voting power in a validator set
    fn total_power_of(&self, validator_set: &ValidatorSet) -> u64 {
        validator_set
            .validators()
            .iter()
            .fold(0u64, |total, val_info| total + val_info.power.value())
    }

    /// Check that there is enough trust between an untrusted header and given
    /// trusted and untrusted validator sets.
    ///
    /// First of all, checks that enough validators from the
    /// `trusted_validators` set signed the `untrusted_header` to reach given
    /// `trust_threshold`.
    ///
    /// Second of all, checks that enough validators from the
    /// `untrusted_validators` set signed the `untrusted_header` to reach
    /// a trust threshold of ⅔.
    ///
    /// If both of those conditions aren’t met, it’s unspecified which error is
    /// returned.
    fn check_enough_trust_and_signers(
        &self,
        untrusted_header: &SignedHeader,
        trusted_validators: &ValidatorSet,
        trust_threshold: TrustThreshold,
        untrusted_validators: &ValidatorSet,
    ) -> Result<(), VerificationError> {
        let (trusted_power, untrusted_power) = self.voting_power_in_sets(
            untrusted_header,
            (trusted_validators, trust_threshold),
            (untrusted_validators, TrustThreshold::TWO_THIRDS),
        )?;
        trusted_power
            .check()
            .map_err(VerificationError::not_enough_trust)?;
        untrusted_power
            .check()
            .map_err(VerificationError::insufficient_signers_overlap)?;
        Ok(())
    }

    /// Check if there is 2/3rd overlap between an untrusted header and untrusted validator set
    fn check_signers_overlap(
        &self,
        untrusted_header: &SignedHeader,
        untrusted_validators: &ValidatorSet,
    ) -> Result<(), VerificationError> {
        let trust_threshold = TrustThreshold::TWO_THIRDS;
        self.voting_power_in(untrusted_header, untrusted_validators, trust_threshold)?
            .check()
            .map_err(VerificationError::insufficient_signers_overlap)
    }

    /// Compute the voting power in a header and its commit against a validator
    /// set.
    ///
    /// Note that the returned tally may be lower than actual tally so long as
    /// it meets the `trust_threshold`.  Furthermore, the method isn’t
    /// guaranteed to verify all the signatures present in the signed header.
    /// If there are invalid signatures, the method may or may not return an
    /// error depending on which validators those signatures correspond to.
    ///
    /// If you have two separate sets of validators and need to check voting
    /// power for both of them, prefer [`Self::voting_power_in_sets`] method.
    fn voting_power_in(
        &self,
        signed_header: &SignedHeader,
        validator_set: &ValidatorSet,
        trust_threshold: TrustThreshold,
    ) -> Result<VotingPowerTally, VerificationError>;

    /// Compute the voting power in a header and its commit against two separate
    /// validator sets.
    ///
    /// This is equivalent to calling [`Self::voting_power_in`] on each set
    /// separately but may be more optimised.  Implementators are encouraged to
    /// write a properly optimised method which avoids checking the same
    /// signature twice but for a simple unoptimised implementation the
    /// following works:
    ///
    /// ```ignore
    ///     fn voting_power_in_sets(
    ///         &self,
    ///         signed_header: &SignedHeader,
    ///         first_set: (&ValidatorSet, TrustThreshold),
    ///         second_set: (&ValidatorSet, TrustThreshold),
    ///     ) -> Result<(VotingPowerTally, VotingPowerTally), VerificationError> {
    ///         let first_tally = self.voting_power_in(
    ///             signed_header,
    ///             first_set.0,
    ///             first_set.1,
    ///         )?;
    ///         let second_tally = self.voting_power_in(
    ///             signed_header,
    ///             first_set.0,
    ///             first_set.1,
    ///         )?;
    ///         Ok((first_tally, second_tally))
    ///     }
    ///
    /// ```
    fn voting_power_in_sets(
        &self,
        signed_header: &SignedHeader,
        first_set: (&ValidatorSet, TrustThreshold),
        second_set: (&ValidatorSet, TrustThreshold),
    ) -> Result<(VotingPowerTally, VotingPowerTally), VerificationError>;
}

/// A signed non-nil vote.
struct NonAbsentCommitVote {
    signed_vote: SignedVote,
    /// Flag indicating whether the signature has already been verified.
    verified: bool,
}

impl NonAbsentCommitVote {
    /// Returns a signed non-nil vote for given commit.
    ///
    /// If the CommitSig represents a missing vote or a vote for nil returns
    /// `None`.  Otherwise, if the vote is missing a signature returns
    /// `Some(Err)`.  Otherwise, returns a `SignedVote` corresponding to given
    /// `CommitSig`.
    pub fn new(
        commit_sig: &CommitSig,
        validator_index: ValidatorIndex,
        commit: &Commit,
        chain_id: &chain::Id,
    ) -> Option<Result<Self, VerificationError>> {
        let (validator_address, timestamp, signature) = match commit_sig {
            CommitSig::BlockIdFlagAbsent => return None,
            CommitSig::BlockIdFlagCommit {
                validator_address,
                timestamp,
                signature,
            } => (*validator_address, *timestamp, signature),
            CommitSig::BlockIdFlagNil { .. } => return None,
            CommitSig::BlockIdFlagAggCommit {
                validator_address,
                timestamp,
                signature,
            } => (*validator_address, *timestamp, signature),
            CommitSig::BlockIdFlagAggNil {
                validator_address,
                timestamp,
                signature,
            } => (*validator_address, *timestamp, signature),
            CommitSig::BlockIdFlagAggCommitAbsent { .. }
            | CommitSig::BlockIdFlagAggNilAbsent { .. } => return None,
        };

        let vote = Vote {
            vote_type: cometbft::vote::Type::Precommit,
            height: commit.height,
            round: commit.round,
            block_id: Some(commit.block_id),
            timestamp: Some(timestamp),
            validator_address,
            validator_index,
            signature: signature.clone(),
            extension: Default::default(),
            extension_signature: None,
        };
        Some(
            SignedVote::from_vote(vote, chain_id.clone())
                .ok_or_else(VerificationError::missing_signature)
                .map(|signed_vote| Self {
                    signed_vote,
                    verified: false,
                }),
        )
    }

    /// Returns address of the validator making the vote.
    pub fn validator_id(&self) -> account::Id {
        self.signed_vote.validator_id()
    }
}

/// Collection of non-absent commit votes.
///
/// This enum distinguishes between standard CometBFT verification (individual signatures)
/// and BLS aggregated verification (used by Berachain's beacon-kit).
enum NonAbsentCommitVotes {
    /// Standard CometBFT: each validator has an individual signature verified separately.
    Standard {
        /// Votes sorted by validator address.
        votes: Vec<NonAbsentCommitVote>,
        /// Internal buffer for storing sign_bytes.
        sign_bytes: Vec<u8>,
    },
    /// BLS aggregated: multiple validators' signatures are aggregated into one.
    /// Used by Berachain's beacon-kit.
    BlsAggregated {
        /// The aggregated signature for block commits (mandatory)
        commit_signature: Signature,
        /// Addresses of validators who participated in the commit aggregation
        commit_addresses: Vec<account::Id>,
        /// The aggregated signature for nil votes (optional)
        nil_signature: Option<Signature>,
        /// Addresses of validators who participated in the nil aggregation
        nil_addresses: Vec<account::Id>,
        /// Sign bytes without timestamp (for BLS aggregated verification)
        sign_bytes: Vec<u8>,
        /// Whether the aggregated signatures have been verified
        verified: bool,
    },
}

impl NonAbsentCommitVotes {
    /// Initial capacity of the `sign_bytes` buffer.
    ///
    /// The buffer will be resized if it happens to be too small so this value
    /// isn't critical for correctness.  It's a matter of performance to avoid
    /// reallocations.
    ///
    /// Note: As of protocol 0.38, maximum length of the sign bytes is `115 + (N > 13) + N`
    /// where `N` is the length of the chain id.
    /// Chain id can be at most 50 bytes (see [`tendermint::chain::id::MAX_LEN`])
    /// thus the largest buffer we'll ever need is 166 bytes long.
    const SIGN_BYTES_INITIAL_CAPACITY: usize = 166;

    pub fn new(signed_header: &SignedHeader) -> Result<Self, VerificationError> {
        match Self::try_new_bls_aggregated(signed_header)? {
            Some(bls_votes) => Ok(bls_votes),
            None => Self::new_standard(signed_header),
        }
    }

    /// Try to create a BLS aggregated variant for a Berachain/beacon-kit commit.
    ///
    /// Beacon-kit puts the whole aggregate on a single `AggCommit` slot and marks every other
    /// participant `AggCommitAbsent`, so both flags name validators that signed and both belong
    /// in the aggregate. A validator that really did not vote is left as a plain `Absent` slot.
    ///
    /// Returns `Ok(None)` when the commit carries no aggregated slots, so the caller can fall
    /// back to standard CometBFT verification. Once a commit is known to be aggregated it is
    /// never handed to the standard path, whose per-validator verifier cannot read BLS keys.
    fn try_new_bls_aggregated(
        signed_header: &SignedHeader,
    ) -> Result<Option<Self>, VerificationError> {
        if !signed_header
            .commit
            .signatures
            .iter()
            .any(CommitSig::is_aggregated)
        {
            return Ok(None);
        }

        let mut commit_addresses = Vec::new();
        let mut nil_addresses = Vec::new();
        let mut commit_signature: Option<Signature> = None;
        let mut nil_signature: Option<Signature> = None;

        for sig in &signed_header.commit.signatures {
            match sig {
                CommitSig::BlockIdFlagAggCommit {
                    validator_address,
                    signature,
                    ..
                } => {
                    commit_addresses.push(*validator_address);
                    // The first non-None signature is the aggregated commit signature
                    if commit_signature.is_none() {
                        commit_signature = signature.clone();
                    }
                },
                CommitSig::BlockIdFlagAggCommitAbsent {
                    validator_address, ..
                } => {
                    commit_addresses.push(*validator_address);
                },
                CommitSig::BlockIdFlagAggNil {
                    validator_address,
                    signature,
                    ..
                } => {
                    nil_addresses.push(*validator_address);
                    // The first non-None signature is the aggregated nil signature
                    if nil_signature.is_none() {
                        nil_signature = signature.clone();
                    }
                },
                CommitSig::BlockIdFlagAggNilAbsent {
                    validator_address, ..
                } => {
                    nil_addresses.push(*validator_address);
                },
                _ => {},
            }
        }

        // Only the commit arm carries the aggregate, so this also covers an empty address list.
        let Some(commit_signature) = commit_signature else {
            return Err(VerificationError::missing_signature());
        };

        // A validator owns one slot in the commit. Repeated entries would otherwise have
        // their power counted once per entry, letting a single key stand in for a quorum.
        let mut seen = BTreeSet::new();
        if let Some(address) = commit_addresses
            .iter()
            .chain(nil_addresses.iter())
            .find(|address| !seen.insert(**address))
        {
            return Err(VerificationError::duplicate_validator(*address));
        }

        // Construct sign_bytes without timestamp for BLS aggregated verification
        let sign_bytes = Self::construct_sign_bytes_no_timestamp(signed_header);

        Ok(Some(NonAbsentCommitVotes::BlsAggregated {
            commit_signature,
            commit_addresses,
            nil_signature,
            nil_addresses,
            sign_bytes,
            verified: false,
        }))
    }

    /// Create standard CometBFT verification variant.
    fn new_standard(signed_header: &SignedHeader) -> Result<Self, VerificationError> {
        let mut votes = signed_header
            .commit
            .signatures
            .iter()
            .enumerate()
            .flat_map(|(idx, signature)| {
                // We never have more than 2³¹ signatures so this always
                // succeeds.
                let idx = ValidatorIndex::try_from(idx).unwrap();
                NonAbsentCommitVote::new(
                    signature,
                    idx,
                    &signed_header.commit,
                    &signed_header.header.chain_id,
                )
            })
            .collect::<Result<Vec<_>, VerificationError>>()?;
        votes.sort_unstable_by_key(NonAbsentCommitVote::validator_id);

        // Check if there are duplicate signatures.  If at least one duplicate
        // is found, report it as an error.
        let duplicate = votes
            .windows(2)
            .find(|pair| pair[0].validator_id() == pair[1].validator_id());
        if let Some(pair) = duplicate {
            return Err(VerificationError::duplicate_validator(
                pair[0].validator_id(),
            ));
        }

        Ok(NonAbsentCommitVotes::Standard {
            votes,
            sign_bytes: Vec::with_capacity(Self::SIGN_BYTES_INITIAL_CAPACITY),
        })
    }

    /// Construct canonical vote sign bytes WITHOUT timestamp (for BLS aggregated signatures).
    ///
    /// Uses `CanonicalVoteNoTimestamp` which has no timestamp field at all,
    /// matching the Berachain spec and avoiding potential prost encoding issues
    /// with `Option<Time>` where `None` might add an extra byte.
    fn construct_sign_bytes_no_timestamp(signed_header: &SignedHeader) -> Vec<u8> {
        let commit = &signed_header.commit;
        let header = &signed_header.header;

        let part_set_header = CanonicalPartSetHeader {
            total: commit.block_id.part_set_header.total,
            hash: commit.block_id.part_set_header.hash.as_bytes().to_vec(),
        };

        let block_id = CanonicalBlockId {
            hash: commit.block_id.hash.as_bytes().to_vec(),
            part_set_header: Some(part_set_header),
        };

        // Create canonical vote without timestamp field (Berachain spec)
        let vote = CanonicalVoteNoTimestamp {
            r#type: 2, // SIGNED_MSG_TYPE_PRECOMMIT
            height: commit.height.value() as i64,
            round: commit.round.value() as i64,
            block_id: Some(block_id),
            chain_id: header.chain_id.as_str().to_string(),
        };

        // Encode to length-delimited protobuf (CometBFT sign bytes format)
        // This prefixes the message with its length as a varint
        let mut buf = Vec::new();
        vote.encode_length_delimited(&mut buf)
            .expect("encoding canonical vote should never fail");
        buf
    }

    /// Returns true if this is a beacon-kit (Berachain) signed header with BLS aggregated signatures.
    pub fn is_beacon_kit(&self) -> bool {
        matches!(self, NonAbsentCommitVotes::BlsAggregated { .. })
    }

    /// Looks up a vote cast by given validator (standard CometBFT verification).
    ///
    /// If the validator didn't cast a vote or voted for `nil`, returns `Ok(None)`. Otherwise, if
    /// the vote had valid signature, returns `Ok(Some(idx))` where idx is the validator's index.
    /// If the vote had invalid signature, returns `Err`.
    ///
    /// Note: This method is for standard CometBFT verification only. For beacon-kit,
    /// use the beacon-kit verification algorithm via `verify_aggregated_bls_if_present`.
    pub fn has_voted<V: signature::Verifier>(
        &mut self,
        validator: &validator::Info,
    ) -> Result<Option<usize>, VerificationError> {
        match self {
            NonAbsentCommitVotes::BlsAggregated { .. } => {
                // Beacon-kit uses a different verification path
                Ok(None)
            },
            NonAbsentCommitVotes::Standard { votes, sign_bytes } => {
                // Standard individual signature verification
                if let Ok(idx) = votes
                    .binary_search_by_key(&validator.address, NonAbsentCommitVote::validator_id)
                {
                    let vote = &mut votes[idx];

                    if !vote.verified {
                        sign_bytes.clear();
                        vote.signed_vote
                            .sign_bytes_into(sign_bytes)
                            .expect("buffer is resized if needed and encoding never fails");

                        let sign_bytes_slice = sign_bytes.as_slice();
                        validator
                            .verify_signature::<V>(sign_bytes_slice, vote.signed_vote.signature())
                            .map_err(|_| {
                                VerificationError::invalid_signature(
                                    vote.signed_vote.signature().as_bytes().to_vec(),
                                    Box::new(validator.clone()),
                                    sign_bytes_slice.to_vec(),
                                )
                            })?;
                        vote.verified = true;
                    }
                    Ok(Some(idx))
                } else {
                    Ok(None)
                }
            },
        }
    }

    /// Verify the aggregated BLS signatures of a beacon-kit commit.
    ///
    /// The commit aggregate is mandatory and covers exactly the validators that voted for the
    /// block. A nil aggregate is optional, and is verified when present even though nil voters
    /// carry no power towards the block.
    pub fn verify_aggregated_bls_if_present(
        &mut self,
        validator_set: &ValidatorSet,
    ) -> Result<(), VerificationError> {
        let NonAbsentCommitVotes::BlsAggregated {
            commit_signature,
            commit_addresses,
            nil_signature,
            nil_addresses,
            sign_bytes,
            verified,
        } = self
        else {
            return Ok(());
        };

        if *verified {
            return Ok(());
        }

        verify_aggregate(
            validator_set,
            commit_addresses,
            commit_signature,
            sign_bytes,
        )?;

        if let Some(nil_signature) = nil_signature {
            verify_aggregate(validator_set, nil_addresses, nil_signature, sign_bytes)?;
        }

        *verified = true;
        Ok(())
    }
}

/// Check one BLS aggregate against the keys of the validators it claims to cover.
///
/// Every address has to resolve to a usable BLS key. Skipping a validator whose key is missing
/// or fails to parse would leave it credited with power it never signed for.
fn verify_aggregate(
    validator_set: &ValidatorSet,
    addresses: &[account::Id],
    signature: &Signature,
    sign_bytes: &[u8],
) -> Result<(), VerificationError> {
    use blst::min_pk::{PublicKey as BlsPublicKey, Signature as BlsSignature};

    let validators = addresses
        .iter()
        .map(|address| {
            validator_set
                .validator(*address)
                .ok_or_else(|| VerificationError::faulty_signer(*address, validator_set.clone()))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let Some(signer) = validators.first() else {
        return Err(VerificationError::missing_signature());
    };

    let invalid = || {
        VerificationError::invalid_signature(
            signature.as_bytes().to_vec(),
            Box::new(signer.clone()),
            sign_bytes.to_vec(),
        )
    };

    let keys = validators
        .iter()
        .map(|validator| match &validator.pub_key {
            PublicKey::Bls12_381(bytes) => BlsPublicKey::key_validate(bytes).map_err(|_| invalid()),
            _ => Err(invalid()),
        })
        .collect::<Result<Vec<_>, _>>()?;

    let aggregate = BlsSignature::from_bytes(signature.as_bytes()).map_err(|_| invalid())?;
    let key_refs = keys.iter().collect::<Vec<_>>();

    match aggregate.fast_aggregate_verify(true, sign_bytes, BLS_DST, &key_refs) {
        blst::BLST_ERROR::BLST_SUCCESS => Ok(()),
        _ => Err(invalid()),
    }
}

/// Default implementation of a `VotingPowerCalculator`, parameterized with
/// the signature verification trait.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProvidedVotingPowerCalculator<V> {
    _verifier: PhantomData<V>,
}

// Safety: the only member is phantom data
unsafe impl<V> Send for ProvidedVotingPowerCalculator<V> {}
unsafe impl<V> Sync for ProvidedVotingPowerCalculator<V> {}

impl<V> Default for ProvidedVotingPowerCalculator<V> {
    fn default() -> Self {
        Self {
            _verifier: PhantomData,
        }
    }
}

/// Dictionary of validators sorted by address.
///
/// The map stores reference to [`validator::Info`] object (typically held by
/// a `ValidatorSet`) and a boolean flag indicating whether the validator has
/// already been seen.  The validators are sorted by their address such that
/// lookup by address is a logarithmic operation.
struct ValidatorMap<'a> {
    validators: Vec<(&'a validator::Info, bool)>,
}

/// Error during validator lookup.
enum LookupError {
    NotFound,
    AlreadySeen,
}

impl<'a> ValidatorMap<'a> {
    /// Constructs a new map from given list of validators.
    ///
    /// Sorts the validators by address which makes the operation’s time
    /// complexity `O(N lng N)`.
    ///
    /// Produces unspecified result if two objects with the same address are
    /// found.  Unspecified in that it’s not guaranteed which entry will be
    /// subsequently returned by [`Self::find_mut`] however it will always be
    /// consistently the same entry.
    pub fn new(validators: &'a [validator::Info]) -> Self {
        let mut validators = validators.iter().map(|v| (v, false)).collect::<Vec<_>>();
        validators.sort_unstable_by_key(|item| &item.0.address);
        Self { validators }
    }

    /// Finds entry for validator with given address; returns error if validator
    /// has been returned already by previous call to `find`.
    ///
    /// Uses binary search resulting in logarithmic lookup time.
    pub fn find(&mut self, address: &account::Id) -> Result<&'a validator::Info, LookupError> {
        let index = self
            .validators
            .binary_search_by_key(&address, |item| &item.0.address)
            .map_err(|_| LookupError::NotFound)?;

        let (validator, seen) = &mut self.validators[index];
        if *seen {
            Err(LookupError::AlreadySeen)
        } else {
            *seen = true;
            Ok(validator)
        }
    }
}

/// Default implementation of a `VotingPowerCalculator`.
#[cfg(feature = "rust-crypto")]
pub type ProdVotingPowerCalculator =
    ProvidedVotingPowerCalculator<cometbft::crypto::default::signature::Verifier>;

impl<V: signature::Verifier> VotingPowerCalculator for ProvidedVotingPowerCalculator<V> {
    fn voting_power_in(
        &self,
        signed_header: &SignedHeader,
        validator_set: &ValidatorSet,
        trust_threshold: TrustThreshold,
    ) -> Result<VotingPowerTally, VerificationError> {
        let mut votes = NonAbsentCommitVotes::new(signed_header)?;
        voting_power_in_impl::<V>(
            &mut votes,
            validator_set,
            trust_threshold,
            self.total_power_of(validator_set),
        )
    }

    fn voting_power_in_sets(
        &self,
        signed_header: &SignedHeader,
        first_set: (&ValidatorSet, TrustThreshold),
        second_set: (&ValidatorSet, TrustThreshold),
    ) -> Result<(VotingPowerTally, VotingPowerTally), VerificationError> {
        let mut votes = NonAbsentCommitVotes::new(signed_header)?;
        let first_tally = voting_power_in_impl::<V>(
            &mut votes,
            first_set.0,
            first_set.1,
            self.total_power_of(first_set.0),
        )?;
        let second_tally = voting_power_in_impl::<V>(
            &mut votes,
            second_set.0,
            second_set.1,
            self.total_power_of(second_set.0),
        )?;
        Ok((first_tally, second_tally))
    }
}

fn voting_power_in_impl<V: signature::Verifier>(
    votes: &mut NonAbsentCommitVotes,
    validator_set: &ValidatorSet,
    trust_threshold: TrustThreshold,
    total_voting_power: u64,
) -> Result<VotingPowerTally, VerificationError> {
    // Check if we're dealing with beacon-kit (BLS aggregated signatures)
    if votes.is_beacon_kit() {
        return voting_power_in_beacon_kit(
            votes,
            validator_set,
            trust_threshold,
            total_voting_power,
        );
    }

    // Standard CometBFT verification
    voting_power_in_standard::<V>(votes, validator_set, trust_threshold, total_voting_power)
}

/// Standard CometBFT voting power verification with individual signatures.
fn voting_power_in_standard<V: signature::Verifier>(
    votes: &mut NonAbsentCommitVotes,
    validator_set: &ValidatorSet,
    trust_threshold: TrustThreshold,
    total_voting_power: u64,
) -> Result<VotingPowerTally, VerificationError> {
    let mut power = VotingPowerTally::new(total_voting_power, trust_threshold);
    let mut seen_vals = Vec::new();

    for validator in validator_set.validators() {
        if let Some(idx) = votes.has_voted::<V>(validator)? {
            // Check if this validator has already voted.
            //
            // O(n) complexity.
            if seen_vals.contains(&idx) {
                return Err(VerificationError::duplicate_validator(validator.address));
            }
            seen_vals.push(idx);

            power.tally(validator.power());

            // Break early if sufficient voting power is reached.
            if power.check().is_ok() {
                break;
            }
        }
    }
    Ok(power)
}

/// Beacon-kit (Berachain) voting power verification with BLS aggregated signatures.
fn voting_power_in_beacon_kit(
    votes: &mut NonAbsentCommitVotes,
    validator_set: &ValidatorSet,
    trust_threshold: TrustThreshold,
    total_voting_power: u64,
) -> Result<VotingPowerTally, VerificationError> {
    votes.verify_aggregated_bls_if_present(validator_set)?;

    let mut power = VotingPowerTally::new(total_voting_power, trust_threshold);

    let NonAbsentCommitVotes::BlsAggregated {
        commit_addresses, ..
    } = votes
    else {
        return Ok(power);
    };

    // Only the validators covered by the verified commit aggregate carry power. A nil vote is
    // a vote for nil rather than for this block, so it counts for nothing here. Signers the
    // set being measured does not carry are simply worth nothing to it, which is how the
    // standard path measures overlap too.
    let signed = commit_addresses
        .iter()
        .filter_map(|address| validator_set.validator(*address))
        .map(|validator| validator.power())
        .sum();

    power.tally(signed);

    Ok(power)
}

// The below unit tests replaces the static voting power test files
// see https://github.com/informalsystems/tendermint-rs/pull/383
// This is essentially to remove the heavy dependency on MBT
// TODO: We plan to add Lightweight MBT for `voting_power_in` in the near future
#[cfg(test)]
mod tests {
    use cometbft::trust_threshold::TrustThresholdFraction;
    use cometbft_testgen::{
        light_block::generate_signed_header, Commit, Generator, Header,
        LightBlock as TestgenLightBlock, ValidatorSet, Vote as TestgenVote,
    };

    use super::*;
    use crate::{errors::VerificationErrorDetail, types::LightBlock};

    const EXPECTED_RESULT: VotingPowerTally = VotingPowerTally {
        total: 100,
        tallied: 0,
        trust_threshold: TrustThresholdFraction::ONE_THIRD,
    };

    #[test]
    fn test_empty_signatures() {
        let vp_calculator = ProdVotingPowerCalculator::default();
        let trust_threshold = TrustThreshold::default();

        let mut light_block: LightBlock = TestgenLightBlock::new_default(10)
            .generate()
            .unwrap()
            .into();
        light_block.signed_header.commit.signatures = vec![];

        let result_ok = vp_calculator.voting_power_in(
            &light_block.signed_header,
            &light_block.validators,
            trust_threshold,
        );

        // ensure the result matches the expected result
        assert_eq!(result_ok.unwrap(), EXPECTED_RESULT);
    }

    #[test]
    fn test_all_signatures_absent() {
        let vp_calculator = ProdVotingPowerCalculator::default();
        let trust_threshold = TrustThreshold::default();

        let mut testgen_lb = TestgenLightBlock::new_default(10);
        let mut commit = testgen_lb.commit.clone().unwrap();
        // an empty vector of votes translates into all absent signatures
        commit.votes = Some(vec![]);
        testgen_lb.commit = Some(commit);
        let light_block: LightBlock = testgen_lb.generate().unwrap().into();

        let result_ok = vp_calculator.voting_power_in(
            &light_block.signed_header,
            &light_block.validators,
            trust_threshold,
        );

        // ensure the result matches the expected result
        assert_eq!(result_ok.unwrap(), EXPECTED_RESULT);
    }

    #[test]
    fn test_all_signatures_nil() {
        let vp_calculator = ProdVotingPowerCalculator::default();
        let trust_threshold = TrustThreshold::default();

        let validator_set = ValidatorSet::new(vec!["a", "b"]);
        let vals = validator_set.clone().validators.unwrap();
        let header = Header::new(&vals);
        let votes = vec![
            TestgenVote::new(vals[0].clone(), header.clone()).nil(true),
            TestgenVote::new(vals[1].clone(), header.clone()).nil(true),
        ];
        let commit = Commit::new_with_votes(header.clone(), 1, votes);
        let signed_header = generate_signed_header(&header, &commit).unwrap();
        let valset = validator_set.generate().unwrap();

        let result_ok = vp_calculator.voting_power_in(&signed_header, &valset, trust_threshold);

        // ensure the result matches the expected result
        assert_eq!(result_ok.unwrap(), EXPECTED_RESULT);
    }

    #[test]
    fn test_one_invalid_signature() {
        let vp_calculator = ProdVotingPowerCalculator::default();
        let trust_threshold = TrustThreshold::default();

        let mut testgen_lb = TestgenLightBlock::new_default(10);
        let mut commit = testgen_lb.commit.clone().unwrap();
        let mut votes = commit.votes.unwrap();
        let vote = votes.pop().unwrap();
        let header = vote.clone().header.unwrap().chain_id("bad-chain");
        votes.push(vote.header(header));

        commit.votes = Some(votes);
        testgen_lb.commit = Some(commit);
        let light_block: LightBlock = testgen_lb.generate().unwrap().into();

        let result_err = vp_calculator.voting_power_in(
            &light_block.signed_header,
            &light_block.validators,
            trust_threshold,
        );

        match result_err {
            Err(VerificationError(VerificationErrorDetail::InvalidSignature(_), _)) => {},
            _ => panic!("expected InvalidSignature error"),
        }
    }

    #[test]
    fn test_all_signatures_invalid() {
        let vp_calculator = ProdVotingPowerCalculator::default();
        let trust_threshold = TrustThreshold::default();

        let mut testgen_lb = TestgenLightBlock::new_default(10);
        let header = testgen_lb.header.unwrap().chain_id("bad-chain");
        testgen_lb.header = Some(header);
        let light_block: LightBlock = testgen_lb.generate().unwrap().into();

        let result_err = vp_calculator.voting_power_in(
            &light_block.signed_header,
            &light_block.validators,
            trust_threshold,
        );

        match result_err {
            Err(VerificationError(VerificationErrorDetail::InvalidSignature(_), _)) => {},
            _ => panic!("expected InvalidSignature error"),
        }
    }

    #[test]
    fn test_signatures_from_diff_valset() {
        let vp_calculator = ProdVotingPowerCalculator::default();
        let trust_threshold = TrustThreshold::default();

        let mut light_block: LightBlock = TestgenLightBlock::new_default(10)
            .generate()
            .unwrap()
            .into();
        light_block.validators = ValidatorSet::new(vec!["bad-val1", "bad-val2"])
            .generate()
            .unwrap();

        let result_ok = vp_calculator.voting_power_in(
            &light_block.signed_header,
            &light_block.validators,
            trust_threshold,
        );

        // ensure the result matches the expected result
        assert_eq!(result_ok.unwrap(), EXPECTED_RESULT);
    }

    fn bls_validator(seed: u8, power: u64) -> (blst::min_pk::SecretKey, validator::Info) {
        let secret = blst::min_pk::SecretKey::key_gen(&[seed; 32], &[]).unwrap();
        let pub_key = PublicKey::Bls12_381(secret.sk_to_pk().compress().to_vec());
        let power = cometbft::vote::Power::try_from(power).unwrap();

        (secret, validator::Info::new(pub_key, power))
    }

    fn aggregate(secrets: &[&blst::min_pk::SecretKey], sign_bytes: &[u8]) -> Signature {
        let signatures = secrets
            .iter()
            .map(|secret| secret.sign(sign_bytes, BLS_DST, &[]))
            .collect::<Vec<_>>();
        let refs = signatures.iter().collect::<Vec<_>>();
        let aggregate = blst::min_pk::AggregateSignature::aggregate(&refs, true).unwrap();

        Signature::new(aggregate.to_signature().compress().to_vec())
            .unwrap()
            .unwrap()
    }

    /// A commit shell to hang beacon-kit signature slots off. Only the block id, height, round
    /// and chain id feed the sign bytes, so the slots can be swapped freely.
    fn beacon_kit_header() -> SignedHeader {
        let light_block: LightBlock = TestgenLightBlock::new_default(10)
            .generate()
            .unwrap()
            .into();

        light_block.signed_header
    }

    fn agg_commit(
        validator: &validator::Info,
        timestamp: cometbft::Time,
        signature: Option<Signature>,
    ) -> CommitSig {
        CommitSig::BlockIdFlagAggCommit {
            validator_address: validator.address,
            timestamp,
            signature,
        }
    }

    #[test]
    fn beacon_kit_rejects_a_validator_holding_more_than_one_slot() {
        let (secret, validator) = bls_validator(1, 1);
        let (_, other) = bls_validator(2, 99);

        let mut header = beacon_kit_header();
        let sign_bytes = NonAbsentCommitVotes::construct_sign_bytes_no_timestamp(&header);
        let timestamp = header.header.time;

        // The aggregate is one signer's signature repeated, which is what
        // fast_aggregate_verify would happily accept over the duplicated key set.
        let signature = aggregate(&[&secret; 67], &sign_bytes);
        header.commit.signatures = (0..67)
            .map(|i| agg_commit(&validator, timestamp, (i == 0).then(|| signature.clone())))
            .collect();

        let validators = validator::Set::new(vec![validator, other], None);
        let tally = ProdVotingPowerCalculator::default().voting_power_in(
            &header,
            &validators,
            TrustThreshold::default(),
        );

        match tally {
            Err(VerificationError(VerificationErrorDetail::DuplicateValidator(_), _)) => {},
            other => panic!("expected DuplicateValidator, got {other:?}"),
        }
    }

    #[test]
    fn beacon_kit_counts_every_participant_in_the_aggregate() {
        let (first, first_validator) = bls_validator(1, 40);
        let (second, second_validator) = bls_validator(2, 40);
        let (_, offline) = bls_validator(3, 20);

        let mut header = beacon_kit_header();
        let sign_bytes = NonAbsentCommitVotes::construct_sign_bytes_no_timestamp(&header);
        let timestamp = header.header.time;

        // Beacon-kit hangs the whole aggregate off one slot and marks the rest of the signers
        // AggCommitAbsent, so both of these validators are covered by it. The one that truly
        // did not vote gets a plain Absent slot.
        let signature = aggregate(&[&first, &second], &sign_bytes);
        header.commit.signatures = vec![
            agg_commit(&first_validator, timestamp, Some(signature)),
            CommitSig::BlockIdFlagAggCommitAbsent {
                validator_address: second_validator.address,
                timestamp,
                signature: None,
            },
            CommitSig::BlockIdFlagAbsent,
        ];

        let validators =
            validator::Set::new(vec![first_validator, second_validator, offline], None);
        let tally = ProdVotingPowerCalculator::default()
            .voting_power_in(&header, &validators, TrustThreshold::default())
            .unwrap();

        assert_eq!(tally.tallied, 80);
        assert_eq!(tally.total, 100);
    }

    #[test]
    fn beacon_kit_does_not_credit_nil_voters() {
        // The committing validator alone stays under the threshold, so a tally that walked
        // into the nil addresses would visibly overshoot.
        let (first, first_validator) = bls_validator(1, 20);
        let (second, nil_validator) = bls_validator(2, 80);

        let mut header = beacon_kit_header();
        let sign_bytes = NonAbsentCommitVotes::construct_sign_bytes_no_timestamp(&header);
        let timestamp = header.header.time;

        header.commit.signatures = vec![
            agg_commit(
                &first_validator,
                timestamp,
                Some(aggregate(&[&first], &sign_bytes)),
            ),
            CommitSig::BlockIdFlagAggNil {
                validator_address: nil_validator.address,
                timestamp,
                signature: Some(aggregate(&[&second], &sign_bytes)),
            },
        ];

        let validators = validator::Set::new(vec![first_validator, nil_validator], None);
        let tally = ProdVotingPowerCalculator::default()
            .voting_power_in(&header, &validators, TrustThreshold::default())
            .unwrap();

        // A nil vote is a vote for nil, so only the committing validator counts.
        assert_eq!(tally.tallied, 20);
    }

    #[test]
    fn beacon_kit_rejects_a_malformed_bls_key() {
        let (secret, validator) = bls_validator(1, 50);
        let mut malformed = validator.clone();
        malformed.pub_key = PublicKey::Bls12_381(vec![0u8; 10]);
        malformed.address = account::Id::new([9u8; 20]);

        let mut header = beacon_kit_header();
        let sign_bytes = NonAbsentCommitVotes::construct_sign_bytes_no_timestamp(&header);
        let timestamp = header.header.time;

        header.commit.signatures = vec![
            agg_commit(
                &validator,
                timestamp,
                Some(aggregate(&[&secret], &sign_bytes)),
            ),
            agg_commit(&malformed, timestamp, None),
        ];

        let validators = validator::Set::new(vec![validator, malformed], None);
        let tally = ProdVotingPowerCalculator::default().voting_power_in(
            &header,
            &validators,
            TrustThreshold::default(),
        );

        match tally {
            Err(VerificationError(VerificationErrorDetail::InvalidSignature(_), _)) => {},
            other => panic!("expected InvalidSignature, got {other:?}"),
        }
    }
}
