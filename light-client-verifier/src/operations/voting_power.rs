//! Provides an interface and default implementation for the `VotingPower` operation

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
};
#[cfg(feature = "beacon-kit")]
use cometbft::{PublicKey, Signature};
use serde::{Deserialize, Serialize};

#[cfg(feature = "beacon-kit")]
use prost::Message;

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
                signature
            } => (*validator_address, *timestamp, signature),
            CommitSig::BlockIdFlagAggNil { .. } |
            CommitSig::BlockIdFlagAggCommitAbsent { .. } |
            CommitSig::BlockIdFlagAggNilAbsent { .. } => return None
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

/// Information about aggregated BLS signatures (for Berachain/beacon-kit support).
/// There can be two separate aggregated signatures:
/// 1. For block commits (AggCommit, AggCommitAbsent)
/// 2. For nil votes (AggNil, AggNilAbsent)
#[cfg(feature = "beacon-kit")]
struct AggregatedBlsInfo {
    /// The aggregated signature for block commits
    commit_signature: Option<Signature>,
    /// Addresses of validators who participated in the commit aggregation
    commit_addresses: Vec<account::Id>,
    /// The aggregated signature for nil votes
    nil_signature: Option<Signature>,
    /// Addresses of validators who participated in the nil aggregation
    nil_addresses: Vec<account::Id>,
    /// Sign bytes without timestamp (for BLS aggregated verification)
    sign_bytes_no_timestamp: Vec<u8>,
    /// Whether the aggregated signatures have been verified
    verified: bool,
}

/// Collection of non-absent commit votes.
struct NonAbsentCommitVotes {
    /// Votes sorted by validator address.
    votes: Vec<NonAbsentCommitVote>,
    /// Internal buffer for storing sign_bytes.
    ///
    /// The buffer is reused for each canonical vote so that we allocate it
    /// once.
    sign_bytes: Vec<u8>,
    /// Information about aggregated BLS signatures (if present)
    #[cfg(feature = "beacon-kit")]
    aggregated_bls: Option<AggregatedBlsInfo>,
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

        // Detect and collect aggregated BLS signature information
        #[cfg(feature = "beacon-kit")]
        let aggregated_bls = Self::collect_aggregated_bls_info(signed_header);

        Ok(Self {
            votes,
            sign_bytes: Vec::with_capacity(Self::SIGN_BYTES_INITIAL_CAPACITY),
            #[cfg(feature = "beacon-kit")]
            aggregated_bls,
        })
    }

    /// Collect aggregated BLS signature information from the commit.
    ///
    /// Returns `Some` if the commit contains aggregated BLS signatures
    /// (BlockIdFlagAggCommit or BlockIdFlagAggCommitAbsent), `None` otherwise.
    #[cfg(feature = "beacon-kit")]
    fn collect_aggregated_bls_info(signed_header: &SignedHeader) -> Option<AggregatedBlsInfo> {
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
                        if let Some(s) = signature {
                            commit_signature = Some(s.clone());
                        }
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
                        if let Some(s) = signature {
                            nil_signature = Some(s.clone());
                        }
                    }
                },
                CommitSig::BlockIdFlagAggNilAbsent {
                    validator_address, ..
                } => {
                    nil_addresses.push(*validator_address);
                },
                _ => {}
            }
        }

        // If we found no aggregated signatures, return None
        if commit_addresses.is_empty() && nil_addresses.is_empty() {
            return None;
        }

        // Construct sign_bytes without timestamp for BLS aggregated verification
        let sign_bytes_no_timestamp = Self::construct_sign_bytes_no_timestamp(signed_header);

        Some(AggregatedBlsInfo {
            commit_signature,
            commit_addresses,
            nil_signature,
            nil_addresses,
            sign_bytes_no_timestamp,
            verified: false,
        })
    }

    /// Construct canonical vote sign bytes WITHOUT timestamp (for BLS aggregated signatures).
    #[cfg(feature = "beacon-kit")]
    fn construct_sign_bytes_no_timestamp(signed_header: &SignedHeader) -> Vec<u8> {
        // Protobuf message for canonical vote without timestamp
        #[derive(Clone, PartialEq, Message)]
        struct CanonicalVoteNoTimestamp {
            #[prost(enumeration = "i32", tag = "1")]
            pub r#type: i32,
            #[prost(sfixed64, tag = "2")]
            pub height: i64,
            #[prost(sfixed64, tag = "3")]
            pub round: i64,
            #[prost(message, optional, tag = "4")]
            pub block_id: Option<CanonicalBlockId>,
            // Note: No timestamp field (field 5)
            #[prost(string, tag = "6")]
            pub chain_id: alloc::string::String,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CanonicalBlockId {
            #[prost(bytes = "vec", tag = "1")]
            pub hash: Vec<u8>,
            #[prost(message, optional, tag = "2")]
            pub part_set_header: Option<CanonicalPartSetHeader>,
        }

        #[derive(Clone, PartialEq, Message)]
        struct CanonicalPartSetHeader {
            #[prost(uint32, tag = "1")]
            pub total: u32,
            #[prost(bytes = "vec", tag = "2")]
            pub hash: Vec<u8>,
        }

        let commit = &signed_header.commit;
        let header = &signed_header.header;

        let block_id = CanonicalBlockId {
            hash: commit.block_id.hash.as_bytes().to_vec(),
            part_set_header: Some(CanonicalPartSetHeader {
                total: commit.block_id.part_set_header.total,
                hash: commit.block_id.part_set_header.hash.as_bytes().to_vec(),
            }),
        };

        let vote = CanonicalVoteNoTimestamp {
            r#type: 2, // Precommit
            height: commit.height.value() as i64,
            round: commit.round.value() as i64,
            block_id: Some(block_id),
            chain_id: header.chain_id.to_string(),
        };

        // Encode with length prefix (as CometBFT does)
        let mut buf = Vec::new();
        let encoded = vote.encode_to_vec();
        // Varint length prefix
        let len = encoded.len();
        if len < 128 {
            buf.push(len as u8);
        } else {
            buf.push(((len & 0x7F) | 0x80) as u8);
            buf.push((len >> 7) as u8);
        }
        buf.extend_from_slice(&encoded);
        buf
    }

    /// Looks up a vote cast by given validator.
    ///
    /// If the validator didn't cast a vote or voted for `nil`, returns `Ok(None)`. Otherwise, if
    /// the vote had valid signature, returns `Ok(Some(idx))` where idx is the validator's index.
    /// If the vote had invalid signature, returns `Err`.
    ///
    /// Note: For aggregated BLS signatures, call `verify_aggregated_bls_if_present` first
    /// to verify the aggregated signature before calling this method.
    pub fn has_voted<V: signature::Verifier>(
        &mut self,
        validator: &validator::Info,
    ) -> Result<Option<usize>, VerificationError> {
        // Check for aggregated BLS signature participation first
        // The aggregated signature should already be verified via verify_aggregated_bls_if_present
        #[cfg(feature = "beacon-kit")]
        if let Some(ref agg_info) = self.aggregated_bls {
            // Check if this validator participated in the commit aggregation
            if let Some(pos) = agg_info.commit_addresses.iter().position(|a| *a == validator.address) {
                if agg_info.verified {
                    return Ok(Some(pos));
                }
            }
            // Check if this validator participated in the nil aggregation
            if let Some(pos) = agg_info.nil_addresses.iter().position(|a| *a == validator.address) {
                if agg_info.verified {
                    // Offset by commit_addresses length to avoid collision
                    return Ok(Some(pos + agg_info.commit_addresses.len()));
                }
            }
        }

        // Standard individual signature verification
        if let Ok(idx) = self
            .votes
            .binary_search_by_key(&validator.address, NonAbsentCommitVote::validator_id)
        {
            let vote = &mut self.votes[idx];

            if !vote.verified {
                self.sign_bytes.clear();
                vote.signed_vote
                    .sign_bytes_into(&mut self.sign_bytes)
                    .expect("buffer is resized if needed and encoding never fails");

                let sign_bytes = self.sign_bytes.as_slice();
                validator
                    .verify_signature::<V>(sign_bytes, vote.signed_vote.signature())
                    .map_err(|_| {
                        VerificationError::invalid_signature(
                            vote.signed_vote.signature().as_bytes().to_vec(),
                            Box::new(validator.clone()),
                            sign_bytes.to_vec(),
                        )
                    })?;
                vote.verified = true;
            }
            // Offset the index to avoid collision with aggregated BLS indices
            #[cfg(feature = "beacon-kit")]
            let offset = self.aggregated_bls.as_ref().map_or(0, |a| a.commit_addresses.len() + a.nil_addresses.len());
            #[cfg(not(feature = "beacon-kit"))]
            let offset = 0;
            Ok(Some(idx + offset))
        } else {
            Ok(None)
        }
    }

    /// Verify the aggregated BLS signatures against all participating validators.
    ///
    /// This should be called before checking individual votes when aggregated
    /// BLS signatures are present. It verifies both the commit and nil aggregated
    /// signatures using their respective participating validators' public keys.
    #[cfg(feature = "beacon-kit")]
    pub fn verify_aggregated_bls_if_present(
        &mut self,
        validator_set: &ValidatorSet,
    ) -> Result<(), VerificationError> {
        use blst::min_pk::{PublicKey as BlsPublicKey, Signature as BlsSignature};

        let agg_info = match &mut self.aggregated_bls {
            Some(info) if !info.verified => info,
            _ => return Ok(()), // No aggregated BLS or already verified
        };

        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

        // Helper to collect BLS public keys for a list of addresses
        let collect_bls_keys = |addresses: &[account::Id]| -> Vec<BlsPublicKey> {
            let mut keys = Vec::new();
            for addr in addresses {
                let validator = validator_set
                    .validators()
                    .iter()
                    .find(|v| &v.address == addr);

                if let Some(val) = validator {
                    if let PublicKey::Bls12_381(pk_bytes) = &val.pub_key {
                        if let Ok(pk) = BlsPublicKey::from_bytes(pk_bytes) {
                            keys.push(pk);
                        } else {
                            // Try compressed format (first 48 bytes)
                            let compressed: [u8; 48] = pk_bytes[..48].try_into().unwrap_or([0u8; 48]);
                            if let Ok(pk) = BlsPublicKey::from_bytes(&compressed) {
                                keys.push(pk);
                            }
                        }
                    }
                }
            }
            keys
        };

        // Verify aggregated commit signature if present
        if let Some(ref commit_sig) = agg_info.commit_signature {
            let commit_keys = collect_bls_keys(&agg_info.commit_addresses);

            if !commit_keys.is_empty() {
                let sig_bytes = commit_sig.as_bytes();
                let agg_sig = BlsSignature::from_bytes(sig_bytes).map_err(|_| {
                    VerificationError::invalid_signature(
                        sig_bytes.to_vec(),
                        Box::new(validator_set.validators()[0].clone()),
                        agg_info.sign_bytes_no_timestamp.clone(),
                    )
                })?;

                let pk_refs: Vec<&BlsPublicKey> = commit_keys.iter().collect();
                let result = agg_sig.fast_aggregate_verify(
                    false,
                    &agg_info.sign_bytes_no_timestamp,
                    dst,
                    &pk_refs,
                );

                if result != blst::BLST_ERROR::BLST_SUCCESS {
                    return Err(VerificationError::invalid_signature(
                        sig_bytes.to_vec(),
                        Box::new(validator_set.validators()[0].clone()),
                        agg_info.sign_bytes_no_timestamp.clone(),
                    ));
                }
            }
        }

        // Verify aggregated nil signature if present
        if let Some(ref nil_sig) = agg_info.nil_signature {
            let nil_keys = collect_bls_keys(&agg_info.nil_addresses);

            if !nil_keys.is_empty() {
                let sig_bytes = nil_sig.as_bytes();
                let agg_sig = BlsSignature::from_bytes(sig_bytes).map_err(|_| {
                    VerificationError::invalid_signature(
                        sig_bytes.to_vec(),
                        Box::new(validator_set.validators()[0].clone()),
                        agg_info.sign_bytes_no_timestamp.clone(),
                    )
                })?;

                let pk_refs: Vec<&BlsPublicKey> = nil_keys.iter().collect();
                let result = agg_sig.fast_aggregate_verify(
                    false,
                    &agg_info.sign_bytes_no_timestamp,
                    dst,
                    &pk_refs,
                );

                if result != blst::BLST_ERROR::BLST_SUCCESS {
                    return Err(VerificationError::invalid_signature(
                        sig_bytes.to_vec(),
                        Box::new(validator_set.validators()[0].clone()),
                        agg_info.sign_bytes_no_timestamp.clone(),
                    ));
                }
            }
        }

        agg_info.verified = true;
        Ok(())
    }

    /// Check if a validator participated in the aggregated BLS signature.
    #[cfg(feature = "beacon-kit")]
    fn is_aggregated_bls_participant(&self, address: &account::Id) -> bool {
        self.aggregated_bls.as_ref().map_or(false, |info| {
            info.commit_addresses.contains(address) || info.nil_addresses.contains(address)
        })
    }

    /// Mark the aggregated BLS verification as complete (for non-beacon-kit builds).
    #[cfg(not(feature = "beacon-kit"))]
    pub fn verify_aggregated_bls_if_present(
        &mut self,
        _validator_set: &ValidatorSet,
    ) -> Result<(), VerificationError> {
        Ok(())
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
    // Verify aggregated BLS signature if present (before checking individual votes)
    votes.verify_aggregated_bls_if_present(validator_set)?;

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
}
