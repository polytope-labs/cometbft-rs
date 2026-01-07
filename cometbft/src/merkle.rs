//! Merkle tree used in CometBFT networks

pub mod proof;

pub use proof::Proof;

use core::marker::PhantomData;

use digest::{consts::U32, Digest, FixedOutputReset};

use crate::crypto::Sha256;
use crate::prelude::*;

/// Size of Merkle root hash
pub use crate::crypto::sha256::HASH_SIZE;

/// Hash is the output of the cryptographic digest function
pub type Hash = [u8; HASH_SIZE];

/// Compute a simple Merkle root from vectors of arbitrary byte vectors.
/// The leaves of the tree are the bytes of the given byte vectors in
/// the given order.
pub fn simple_hash_from_byte_vectors<H>(byte_vecs: &[impl AsRef<[u8]>]) -> Hash
where
    H: MerkleHash + Default,
{
    let mut hasher = H::default();
    hasher.hash_byte_vectors(byte_vecs)
}

/// Implementation of Merkle tree hashing for CometBFT.
pub trait MerkleHash {
    // tmhash({})
    // Pre and post-conditions: the hasher is in the reset state
    // before and after calling this function.
    fn empty_hash(&mut self) -> Hash;

    // tmhash(0x00 || leaf)
    // Pre and post-conditions: the hasher is in the reset state
    // before and after calling this function.
    fn leaf_hash(&mut self, bytes: &[u8]) -> Hash;

    // tmhash(0x01 || left || right)
    // Pre and post-conditions: the hasher is in the reset state
    // before and after calling this function.
    fn inner_hash(&mut self, left: Hash, right: Hash) -> Hash;

    // Implements recursion into subtrees.
    // Pre and post-conditions: the hasher is in the reset state
    // before and after calling this function.
    fn hash_byte_vectors(&mut self, byte_vecs: &[impl AsRef<[u8]>]) -> Hash {
        let length = byte_vecs.len();
        match length {
            0 => self.empty_hash(),
            1 => self.leaf_hash(byte_vecs[0].as_ref()),
            _ => {
                let split = length.next_power_of_two() / 2;
                let left = self.hash_byte_vectors(&byte_vecs[..split]);
                let right = self.hash_byte_vectors(&byte_vecs[split..]);
                self.inner_hash(left, right)
            },
        }
    }
}

// A helper to copy GenericArray into the human-friendly Hash type.
fn copy_to_hash(output: impl AsRef<[u8]>) -> Hash {
    let mut hash_bytes = [0u8; HASH_SIZE];
    hash_bytes.copy_from_slice(output.as_ref());
    hash_bytes
}

impl<H> MerkleHash for H
where
    H: Digest<OutputSize = U32> + FixedOutputReset,
{
    fn empty_hash(&mut self) -> Hash {
        // Get the output of an empty digest state.
        let digest = self.finalize_reset();
        copy_to_hash(digest)
    }

    fn leaf_hash(&mut self, bytes: &[u8]) -> Hash {
        // Feed the data to the hasher, prepended with 0x00.
        Digest::update(self, [0x00]);
        Digest::update(self, bytes);

        // Finalize the digest, reset the hasher state.
        let digest = self.finalize_reset();

        copy_to_hash(digest)
    }

    fn inner_hash(&mut self, left: Hash, right: Hash) -> Hash {
        // Feed the data to the hasher: 0x1, then left and right data.
        Digest::update(self, [0x01]);
        Digest::update(self, left);
        Digest::update(self, right);

        // Finalize the digest, reset the hasher state
        let digest = self.finalize_reset();

        copy_to_hash(digest)
    }
}

/// Get the split point for merkle tree construction.
/// Returns the largest power of 2 less than n, matching CometBFT's getSplitPoint.
pub fn get_split_point(n: u64) -> u64 {
    if n < 1 {
        panic!("n must be >= 1");
    }
    let bit_len = 64 - n.leading_zeros();
    let k = 1u64 << (bit_len - 1);

    // If k equals n, then n is a power of 2, and we need k/2 to get a value LESS than n
    if k == n {
        k >> 1
    } else {
        k
    }
}

/// Compute the merkle root hash from a leaf hash and its aunt hashes.
/// This implements CometBFT's computeHashFromAunts algorithm.
///
/// * `aunts` - The sibling hashes from leaf to root (bottom to top)
pub fn compute_hash_from_aunts<H: MerkleHash + Default>(
    index: u64,
    total: u64,
    leaf_hash: Hash,
    aunts: &[Hash],
) -> Option<Hash> {
    if total == 0 {
        return None;
    }

    if total == 1 {
        if aunts.is_empty() {
            return Some(leaf_hash);
        }
        return None;
    }

    if aunts.is_empty() {
        return None;
    }

    let split = get_split_point(total);
    let mut hasher = H::default();

    if index < split {
        // Leaf is in left subtree
        let left_hash = compute_hash_from_aunts::<H>(
            index,
            split,
            leaf_hash,
            &aunts[..aunts.len() - 1],
        )?;
        let right_hash = aunts.last()?;
        Some(hasher.inner_hash(left_hash, *right_hash))
    } else {
        // Leaf is in right subtree
        let left_hash = aunts.last()?;
        let right_hash = compute_hash_from_aunts::<H>(
            index - split,
            total - split,
            leaf_hash,
            &aunts[..aunts.len() - 1],
        )?;
        Some(hasher.inner_hash(*left_hash, right_hash))
    }
}

/// Compute the merkle root from a slice of leaf hashes.
pub fn compute_root_from_leaf_hashes<H: MerkleHash + Default>(leaf_hashes: &[Hash]) -> Hash {
    let mut hasher = H::default();
    compute_root_recursive(&mut hasher, leaf_hashes)
}

fn compute_root_recursive<H: MerkleHash>(hasher: &mut H, hashes: &[Hash]) -> Hash {
    match hashes.len() {
        0 => hasher.empty_hash(),
        1 => hashes[0],
        n => {
            let split = get_split_point(n as u64) as usize;
            let left = compute_root_recursive(hasher, &hashes[..split]);
            let right = compute_root_recursive(hasher, &hashes[split..]);
            hasher.inner_hash(left, right)
        },
    }
}

/// Generate a merkle proof (aunt hashes) for a leaf at the given index.
/// Returns the sibling hashes from leaf to root (bottom to top).
pub fn generate_proof<H: MerkleHash + Default>(leaf_hashes: &[Hash], index: usize) -> Vec<Hash> {
    let mut hasher = H::default();
    generate_proof_recursive(&mut hasher, leaf_hashes, index)
}

fn generate_proof_recursive<H: MerkleHash>(
    hasher: &mut H,
    hashes: &[Hash],
    index: usize,
) -> Vec<Hash> {
    if hashes.len() <= 1 {
        return Vec::new();
    }

    let split = get_split_point(hashes.len() as u64) as usize;

    if index < split {
        // Leaf is in left subtree/branch
        let mut proof = generate_proof_recursive(hasher, &hashes[..split], index);
        // Add right subtree root as aunt/sibling
        let right_root = compute_root_recursive(hasher, &hashes[split..]);
        proof.push(right_root);
        proof
    } else {
        // Leaf is in right subtree/branch
        let mut proof = generate_proof_recursive(hasher, &hashes[split..], index - split);
        // Add left subtree root as aunt/sibling
        let left_root = compute_root_recursive(hasher, &hashes[..split]);
        proof.push(left_root);
        proof
    }
}

/// A wrapper for platform-provided host functions which can't do incremental
/// hashing. One unfortunate example of such platform is Polkadot.
pub struct NonIncremental<H>(PhantomData<H>);

impl<H> Default for NonIncremental<H> {
    fn default() -> Self {
        Self(Default::default())
    }
}

impl<H: Sha256> MerkleHash for NonIncremental<H> {
    fn empty_hash(&mut self) -> Hash {
        let digest = H::digest([]);
        copy_to_hash(digest)
    }

    fn leaf_hash(&mut self, bytes: &[u8]) -> Hash {
        // This is why non-incremental digest APIs are daft.
        let mut buf = Vec::with_capacity(1 + bytes.len());
        buf.push(0);
        buf.extend_from_slice(bytes);
        let digest = H::digest(buf);
        copy_to_hash(digest)
    }

    fn inner_hash(&mut self, left: Hash, right: Hash) -> Hash {
        // This is why non-incremental digest APIs are daft.
        let mut buf = [0u8; 1 + HASH_SIZE * 2];
        buf[0] = 1;
        buf[1..HASH_SIZE + 1].copy_from_slice(&left);
        buf[HASH_SIZE + 1..].copy_from_slice(&right);
        let digest = H::digest(buf);
        copy_to_hash(digest)
    }
}

#[cfg(all(test, feature = "rust-crypto"))]
mod tests {
    use sha2::Sha256;
    use subtle_encoding::hex;

    use super::*; // TODO: use non-subtle ?

    #[test]
    fn test_rfc6962_empty_tree() {
        let empty_tree_root_hex =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let empty_tree_root = &hex::decode(empty_tree_root_hex).unwrap();
        let empty_tree: Vec<Vec<u8>> = vec![vec![]; 0];

        let root = simple_hash_from_byte_vectors::<Sha256>(&empty_tree);
        assert_eq!(empty_tree_root, &root);
    }

    #[test]
    fn test_rfc6962_empty_leaf() {
        let empty_leaf_root_hex =
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d";
        let empty_leaf_root = &hex::decode(empty_leaf_root_hex).unwrap();
        let one_empty_leaf: Vec<Vec<u8>> = vec![vec![]; 1];

        let root = simple_hash_from_byte_vectors::<Sha256>(&one_empty_leaf);
        assert_eq!(empty_leaf_root, &root);
    }

    #[test]
    fn test_rfc6962_leaf() {
        let leaf_root_hex = "395aa064aa4c29f7010acfe3f25db9485bbd4b91897b6ad7ad547639252b4d56";
        let leaf_string = "L123456";

        let leaf_root = &hex::decode(leaf_root_hex).unwrap();
        let leaf_tree: Vec<Vec<u8>> = vec![leaf_string.as_bytes().to_vec(); 1];

        let root = simple_hash_from_byte_vectors::<Sha256>(&leaf_tree);
        assert_eq!(leaf_root, &root);
    }

    #[test]
    fn test_rfc6962_tree_of_2() {
        let node_hash_hex = "dc9a0536ff2e196d5a628a5bf377ab247bbddf83342be39699461c1e766e6646";
        let left = b"N123".to_vec();
        let right = b"N456".to_vec();

        let node_hash = &hex::decode(node_hash_hex).unwrap();
        let hash = simple_hash_from_byte_vectors::<Sha256>(&[left, right]);
        assert_eq!(node_hash, &hash);
    }

    mod non_incremental {
        use super::*;

        #[test]
        fn test_rfc6962_tree_of_2() {
            let node_hash_hex = "dc9a0536ff2e196d5a628a5bf377ab247bbddf83342be39699461c1e766e6646";
            let left = b"N123".to_vec();
            let right = b"N456".to_vec();

            let node_hash = &hex::decode(node_hash_hex).unwrap();
            let hash = simple_hash_from_byte_vectors::<NonIncremental<Sha256>>(&[left, right]);
            assert_eq!(node_hash, &hash);
        }
    }
}
