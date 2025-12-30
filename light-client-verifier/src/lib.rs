#![no_std]

extern crate alloc;

mod prelude;

pub mod errors;
pub mod operations;
pub mod options;
pub mod predicates;
pub mod types;
mod verifier;
#[cfg(test)]
mod test;

pub use verifier::{PredicateVerifier, Verdict, Verifier};

#[cfg(feature = "rust-crypto")]
pub use verifier::ProdVerifier;
