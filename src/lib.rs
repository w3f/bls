//! # Aggregate BLS signature library with extensive tuning options. 
//! 
//! In short, anyone using BLS signatures should normally choose both
//! an orientation as well as some aggregation and batching strategies
//! These two decissions impact performance dramaticaly, but making
//! the optimal choises requires some attentiom.  This crate employs
//! convenient abstraction boundaries between curver arithmatic, 
//! verifier routines, and aggregated and/or batched BLS signatures.
//! 
//! ### Pairings
//! 
//! If we have two elliptic curve with a pairing `e`, then
//! a BLS signature `sigma = s*H(msg)` by a public key `S = s g1`
//! can be verified with the one equation `e(g1,sigma) = e(S,H(msg))`.
//! These simple BLS signatures are very slow to verify however
//! because the pairing map `e` is far slower than many cryptographic
//! primitives.
//! 
//! Our pairing `e` maps from a small curve over `F(q)` and a larger
//! curve over `F(q^2)` into some multipliccative group if a field,
//! normally over `F(q^12)`.  In principle, this map `e` into `F(q^12)`
//! makes pairing based cryptography like BLS less secure than
//! other elliptic curve based cryptography, which further slows down
//! BLS signatures by requiring larger `q`.
//!
//! ### Arithmatic
//!
//! An almost universally applicable otimization is to seperate the
//! "Miller loop" that computes in `F(q)` and `F(q^2)` from the slow
//! final exponentiation that happens in `F(q^12)`.  So our actual
//! verification equation more resembles `e(-g1,sigma) e(S,H(msg)) = 1`.
//!
//! As one curve is smaller and hence faster, the user should choose 
//! which orientation of curves they prefer, meaning to which curve
//! they hash, and which curves hold the signatues and public keys.
//! In other words, your desired aggregation techniques and usage 
//! characteristics should determine if youp refer the verification
//! equation `e(g1,sigma) = e(S,H(msg))` or the fliped form
//! `e(sigma,g2) = e(H(msg),S)`.  See `UsualBLS` and `TinyBLS`.
//!
//! ### Aggregation
//!
//! We consder BLS signatures interesting because they support
//! dramatic optimizations when handling multiple signatures together.
//! In fact, BLS signatures support aggregation by a third party
//! that makes signatures smaller, not merely batch verification.  
//! All this stems from the bilinearity of `e`, meaning we reduce
//! the number of pairings, or size of the miller loop, by appling
//! rules like `e(x,z)e(y,z) = e(x+y,z)`, `e(x,y)e(x,z) = e(x,y+z)`,
//! etc.
//!
//! In essence, our aggregation tricks fall into two categories,
//! linear aggregation, in which only addition is used, and
//! delinearized optimiztions, in which we multiply curve points
//! by values unforseeable to the signers.
//! In general, linear techniques provide much better performance,
//! but require stronger invariants be maintained by the caller,
//! like messages being distinct, or limited signer sets with 
//! proofs-of-possession.  Also, the delinearized techniques remain
//! secure without tricky assumptions, but require more computation.
//! 
//! ### Verification
//!
//! We can often further reduce the pairings required in the
//! verification equation, beyond the naieve information tracked
//! by the aggregated signature itself.  Aggregated signature must
//! state all the individual messages and/or public keys, but
//! verifiers may collapse anything permitted. 
//! We thus encounter aggregation-like decissions that impact
//! verifier performance.
//!
//! We therefore provide an abstract interface that permits
//! doing further aggregation and/or passing any aggregate signature
//! to any verification routine.
//!
//! As a rule, we also attempt to batch normalize different arithmatic
//! outputs, but concievably small signer set sizes might make this
//! a pessimization.
//!
//! 
//!


// #![feature(generic_associated_types)]
#![feature(associated_type_defaults)]

#[macro_use]
extern crate arrayref;

// #[macro_use]
extern crate ff;

extern crate merlin;
extern crate paired as pairing;
extern crate rand;
// extern crate sha3;

use std::borrow::Borrow;

use ff::{Field, PrimeField, ScalarEngine, SqrtField}; // PrimeFieldDecodingError, PrimeFieldRepr
use pairing::{CurveAffine, CurveProjective, Engine};
use rand::{Rand, Rng};

pub mod single;
pub mod distinct;
pub mod pop;
pub mod delinear;
pub mod verifiers;
// pub mod delinear;


pub use single::{PublicKey,KeypairVT,Keypair,SecretKeyVT,SecretKey,Signature};


/// Internal message hash size.  
///
/// We choose 256 bits here so that birthday bound attacks cannot
/// find messages with the same hash.
const MESSAGE_SIZE: usize = 32;

/// Internal message hash type.  Short for frequent rehashing
/// by `HashMap`, etc.
#[derive(Debug,Copy,Clone,Hash,PartialEq,Eq,PartialOrd,Ord)]
pub struct Message(pub [u8; MESSAGE_SIZE]);

impl Message {
    pub fn new(context: &'static [u8], message: &[u8]) -> Message {
        // use sha3::{Shake128, digest::{Input,ExtendableOutput,XofReader}};
        // let mut h = Shake128::default();
        // h.input(self.message.borrow());
        // h.input(self.signature.0.into_affine().into_uncompressed().as_ref());        
        let mut t = ::merlin::Transcript::new(context);
        t.commit_bytes(b"", message);
        let mut msg = [0u8; MESSAGE_SIZE];
        // h.xof_result().read(&mut msg[..]);
        t.challenge_bytes(b"", &mut msg);
        Message(msg)
    }

    pub fn hash_to_signature_curve<E: EngineBLS>(&self) -> E::SignatureGroup {
        E::hash_to_signature_curve(&self.0[..])
    }
}

impl<'a> From<&'a [u8]> for Message {
    fn from(x: &[u8]) -> Message { Message::new(b"",x) }     
}


/// A weakening of `pairing::Engine` to permit transposing the groups.
///
/// You cannot transpose the two groups in a `pairing::Engine` without
/// first providing panicing implementations of `pairing::PrimeField`
/// for `Engine::Fqe`, which is not a prime field, and second,
/// providing wrapper types for the projective and affine group 
/// representations, which makes interacting with the original
/// `pairing::Engine` annoying.  This trait merely replicates
/// transposable functionality from `pairing::Engine` by removing
/// the fields of definition, but leaves the actual BLS signature
/// scheme to wrapper types.
///
/// We also extract two functions users may with to override:
/// random scalar generation and hashing to the singature curve.
pub trait EngineBLS {
    type Engine: Engine + ScalarEngine<Fr = Self::Scalar>;
    type Scalar: PrimeField + SqrtField; // = <Self::Engine as ScalarEngine>::Fr;

    /// Group where BLS public keys live
    /// 
    /// You should take this to be the `Engine::G1` curve usually
    /// becuase all verifiers perform additions on this curve, or
    /// even scalar multiplicaitons with delinearization.
    type PublicKeyGroup: 
        CurveProjective<Engine = Self::Engine, Scalar = Self::Scalar>
        + Into<<Self::PublicKeyGroup as CurveProjective>::Affine>;

    /// Group where BLS signatures live
    ///
    /// You should take this to be the `Engine::G2` curve usually
    /// becuase only aggregators perform additions on this curve, or
    /// scalar multiplicaitons with delinearization.
    type SignatureGroup: 
        CurveProjective<Engine = Self::Engine, Scalar = Self::Scalar>
        + Into<<Self::SignatureGroup as CurveProjective>::Affine>;

    /// Generate a random scalar for use as a secret key.
    fn generate<R: Rng>(rng: &mut R) -> Self::Scalar {
        Self::Scalar::rand(rng)
    }

    /// Hash one message to the signature curve.
    fn hash_to_signature_curve<M: Borrow<[u8]>>(message: M) -> Self::SignatureGroup {
        <Self::SignatureGroup as CurveProjective>::hash(message.borrow())
    }

    /// Run the Miller loop from `Engine` but orients its arguments
    /// to be a `SignatureGroup` and `PublicKeyGroup`.
    fn miller_loop<'a,I>(i: I) -> <Self::Engine as Engine>::Fqk
    where
        I: IntoIterator<Item = (
            &'a <<Self::PublicKeyGroup as CurveProjective>::Affine as CurveAffine>::Prepared,
            &'a <<Self::SignatureGroup as CurveProjective>::Affine as CurveAffine>::Prepared,
        )>;

    /// Perform final exponentiation on the result of a Miller loop.
    fn final_exponentiation(e: &<Self::Engine as Engine>::Fqk) -> Option<<Self::Engine as Engine>::Fqk> {
        Self::Engine::final_exponentiation(e)
    }

    /// Performs a pairing operation `e(p, q)` by calling `Engine::pairing`
    /// but orients its arguments to be a `PublicKeyGroup` and `SignatureGroup`.
    fn pairing<G1,G2>(p: G1, q: G2) -> <Self::Engine as Engine>::Fqk
    where
        G1: Into<<Self::PublicKeyGroup as CurveProjective>::Affine>,
        G2: Into<<Self::SignatureGroup as CurveProjective>::Affine>;
    /*
    {
        Self::final_exponentiation(&Self::miller_loop(
            [(&(p.into().prepare()), &(q.into().prepare()))].into_iter(),
        )).unwrap()
    }
    */

    /// Implement verification equation for aggregate BLS signatures
    /// provided as prepared points
    /// 
    /// This low-level routine does no verification of critical security
    /// properties like message distinctness.  It exists purely to
    /// simplify replacing mid-level routines with optimized variants,
    /// like versions that cache public key preperation or use fewer pairings. 
    fn verify_prepared<'a,I>(
        signature: &'a <<Self::SignatureGroup as CurveProjective>::Affine as CurveAffine>::Prepared,
        inputs: I
      ) -> bool
    where
        I: IntoIterator<Item = (
            &'a <<Self::PublicKeyGroup as CurveProjective>::Affine as CurveAffine>::Prepared,
            &'a <<Self::SignatureGroup as CurveProjective>::Affine as CurveAffine>::Prepared,
        )>
    {
        // Use a polymorphic static or const if we ever get either. 
        let mut g1_minus_generator = <Self::PublicKeyGroup as CurveProjective>::Affine::one();
        g1_minus_generator.negate();
        Self::final_exponentiation( & Self::miller_loop(
            inputs.into_iter().map(|t| t)  // reborrow hack
                .chain(::std::iter::once( (& g1_minus_generator.prepare(), signature) ))
        ) ).unwrap() == <Self::Engine as Engine>::Fqk::one()
    }
}


pub type PublicKeyProjective<E> = <E as EngineBLS>::PublicKeyGroup;
pub type PublicKeyAffine<E> = <<E as EngineBLS>::PublicKeyGroup as CurveProjective>::Affine;

pub type SignatureProjective<E> = <E as EngineBLS>::SignatureGroup;
pub type SignatureAffine<E> = <<E as EngineBLS>::SignatureGroup as CurveProjective>::Affine;




/// Usual aggregate BLS signature scheme on ZCash's BLS12-381 curve.
pub type ZBLS = UsualBLS<::pairing::bls12_381::Bls12>;

/// Usual aggregate BLS signature scheme on ZCash's BLS12-381 curve.
pub const Z_BLS : ZBLS = UsualBLS(::pairing::bls12_381::Bls12);


/// Usual BLS variant with tiny 48 byte public keys and 96 byte signatures.
///
/// We favor this variant because verifiers always perform
/// `O(signers)` additions on the `PublicKeyGroup`, or worse 128 bit
/// scalar multiplications with delinearization. 
/// We also orient this variant to match zcash's traits.
#[derive(Default)]
pub struct UsualBLS<E: Engine>(pub E);

impl<E: Engine> EngineBLS for UsualBLS<E> {
    type Engine = E;
    type Scalar = <Self::Engine as ScalarEngine>::Fr;
    type PublicKeyGroup = E::G1;
    type SignatureGroup = E::G2;

    fn miller_loop<'a,I>(i: I) -> E::Fqk
    where
        I: IntoIterator<Item = (
            &'a <E::G1Affine as CurveAffine>::Prepared,
            &'a <E::G2Affine as CurveAffine>::Prepared,
        )>,
    {
        // We require an ugly unecessary allocation here because
        // zcash's pairing library cnsumes an iterator of references
        // to tuples of references, which always requires 
        let i = i.into_iter().map(|t| t)
              .collect::<Vec<(&<E::G1Affine as CurveAffine>::Prepared,&<E::G2Affine as CurveAffine>::Prepared)>>();
        E::miller_loop(&i)
    }

    fn pairing<G1,G2>(p: G1, q: G2) -> E::Fqk
    where
        G1: Into<E::G1Affine>,
        G2: Into<E::G2Affine>,
    {
        E::pairing(p,q)
    }
}


/// Infrequently used BLS variant with tiny 48 byte signatures and 96 byte public keys,
///
/// We recommend gainst this variant by default because verifiers
/// always perform `O(signers)` additions on the `PublicKeyGroup`,
/// or worse 128 bit scalar multiplications with delinearization. 
/// Yet, there are specific use cases where this variant performs
/// better.  We swapy two group roles relative to zcash here.
#[derive(Default)]
pub struct TinyBLS<E: Engine>(pub E);

impl<E: Engine> EngineBLS for TinyBLS<E> {
    type Engine = E;
    type Scalar = <Self::Engine as ScalarEngine>::Fr;
    type PublicKeyGroup = E::G2;
    type SignatureGroup = E::G1;

    fn miller_loop<'a,I>(i: I) -> E::Fqk
    where
        I: IntoIterator<Item = (
            &'a <E::G2Affine as CurveAffine>::Prepared,
            &'a <E::G1Affine as CurveAffine>::Prepared,
        )>,
    {
        // We require an ugly unecessary allocation here because
        // zcash's pairing library cnsumes an iterator of references
        // to tuples of references, which always requires 
        let i = i.into_iter().map(|(x,y)| (y,x))
              .collect::<Vec<(&<E::G1Affine as CurveAffine>::Prepared,&<E::G2Affine as CurveAffine>::Prepared)>>();
        E::miller_loop(&i)
    }

    fn pairing<G2,G1>(p: G2, q: G1) -> E::Fqk
    where
        G1: Into<E::G1Affine>,
        G2: Into<E::G2Affine>,
    {
        E::pairing(q,p)
    }
}


/// Representation of an aggregated BLS signature.
///
/// We implement this trait only for borrows of appropriate structs
/// because otherwise we'd need extensive lifetime plumbing here,
/// due to the absence of assocaited type constructers (ATCs).
/// We shall make `messages_and_publickeys` take `&sefl` and
/// remove these limitations in the future once ATCs stabalize,
/// thus removing `PKG`.  See [Rust RFC 1598](https://github.com/rust-lang/rfcs/blob/master/text/1598-generic_associated_types.md)
/// We shall eventually remove MnPK entirely whenever `-> impl Trait`
/// in traits gets stabalized.  See [Rust RFCs 1522, 1951, and 2071](https://github.com/rust-lang/rust/issues/34511
pub trait Signed: Sized {
    type E: EngineBLS;

    /// Return the aggregated signature 
    fn signature(&self) -> Signature<Self::E>;

    type M: Borrow<Message> = Message;
    type PKG: Borrow<PublicKey<Self::E>> = PublicKey<Self::E>;

    /// Iterator over messages and public key reference pairs.
    type PKnM: Iterator<Item = (Self::M,Self::PKG)> + ExactSizeIterator;
    // type PKnM<'a>: Iterator<Item = (
    //    &'a <<Self as Signed<'a>>::E as EngineBLS>::PublicKeyGroup,
    //    &'a Self::M,
    // )> + DoubleEndedIterator + ExactSizeIterator + 'a;

    /// Returns an iterator over messages and public key reference for
    /// pairings, often only partially aggregated. 
    fn messages_and_publickeys(self) -> Self::PKnM;
    // fn messages_and_publickeys<'a>(&'s self) -> PKnM<'a>
    // -> impl Iterator<Item = (&'a Self::M, &'a Self::E::PublicKeyGroup)> + 'a;

    /// Appropriate BLS signature verification for the `Self` type.
    ///
    /// We use `verify_simple` as a default implementation because
    /// it supports unstable `self.messages_and_publickeys()` securely
    /// by calling it only once, and does not expect pulic key points
    /// to be normalized, but this should usually be replaced by more
    /// optimized variants. 
    fn verify(self) -> bool {
        verifiers::verify_simple(self)
    }
}



#[cfg(test)]
mod tests {
    // use super::*;

    // use rand::{SeedableRng, XorShiftRng};

    // #[test]
    // fn foo() { }
}

