//! Aggregated BLS signature library

// #![feature(generic_associated_types)]
#![feature(associated_type_defaults)]

extern crate merlin;
extern crate pairing;
extern crate rand;
// extern crate sha3;

use pairing::{CurveAffine, CurveProjective, Engine, Field, PrimeField, SqrtField};
use rand::{Rand, Rng};

use std::borrow::Borrow;
use std::collections::HashSet;
use std::hash::Hash;  // Hasher
use std::marker::PhantomData;

pub mod single;
pub mod linear;
// pub mod delinear;

pub use single::{PublicKey,KeypairVT,Keypair,SecretKeyVT,SecretKey,Signature};

/// Internal message hash size.  
///
/// We choose 192 bits here although 128 bits (16 bytes) suffices.
const MESSAGE_SIZE: usize = 24;

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
    type Engine: Engine<Fr = Self::Scalar>;
    type Scalar: PrimeField + SqrtField;

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

	/// Generate a random scalar 
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
                // .chain(&[ (& g1_minus_generator.prepare(), signature) ])
		) ).unwrap().is_zero() // == E::Fqk::zero()
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
/// scalar multiplications with delinearization.  We nevertheless
#[derive(Default)]
pub struct UsualBLS<E: Engine>(pub E);

impl<E: Engine> EngineBLS for UsualBLS<E> {
	type Engine = E;
	type Scalar = <Self::Engine as Engine>::Fr;
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


/// Infrequently used BLS variant with tiny 48 byte signatures and 96 byte public keys.
///
/// We recommend gainst this variant because verifiers always perform
/// `O(signers)` additions on the `PublicKeyGroup`, or worse 128 bit
/// scalar multiplications with delinearization.  We nevertheless
/// provide this variant because some use cases may perform better
/// this way, or even require both curves in both roles. 
#[derive(Default)]
pub struct TinyBLS<E: Engine>(pub E);

impl<E: Engine> EngineBLS for TinyBLS<E> {
	type Engine = E;
	type Scalar = <Self::Engine as Engine>::Fr;
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
/// thus removing `PKG`. 
/// https://github.com/rust-lang/rfcs/blob/master/text/1598-generic_associated_types.md
/// We shall eventually remove MnPK entirely whenever `-> impl Trait`
/// in traits gets stabalized https://github.com/rust-lang/rust/issues/34511
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
		verify_simple(self)
    }
}


/// Simple unoptimized BLS signature verification.  Useful for testing.
pub fn verify_unoptimized<S: Signed>(s: S) -> bool {
    let signature = s.signature().0.into_affine().prepare();
	let prepared = s.messages_and_publickeys()
	    .map(|(message,public_key)| {
		    (public_key.borrow().0.into_affine().prepare(),
		     message.borrow().hash_to_signature_curve::<S::E>().into_affine().prepare())
	    }).collect::<Vec<(_,_)>>();
    S::E::verify_prepared(
        & signature,
        prepared.iter().map(|(m,pk)| (m,pk))
    )
}


/// Simple universal BLS signature verification
///
/// We support an unstable `Signed::messages_and_publickeys()`
/// securely by calling it only once and batch normalizing all
/// points, as do most other verification routines here.
/// We do no optimizations that reduce the number of pairings
/// by combining repeated messages or signers. 
pub fn verify_simple<S: Signed>(s: S) -> bool {
    let signature = s.signature().0;
	// We could write this more idiomatically using iterator adaptors,
	// and avoiding an unecessary allocation for publickeys, but only
	// by calling self.messages_and_publickeys() repeatedly.
	let itr = s.messages_and_publickeys();
    let l = {  let (lower, upper) = itr.size_hint();  upper.unwrap_or(lower)  };
	let mut gpk = Vec::with_capacity(l);
	let mut gms = Vec::with_capacity(l+1);
    for (message,publickey) in itr {
		gpk.push( publickey.borrow().0.clone() );
    	gms.push( message.borrow().hash_to_signature_curve::<S::E>() );
    }
	<<S as Signed>::E as EngineBLS>::PublicKeyGroup::batch_normalization(gpk.as_mut_slice());
	gms.push(signature);
	<<S as Signed>::E as EngineBLS>::SignatureGroup::batch_normalization(gms.as_mut_slice());
    let signature = gms.pop().unwrap().into_affine().prepare();
	let prepared = gpk.iter().zip(gms)
	    .map(|(pk,m)| { (pk.into_affine().prepare(), m.into_affine().prepare()) })
        .collect::<Vec<(_,_)>>();
    S::E::verify_prepared( &signature, prepared.iter().map(|(m,pk)| (m,pk)) )
}


/// Excessively optimized BLS signature verification
///
/// We minimize the number of pairing operations by doing two
/// basis change operation using Gaussian elimination, first in the
/// message space and then in the signer space.  As a result, we
/// do only `1 + min(msg_d,pk_d)` pairings where `msg_d` and `pk_d`
/// are the numbers of distinct messages and signers, respectively.
///
/// We expect this to improve performance dramatically when both
/// signers and messages are repeated enough, simpler strategies
/// work as well or better when say messages are distinct. 
///
/// Explination:
///
/// We consider the bipartite graph with vertex sets given by points
/// on the two curves and edges given by desired pairings between them.
/// We let $M$ denote the bipartite adjacency matrix for this graph,
/// so that multiplying $M$ on the the right and left by the vectors
/// of messages and signers respectively reproduces our original sum
/// of pairings.
///
/// We first use elementary "row" operations to make $M$ upper
/// triangular, as in Gaussian elimination, but at the cost of also
/// performing one-sided "change of basis" operations that collect
/// our original "basis vectors" into sums of curve points.
/// We next use elementary "column" operations to make $M$ diagonal,
/// again adjusting the basis with curve point operations.
///
/// In this, we regard $M$ as a matrix over the scalar field $F_p$
/// so we may do row or column swaps and row or column addition
/// operations with small scalars, but not lone row or column scalar
/// multiplication because these always involve divisions, which
/// produces large curve points that slow us down thereafter.  
/// We do not require such divisions because we do not solve any
/// system of equations and do not need ones on the diagonal.
///
/// TODO: 
/// We leave implementing this optimization to near future work 
/// because it benifits from public keys being affine or having
/// another hashable representation. 
///
///
/// As a curiosity, we note one interesting but suboptimal algorithm
/// that avoids small scalar multiplications when doing this:
///
/// If we ignore subtraction, then the minimal number of pairing
/// operations required to verify aggregated BLS signatures is the
/// minimal bipartite edge cover, aka bipartite dimension, of the
/// bipartite graph with vertices given by points on the two curves
/// and edges given by desired pairings. 
/// In general, this problem is NP-hard even to approximate. 
/// See:  https://en.wikipedia.org/wiki/Bipartite_dimension
///
/// There are polynomial time algorithms for bipartite edge cover in
/// special cases, with domino-free graphs being among the widest
/// known classes.  See:
/// Amilhastre, Jérôme; Janssen, Philippe; Vilarem, Marie-Catherine,
/// "Computing a minimum biclique cover is polynomial for bipartite domino-free graphs" (1997)
/// https://core.ac.uk/download/pdf/82546650.pdf
///
/// If we now exploit subtraction, then these dominos can be
/// completed into $K_{3,3}$s, like
///  $(a,x)+(a,y)+(b,x)+(b,y)+(b,z)+(c,y)+(c,z) = (a+b+c,x+y+z) - (a,z) - (c,z)$
/// which looks optimal for itself, and likely permits the further
/// aggregation, and maybe the subtracted terms can be aggregated later.
///
/// We could not however find the optimal numbers of pairings by
/// completing dominos like this because (a+b+c,x+y+z) - (b,y),
/// which looks optimal for itself, but only has one subtraction.
fn verify_with_gaussian_elimination<S: Signed>(s: S) -> bool {
    unimplemented!()
}



#[cfg(test)]
mod tests {
	use super::*;

    use pairing::bls12_381::Bls12;
    use rand::{SeedableRng, XorShiftRng};

    // #[test]
	// fn foo() { }
}

