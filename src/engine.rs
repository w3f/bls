//! ## Adaptation of `ark_ec::PairingEngine` to BLS-like signatures.
//!
//! We provide an `EngineBLS` trait that adapts `pairing::Engine`
//! to BLS-like signatures by permitting the group roles to be
//! transposed, which involves removing the field of definition, 
//! while retaining the correct associations.  
//! 
//! We support same-message aggregation strategies using wrappers
//! that satisfy `EngineBLS` as well, primarily because these
//! strategies must ocntroll access to the public key type.
//!
//! In future, we should support [Pixel](https://github.com/w3f/bls/issues/4)
//! by adding wrapper that replace `SignatureGroup` with a product
//! of both groups.  I think this requires abstracting `CruveAffine`
//! and `CruveProjective` without their base fields and wNAF windows,
//! but still with their affine, projective, and compressed forms,
//! and batch normalization. 

use std::borrow::{Borrow};
use std::ops::{MulAssign};
    
use ark_ff::{Field, PrimeField, SquareRootField};
use ark_ec::{AffineCurve, ProjectiveCurve, PairingEngine};
use ark_ec::hashing::map_to_curve_hasher::{MapToCurveBasedHasher, MapToCurve, HashToField};
use ark_ec::hashing::field_hashers::DefaultFieldHasher;
use ark_ec::hashing::curve_maps::wb::{WBParams, WBMap};
use ark_ff::{One};
use rand::{Rng};
use rand_core::RngCore;

use ark_ff::bytes::{ToBytes};
use std::fmt::Debug;

use blake2::VarBlake2b;

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
    type Engine: PairingEngine; //<Fr = Self::Scalar>;
    type Scalar: PrimeField + SquareRootField; // = <Self::Engine as ScalarEngine>::Fr;
    /// Group where BLS public keys live
    /// 
    /// You should take this to be the `Engine::G1` curve usually
    /// becuase all verifiers perform additions on this curve, or
    /// even scalar multiplicaitons with delinearization.
    type PublicKeyGroupBaseField: Field;

    type PublicKeyGroupAffine:
    AffineCurve<ScalarField = Self::Scalar, BaseField = Self::PublicKeyGroupBaseField, Projective = Self::PublicKeyGroup>
        + From<Self::PublicKeyGroup>
        + Into<Self::PublicKeyGroup>
        + Into<Self::PublicKeyPrepared>;
        //+ Into<<Self::PublicKeyGroup as ProjectiveCurve>::Affine>;

    type PublicKeyGroup: 
        ProjectiveCurve<Affine = Self::PublicKeyGroupAffine, ScalarField = Self::Scalar, BaseField = Self::PublicKeyGroupBaseField>
        + From<Self::PublicKeyGroupAffine>
        + Into<Self::PublicKeyGroupAffine>
	+ MulAssign<Self::Scalar>;
    
    type PublicKeyPrepared: ToBytes + Default + Clone + Send + Sync + Debug + From<Self::PublicKeyGroupAffine>;

    /// Group where BLS signatures live
    ///
    /// You should take this to be the `Engine::G2` curve usually
    /// becuase only aggregators perform additions on this curve, or
    /// scalar multiplicaitons with delinearization.
    type SignatureGroupBaseField: Field;

    type SignatureGroupAffine:
        AffineCurve<ScalarField = Self::Scalar, BaseField = Self::SignatureGroupBaseField, Projective = Self::SignatureGroup>
        + From<Self::SignatureGroup>
        + Into<Self::SignatureGroup>
	+ Into<Self::SignaturePrepared>;
    
    type SignatureGroup:  ProjectiveCurve<Affine = Self::SignatureGroupAffine, ScalarField = Self::Scalar, BaseField = Self::SignatureGroupBaseField>
        + Into<Self::SignatureGroupAffine>
	+ From<Self::SignatureGroupAffine>
	+ MulAssign<Self::Scalar>;

    type SignaturePrepared: ToBytes + Default + Clone + Send + Sync + Debug + From<Self::SignatureGroupAffine>;

    type HashToSignatureField: HashToField<Self::SignatureGroupBaseField>;
    type MapToSignatureCurve: MapToCurve<Self::SignatureGroupAffine>;

    /// Generate a random scalar for use as a secret key.
    fn generate<R: Rng + RngCore>(rng: &mut R) -> Self::Scalar {
        Self::Scalar::rand(rng)
    }

    /// getter function for the hash to curve map
    fn hash_to_curve_map(&self) -> MapToCurveBasedHasher::<Self::SignatureGroupAffine, Self::HashToSignatureField, Self::MapToSignatureCurve>;
    
    /// Hash one message to the signature curve.
    fn hash_to_signature_curve<M: Borrow<[u8]>>(&self, message: M) -> Self::SignatureGroup {
        self.hash_to_curve_map().hash(message);
    }

    /// Run the Miller loop from `Engine` but orients its arguments
    /// to be a `SignatureGroup` and `PublicKeyGroup`.
    fn miller_loop<'a,I>(i: I) -> <Self::Engine as PairingEngine>::Fqk
    where
        Self::PublicKeyPrepared: 'a,
        Self::SignaturePrepared: 'a,
        I: IntoIterator<Item = &'a (
            <Self as EngineBLS>::PublicKeyPrepared,
            Self::SignaturePrepared,
        )>;

    /// Perform final exponentiation on the result of a Miller loop.
    fn final_exponentiation(e: &<Self::Engine as PairingEngine>::Fqk) -> Option<<Self::Engine as PairingEngine>::Fqk> {
        Self::Engine::final_exponentiation(e)
    }

    /// Performs a pairing operation `e(p, q)` by calling `Engine::pairing`
    /// but orients its arguments to be a `PublicKeyGroup` and `SignatureGroup`.
    fn pairing<G1,G2>(p: G1, q: G2) -> <Self::Engine as PairingEngine>::Fqk
    where
        G1: Into<<Self::PublicKeyGroup as ProjectiveCurve>::Affine>,
        G2: Into<<Self::SignatureGroup as ProjectiveCurve>::Affine>;
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
        signature: Self::SignaturePrepared,
        inputs: I
      ) -> bool
    where
        Self::PublicKeyPrepared: 'a,
        Self::SignaturePrepared: 'a,
        I: IntoIterator<Item = &'a (
            Self::PublicKeyPrepared,
            Self::SignaturePrepared,
        )>
    {
        let lhs: [_;1] = [(Self::public_key_minus_generator_prepared(),signature)];
        Self::final_exponentiation( & Self::miller_loop(
            inputs.into_iter().map(|t| t).chain(&lhs)
	) ).unwrap() == <Self::Engine as PairingEngine>::Fqk::one()
    }
    
    /// Prepared negative of the generator of the public key curve.
    fn public_key_minus_generator_prepared() -> Self::PublicKeyPrepared;

    /// Process the public key to be use in pairing. This has to be
    /// implemented by the type of BLS system implementing the engine
    /// by calling either prepare_g1 or prepare_g2 based on which group
    /// is used by the signature system to host the public key
    fn prepare_public_key(g: impl Into<Self::PublicKeyGroupAffine>) -> Self::PublicKeyPrepared {
        let g_affine: Self::PublicKeyGroupAffine = g.into();
        Self::PublicKeyPrepared::from(g_affine)
    }

    /// Process the signature to be use in pairing. This has to be
    /// implemented by the type of BLS system implementing the engine
    /// by calling either prepare_g1 or prepare_g2 based on which group
    /// is used by the signature system to host the public key
    fn prepare_signature(g: impl Into<Self::SignatureGroupAffine>) -> Self::SignaturePrepared {
	    let g_affine: Self::SignatureGroupAffine = g.into();
        Self::SignaturePrepared::from(g_affine)
    }

}

/// Usual aggregate BLS signature scheme on ZCash's BLS12-381 curve.
//pub type ZBLS = UsualBLS<ark_bls12_381::Bls12_381>;
pub type BLS377 = UsualBLS<ark_bls12_377::Bls12_377>;

/// Usual aggregate BLS signature scheme on ZCash's BLS12-381 curve.
// pub const Z_BLS : ZBLS = UsualBLS(::zexe_algebra::bls12_381::Bls12_381{});

/// Usual BLS variant with tiny 48 byte public keys and 96 byte signatures.
///
/// We favor this variant because verifiers always perform
/// `O(signers)` additions on the `PublicKeyGroup`, or worse 128 bit
/// scalar multiplications with delinearization. 
/// We also orient this variant to match zcash's traits.
#[derive(Default)]
pub struct UsualBLS<E: PairingEngine>(pub E);

impl<E: PairingEngine> EngineBLS for UsualBLS<E> {
    type Engine = E;
    type Scalar = <Self::Engine as PairingEngine>::Fr;

    type PublicKeyGroup = E::G1Projective;
    type PublicKeyGroupAffine = E::G1Affine;
    type PublicKeyPrepared = E::G1Prepared;
    type PublicKeyGroupBaseField = <Self::Engine as PairingEngine>::Fq;

    type SignatureGroup = E::G2Projective;
    type SignatureGroupAffine = E::G2Affine;
    type SignaturePrepared = E::G2Prepared;
    type SignatureGroupBaseField = <Self::Engine as PairingEngine>::Fqe;

    type HashToSignatureField =  DefaultFieldHasher<VarBlake2b>;    
    type MapToSignatureCurve = WBMap<E>;
    
    fn miller_loop<'a,I>(i: I) -> E::Fqk
    where
        // Self::PublicKeyPrepared: 'a,
        // Self::SignaturePrepared: 'a,
        I: IntoIterator<Item = &'a (
             Self::PublicKeyPrepared,
             Self::SignaturePrepared,
        )>
    {
        E::miller_loop(i)
    }

    fn pairing<G1,G2>(p: G1, q: G2) -> E::Fqk
    where
        G1: Into<E::G1Affine>,
        G2: Into<E::G2Affine>,
    {
        E::pairing(p,q)
    }

    /// Prepared negative of the generator of the public key curve.
    fn public_key_minus_generator_prepared()
     -> Self::PublicKeyPrepared
    {
        let g1_minus_generator = <Self::PublicKeyGroup as ProjectiveCurve>::Affine::prime_subgroup_generator();
        (-g1_minus_generator).into()
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
pub struct TinyBLS<E: PairingEngine>(pub E);

impl<E: PairingEngine> EngineBLS for TinyBLS<E> {
    type Engine = E;
    type Scalar = <Self::Engine as PairingEngine>::Fr;

    type SignatureGroup = E::G1Projective;
    type SignatureGroupAffine = E::G1Affine;
    type SignaturePrepared = E::G1Prepared;
    type SignatureGroupBaseField = <Self::Engine as PairingEngine>::Fq;

    type PublicKeyGroup = E::G2Projective;
    type PublicKeyGroupAffine = E::G2Affine;
    type PublicKeyPrepared = E::G2Prepared;
    type PublicKeyGroupBaseField = <Self::Engine as PairingEngine>::Fqe;

    fn miller_loop<'a,I>(i: I) -> E::Fqk
    where
        I: IntoIterator<Item = &'a(
            Self::PublicKeyPrepared,
            Self::SignaturePrepared,
        )>,
    {
        // We require an ugly unecessary allocation here because
        // zcash's pairing library cnsumes an iterator of references
        // to tuples of references, which always requires 
        let i = i.into_iter().map(|(x,y)| (y.clone(),x.clone()))
              .collect::<Vec<(Self::SignaturePrepared, Self::PublicKeyPrepared)>>();
        E::miller_loop(&i)
    }

    fn pairing<G2,G1>(p: G2, q: G1) -> E::Fqk
    where
        G1: Into<E::G1Affine>,
        G2: Into<E::G2Affine>,
    {
        E::pairing(q,p)
    }

    /// Prepared negative of the generator of the public key curve.
    fn public_key_minus_generator_prepared()
     -> Self::PublicKeyPrepared
    {
        let g2_minus_generator = <Self::PublicKeyGroup as ProjectiveCurve>::Affine::prime_subgroup_generator();
        (-g2_minus_generator).into()
    }

}

