//! ## Unaggreagated BLS signatures with double public key and DLEQ proof
//!

use core::iter::once;

use ark_ec::{CurveGroup,AffineRepr,};

use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};

use sha2::Sha256;

use crate::serialize::SerializableToBytes;
#[macro_use]
use crate::{broken_derives};
use crate::single::{SecretKeyVT,KeypairVT,PublicKey,Keypair, Signature};
use crate::schnorr_pop::SchnorrProof;
use crate::chaum_pedersen_signature::{ChaumPedersenSigner, ChaumPedersenVerifier};
use crate::{EngineBLS, Message, Signed};

/// Wrapper for a point in the signature group which is supposed to
/// the same logarithm as the public key in the public key group
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKeyInSignatureGroup<E: EngineBLS>(pub E::SignatureGroup);
broken_derives!(PublicKeyInSignatureGroup);  // Actually the derive works for this one, not sure why.

/// BLS Public Key with sub keys in both groups.
#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct DoublePublicKey<E: EngineBLS>(pub E::SignatureGroup, pub E::PublicKeyGroup);

pub trait DoublePublicKeyScheme<E: EngineBLS> {
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E>;
    fn sign(&mut self, message: Message) -> DoubleSignature<E>;
}

impl<E: EngineBLS> DoublePublicKeyScheme<E> for SecretKeyVT<E> {
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        PublicKeyInSignatureGroup( <E::SignatureGroup as CurveGroup>::Affine::generator().into_group()*self.0)       
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: Message) -> DoubleSignature<E> {
	let chaum_pedersen_signature = ChaumPedersenSigner::<E, Sha256>::generate_cp_signature(self, message);
	DoubleSignature(chaum_pedersen_signature.0.0, chaum_pedersen_signature.1)
    }
}

impl<E: EngineBLS> DoublePublicKeyScheme<E> for KeypairVT<E> {
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        self.secret.into_public_key_in_signature_group()
    }
    
    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: Message) -> DoubleSignature<E> {
	DoublePublicKeyScheme::sign(&mut self.secret, message)
    }

}

impl<E: EngineBLS> DoublePublicKeyScheme<E> for Keypair<E> {
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        self.into_vartime().into_public_key_in_signature_group()
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: Message) -> DoubleSignature<E> {
	DoublePublicKeyScheme::sign(&mut self.into_vartime(), message)
    }
    
}

/// Serialization for DoublePublickey
impl <E: EngineBLS> SerializableToBytes for DoublePublicKey<E>  {const SERIALIZED_BYTES_SIZE : usize  = E::SIGNATURE_SERIALIZED_SIZE+ E::PUBLICKEY_SERIALIZED_SIZE;}

/// Detached BLS Signature containing DLEQ
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct DoubleSignature<E: EngineBLS>(pub E::SignatureGroup, SchnorrProof<E>);

impl<E: EngineBLS> DoubleSignature<E> {
    //const DESCRIPTION : &'static str = "A BLS signature"; 

    /// Verify a single BLS signature
    pub fn verify(&self, message: Message, publickey: &PublicKey<E>) -> bool {
        let publickey = E::prepare_public_key(publickey.0);
        // TODO: Bentchmark these two variants
        // Variant 1.  Do not batch any normalizations
        let message = E::prepare_signature(message.hash_to_signature_curve::<E>());
        let signature = E::prepare_signature(self.0);
        // Variant 2.  Batch signature curve normalizations
        //   let mut s = [E::hash_to_signature_curve(message), signature.0];
        //   E::SignatureCurve::batch_normalization(&s);
        //   let message = s[0].into_affine().prepare();
        //   let signature = s[1].into_affine().prepare();
        // TODO: Compare benchmarks on variants
        E::verify_prepared( signature,  &[(publickey,message)] )
    }
}

/// Message with attached BLS signature
/// 
/// 
#[derive(Debug,Clone)]
pub struct DoubleSignedMessage<E: EngineBLS> {
    pub message: Message,
    pub publickey: DoublePublicKey<E>,
    pub signature: DoubleSignature<E>,
}

impl<E: EngineBLS>  PartialEq<Self> for DoubleSignedMessage<E> {
    fn eq(&self, other: &Self) -> bool {
        self.message.eq(&other.message)
        && self.publickey.0.eq(&other.publickey.0)
        && self.publickey.1.eq(&other.publickey.1)
        && self.signature.0.eq(&other.signature.0)
    }
}

impl<'a,E: EngineBLS> Signed for &'a DoubleSignedMessage<E> {
    type E = E;

    type M = Message;
    type PKG = PublicKey<E>;

    type PKnM = ::core::iter::Once<(Message, PublicKey<E>)>;

    fn messages_and_publickeys(self) -> Self::PKnM {
        once((self.message.clone(), PublicKey(self.publickey.1)))    // TODO:  Avoid clone
    }

    fn signature(&self) -> Signature<E> { Signature(self.signature.0) }

    fn verify(self) -> bool {
	//we chaum pederesen verification which is faster
	ChaumPedersenVerifier::<E, Sha256>::verify_cp_signature(&PublicKeyInSignatureGroup::<E>(self.publickey.0), self.message, (Signature(self.signature.0), self.signature.1))
	    
    }    
}

/// Serialization for DoublePublickey
impl <E: EngineBLS> SerializableToBytes for DoubleSignature<E> {const SERIALIZED_BYTES_SIZE : usize = E::SIGNATURE_SERIALIZED_SIZE + 2 * E::SECRET_KEY_SIZE; }

