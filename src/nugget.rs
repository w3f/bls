//! ## BLS key pair with public key in both G1 and G2 and on a third curve of
//! ## group the same prime order
//! ## This implement Unaggreagated BLS signature along side with their DLEQ proof
//!
//! Implements schemes suggested in
//! [paper](https://eprint.iacr.org/2022/1611)
//! with a chaum-pedersen signature on a third curve
//!
//! The scheme is the same as the one implemented in `double.rs`
//! with the exception that the signature is on the third curve.
//!

use alloc::vec::Vec;
use core::{iter::once, marker::PhantomData};

use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};

use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

use digest::FixedOutputReset;
use sha2::Sha256;

use crate::broken_derives;
use crate::chaum_pedersen_signature::{ChaumPedersenSigner, ChaumPedersenVerifier};
use crate::dual_scalar_mul::DualScalarMultiplication;
use crate::chaum_pedersen_signature::DLEQProof;
use crate::serialize::SerializableToBytes;
use crate::single::{Keypair, KeypairVT, PublicKey, SecretKey, SecretKeyVT, Signature};
use crate::{EngineBLS, Message, Signed};

/// Wrapper for a point in the signature group which is supposed to
/// have the same logarithm as the public key in the public key group
#[derive(Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct PublicKeyInSignatureGroup<E: EngineBLS>(pub E::SignatureGroup);
broken_derives!(PublicKeyInSignatureGroup); // Actually the derive works for this one, not sure why.

//TODO: Make a type for a sister group. This makes sense because SisterGroup it doesn't mean on itself
// SisterGroup<E: EngineBLS> = CurveGroup + PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes
/// Wrapper for a point in the third curve sister group which is supposed to
/// have the same logarithm as the public key in the public key group
#[derive(Debug, Clone, Copy, PartialEq, Eq, CanonicalDeserialize)]
pub struct PublicKeyInSisterGroup<S: CurveGroup>(pub S);

pub trait NuggetPublicKey<
    E: EngineBLS,
    S: CurveGroup + PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
>
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E>;

    fn into_bls_public_key(&self) -> PublicKey<E>;

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S>;

    fn straus_sister_group_precomputed_points(&self) -> &[S];

    fn verify(&self, message: &Message, signature: &NuggetSignature<E>) -> bool;
}

pub trait NuggetBLS<E: EngineBLS, S: CurveGroup>
where
    S: PrimeGroup<ScalarField = E::Scalar>,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E>;

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S>;

    /// Return a triple public object containing public keys both in G1 and G2 and S
    fn sign(&mut self, message: &Message) -> NuggetSignature<E>;
}

impl<E: EngineBLS, S: CurveGroup> NuggetBLS<E, S> for SecretKeyVT<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        PublicKeyInSignatureGroup(
            <E::SignatureGroup as CurveGroup>::Affine::generator().into_group() * self.0,
        )
    }

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S> {
        PublicKeyInSisterGroup(S::Affine::generator().into_group() * self.0)
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        ChaumPedersenSigner::<E, S, Sha256>::generate_cp_signature(self, &message)
    }
}

/// Side-channel-protected variant: signing goes through the
/// `ChaumPedersenSigner` impl for `SecretKey`, so the resplit happens
/// on the split key (no `into_vartime` conversion is done here).
impl<E: EngineBLS, S: CurveGroup> NuggetBLS<E, S> for SecretKey<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        NuggetBLS::<E, S>::into_public_key_in_signature_group(&self.into_vartime())
    }

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S> {
        self.into_vartime().into_public_key_in_sister_group()
    }

    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        ChaumPedersenSigner::<E, S, Sha256>::generate_cp_signature(self, &message)
    }
}

impl<E: EngineBLS, S: CurveGroup> NuggetBLS<E, S> for KeypairVT<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        NuggetBLS::<E, S>::into_public_key_in_signature_group(&self.secret)
    }

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S> {
        self.secret.into_public_key_in_sister_group()
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        NuggetBLS::<E, S>::sign(&mut self.secret, message)
    }
}

impl<E: EngineBLS, S: CurveGroup> NuggetBLS<E, S> for Keypair<E>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn into_public_key_in_signature_group(&self) -> PublicKeyInSignatureGroup<E> {
        NuggetBLS::<E, S>::into_public_key_in_signature_group(&self.secret)
    }

    fn into_public_key_in_sister_group(&self) -> PublicKeyInSisterGroup<S> {
        NuggetBLS::<E, S>::into_public_key_in_sister_group(&self.secret)
    }

    /// Sign a message using a Seedabale RNG created from a seed derived from the message and key
    fn sign(&mut self, message: &Message) -> NuggetSignature<E> {
        NuggetBLS::<E, S>::sign(&mut self.secret, message)
    }
}

/// Detached BLS Signature containing DLEQ
#[derive(Clone, Debug, CanonicalSerialize, CanonicalDeserialize)]
pub struct NuggetSignature<E: EngineBLS>(pub E::SignatureGroup, pub DLEQProof<E>);

impl<E: EngineBLS> NuggetSignature<E> {
    //const DESCRIPTION : &'static str = "A BLS signature";

    /// Verify a single BLS signature using DLEQ proof
    pub fn verify<
        S: CurveGroup + DualScalarMultiplication,
        H: FixedOutputReset + Default + Clone,
        P: ChaumPedersenVerifier<E, S, H>,
    >(
        &self,
        message: &Message,
        publickey: &P,
    ) -> bool
    where
        S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
        E::SignatureGroup: DualScalarMultiplication,
    {
        publickey.verify_cp_signature(message, self)
    }
}

/// Message with attached BLS signature
///
///
#[derive(Debug, Clone)]
pub struct NuggetSignedMessage<E: EngineBLS, S: CurveGroup, P: NuggetPublicKey<E, S>>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
    P: Sized,
{
    pub message: Message,
    pub publickey: P,
    pub signature: NuggetSignature<E>,
    pub _phantom: PhantomData<S>,
}

impl<E: EngineBLS, S: CurveGroup, P: NuggetPublicKey<E, S>> NuggetSignedMessage<E, S, P>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
    P: Sized,
{
    pub fn new(message: Message, publickey: P, signature: NuggetSignature<E>) -> Self {
        NuggetSignedMessage {
            message,
            publickey,
            signature,
            _phantom: PhantomData,
        }
    }
}

impl<E: EngineBLS, S: CurveGroup, P: NuggetPublicKey<E, S>> PartialEq<Self>
    for NuggetSignedMessage<E, S, P>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
{
    fn eq(&self, other: &Self) -> bool {
        self.message.eq(&other.message)
            && self
                .publickey
                .into_bls_public_key()
                .eq(&other.publickey.into_bls_public_key())
            && self
                .publickey
                .into_public_key_in_signature_group()
                .eq(&other.publickey.into_public_key_in_signature_group())
            && self
                .publickey
                .into_public_key_in_sister_group()
                .eq(&other.publickey.into_public_key_in_sister_group())
            && self.signature.0.eq(&other.signature.0)
    }
}

impl<
        'a,
        E: EngineBLS,
        S: CurveGroup + DualScalarMultiplication,
        P: ChaumPedersenVerifier<E, S, Sha256>,
    > Signed for &'a NuggetSignedMessage<E, S, P>
where
    S: PrimeGroup<ScalarField = E::Scalar> + SerializableToBytes,
    E::SignatureGroup: DualScalarMultiplication,
{
    type E = E;

    type M = Message;
    type PKG = PublicKey<E>;

    type PKnM = ::core::iter::Once<(Message, PublicKey<E>)>;

    fn messages_and_publickeys(self) -> Self::PKnM {
        once((self.message.clone(), self.publickey.into_bls_public_key())) // TODO:  Avoid clone
    }

    fn signature(&self) -> Signature<E> {
        Signature(self.signature.0)
    }

    fn verify(self) -> bool {
        //we chaum pederesen verification which is faster
        ChaumPedersenVerifier::<E, S, Sha256>::verify_cp_signature(
            &self.publickey,
            &self.message,
            &self.signature,
        )
    }
}

/// Serialization for NuggetSignature
impl<E: EngineBLS> SerializableToBytes for NuggetSignature<E> {
    const SERIALIZED_BYTES_SIZE: usize = E::SIGNATURE_SERIALIZED_SIZE + 2 * E::SECRET_KEY_SIZE;
}

// Tests for the nugget module's traits live in the implementation modules:
// - double_nugget.rs tests for NuggetDoublePublicKey
// - double_nugget_glv.rs tests for NuggetDoublePublicKeyGLV
// - triple_nugget.rs tests for NuggetTriplePublicKey
