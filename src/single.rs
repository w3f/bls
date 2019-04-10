//! Unaggreagated BLS signatures
//!
//! We simplify the code by using only the projective form as
//! produced by algebraic operations, like aggregation, signing, and
//! `SecretKey::into_public`, for both `Signature` and `Group`.
//!
//! In principle, one benifits from an affine form in serialization,
//! and pairings meaning signature verification, but the conversion
//! from affine to projective is always free and the converion from
//! projective to affine is free if we do no algebraic operations.  
//! We thus expect the conversion to and from projective to be free
//! in the case of verifications where staying affine yields the
//! largest benifits.
//!
//! We imagine this simplification helps focus on more important
//! optimizations, like placing `batch_normalization` calls well.
//! We could exploit `CurveProjective::add_assign_mixed` function
//! if we had seperate types for affine points, but if doing so 
//! improved performance enough then we instead suggest tweaking
//! `CurveProjective::add_mixed` to test for normalized points.
//!
//! TODO: Add serde support for serialization throughout.  See
//!  https://github.com/ebfull/pairing/pull/87#issuecomment-402397091
//!  https://github.com/poanetwork/hbbft/blob/38178af1244ddeca27f9d23750ca755af6e886ee/src/crypto/serde_impl.rs#L95

use ff::{Field}; // PrimeField, ScalarEngine, SqrtField
use pairing::{CurveAffine, CurveProjective};  // Engine, PrimeField, SqrtField
use rand::{Rng, thread_rng, SeedableRng, chacha::ChaChaRng};
// use rand::prelude::*; // ThreadRng,thread_rng
// use rand_chacha::ChaChaRng;

// use std::borrow::{Borrow,BorrowMut};
use std::iter::once;

use super::*;


// Secrets //


/// Secret signing key lacking the side channel protections from
/// key splitting.  Avoid using directly in production.
#[derive(Clone)]
pub struct SecretKeyVT<E: EngineBLS>(pub E::Scalar);

impl<E: EngineBLS> SecretKeyVT<E> {
    /// Generate a secret key without side channel protections.
    pub fn generate<R: Rng>(mut rng: R) -> Self {
        SecretKeyVT( E::generate(&mut rng) )
    }

    /// Sign without side channel protections from key mutation.
    pub fn sign(&self, message: Message) -> Signature<E> {
        let mut s = message.hash_to_signature_curve::<E>();
        s.mul_assign(self.0);
        // s.normalize();   // VRFs are faster if we only normalize once, but no normalize method exists.
        // E::SignatureGroup::batch_normalization(&mut [&mut s]);  
        Signature(s)
    }

    /// Convert into a `SecretKey` that supports side channel protections,
    /// but does not itself resplit the key.
    pub fn into_split(&self) -> SecretKey<E> {
        SecretKey(self.0.clone(),E::Scalar::zero())
    }

    /// 
    pub fn into_public(&self) -> PublicKey<E> {
        // TODO str4d never decided on projective vs affine here, so benchmark both versions.
        PublicKey( <E::PublicKeyGroup as CurveProjective>::Affine::one().mul(self.0) )
        // let mut g = <E::PublicKeyGroup as CurveProjective>::one();
        // g.mul_assign(self.0);
        // PublicKey(p)
    }
}

/// Secret signing key that is split to provide side channel protection.
///
/// This works because `self.0 * H(message) + self.1 * H(message) = (self.0 + self.1) * H(message)`
///
/// We require mutable access to the secret key, but interior mutability
/// can easily be employed.  If `secret: RefCell<SecretKey>` this might resemble:
/// ```rust,no_run
/// let mut s = secret.borrow().clone();
/// let signature = s.sign(message,OsRng);
/// secret.replace(s);
/// ```
/// If however `secret: Mutex<SecretKey>` or `secret: RwLock<SecretKey>`
/// then one might avoid holding the write lock while signing, or even
/// while sampling the random numbers, possibly using `sign_with`.
///
/// TODO: Is Pippenger’s algorithm, or another fast MSM algorithm,
/// secure when used with key splitting?
#[derive(Clone)]
pub struct SecretKey<E: EngineBLS>(E::Scalar,E::Scalar);
// TODO: Serialization

impl<E: EngineBLS> SecretKey<E> {
    /// Generate a secret key that is already split for side channel protection.
    pub fn generate<R: Rng>(mut rng: R) -> Self {
        SecretKey( E::generate(&mut rng), E::generate(&mut rng) )
    }

    /// Create a representative usable for operations lacking 
    /// side channel protections.  
    pub fn into_vartime(&self) -> SecretKeyVT<E> {
        let mut secret = self.0.clone();
        secret.add_assign(&self.1);
        SecretKeyVT(secret)
    }

    /// Randomly adjust how we split our secret signing key. 
    //
    // An initial call to this function after deserialization or
    // `into_split` incurs a miniscule risk from side channel attacks
    // but then protects the highly vulnerable signing operations.
    pub fn resplit<R: Rng>(&mut self, mut rng: R) {
        // resplit_with(|| Ok(self), rng).unwrap();
        let x = E::generate(&mut rng);
        self.0.add_assign(&x);
        self.1.sub_assign(&x);
    }

    /// Sign without doing the key resplit mutation that provides side channel protection.
    ///
    /// Avoid using directly without appropriate `replit` calls, but maybe
    /// useful in proof-of-concenpt code, as it does not require a mutable
    /// secret key.
    pub fn sign_once(&self, message: Message) -> Signature<E> {
        let mut s = message.hash_to_signature_curve::<E>();
        let mut t = s.clone();
        t.mul_assign(self.0);
        s.mul_assign(self.1);
        s.add_assign(&t);
        // s.normalize();   // VRFs are faster if we only normalize once, but no normalize method exists.
        // E::SignatureGroup::batch_normalization(&mut [&mut s]);  
        Signature(s)
    }

    /// Sign after respliting the secret key for side channel protections.
    pub fn sign<R: Rng>(&mut self, message: Message, rng: R) -> Signature<E> {
        self.resplit(rng);
        self.sign_once(message)
    }

    /// Derive our public key from our secret key
    ///
    /// We do not resplit for side channel protections here since
    /// this call should be rare.
    pub fn into_public(&self) -> PublicKey<E> {
        let generator = <E::PublicKeyGroup as CurveProjective>::Affine::one();
        let mut publickey = generator.mul(self.0);
        publickey.add_assign( & generator.mul(self.1) );
        PublicKey(publickey)
        // TODO str4d never decided on projective vs affine here, so benchmark this.
        /*
        let mut x = <E::PublicKeyGroup as CurveProjective>::one();
        x.mul_assign(self.0);
        let y = <E::PublicKeyGroup as CurveProjective>::one();
        y.mul_assign(self.1);
        x.add_assign(&y);
        PublicKey(x)
        */
    }
}


// Non-secrets //


/*
TODO: Requires specilizatin
macro_rules! borrow_wrapper {
    ($wrapper:tt,$wrapped:tt,$var:tt) => {
impl<E: EngineBLS> Borrow<E::$wrapped> for $wrapper<E> {
    borrow(&self) -> &E::$wrapped { &self.$var }
}
impl<E: EngineBLS> BorrowMut<E::$wrapped> for $wrapper<E> {
    borrow_mut(&self) -> &E::$wrapped { &self.$var }
}
    } 
} // macro_rules!
*/


macro_rules! broken_derives {
    ($wrapper:tt) => {

impl<E: EngineBLS> Clone for $wrapper<E> {
    fn clone(&self) -> Self { $wrapper(self.0) }
}
impl<E: EngineBLS> Copy for $wrapper<E> { }

impl<E: EngineBLS>  PartialEq<Self> for $wrapper<E> {
    fn eq(&self, other: &Self) -> bool {
        self.0.eq(&other.0)
    }
}

impl <E: EngineBLS> Eq for $wrapper<E> {}

// TODO: PartialOrd & Ord

    }
}  // macro_rules!


/// Detached BLS Signature
#[derive(Debug)]
pub struct Signature<E: EngineBLS>(pub E::SignatureGroup);
// TODO: Serialization

broken_derives!(Signature);  // Actually the derive works for this one, not sure why.
// borrow_wrapper!(Signature,SignatureGroup,0);

impl<E: EngineBLS> Signature<E> {
    /// Verify a single BLS signature
    pub fn verify(&self, message: Message, publickey: &PublicKey<E>) -> bool {
        let publickey = publickey.0.into_affine().prepare();
        // TODO: Bentchmark these two variants
        // Variant 1.  Do not batch any normalizations
        let message = message.hash_to_signature_curve::<E>().into_affine().prepare();
        let signature = self.0.into_affine().prepare();
        // Variant 2.  Batch signature curve normalizations
        //   let mut s = [E::hash_to_signature_curve(message), signature.0];
        //   E::SignatureCurve::batch_normalization(&s);
        //   let message = s[0].into_affine().prepare();
        //   let signature = s[1].into_affine().prepare();
        // TODO: Compare benchmarks on variants
        E::verify_prepared( & signature, once((&publickey,&message)) )
    }
}


/// BLS Public Key
#[derive(Debug)]
pub struct PublicKey<E: EngineBLS>(pub E::PublicKeyGroup);
// TODO: Serialization

broken_derives!(PublicKey);
// borrow_wrapper!(PublicKey,PublicKeyGroup,0);

// impl<E: EngineBLS> PublicKey<E> {  }



/// BLS Keypair
///
/// We create `Signed` messages with a `Keypair` to avoid recomputing
/// the public key, which usually takes longer than signing when
/// the public key group is `G2`.
///
/// We provide constant-time signing using key splitting.
pub struct KeypairVT<E: EngineBLS> {
    pub secret: SecretKeyVT<E>,
    pub public: PublicKey<E>,
}
// TODO: Serialization

impl<E: EngineBLS> KeypairVT<E> {
    /// Generate a `Keypair`
    pub fn generate<R: Rng>(rng: R) -> Self {
        let secret = SecretKeyVT::generate(rng);
        let public = secret.into_public();
        KeypairVT { secret, public }
    }

    /// Sign a message creating a `SignedMessage` using a user supplied CSPRNG for the key splitting.
    pub fn sign<R: Rng>(&self, message: Message) -> SignedMessage<E> {
        let signature = self.secret.sign(message);  
        SignedMessage {
            message,
            publickey: self.public.clone(),
            signature,
        }
    }
}


/// BLS Keypair
///
/// We create `Signed` messages with a `Keypair` to avoid recomputing
/// the public key, which usually takes longer than signing when
/// the public key group is `G2`.
///
/// We provide constant-time signing using key splitting.
pub struct Keypair<E: EngineBLS> {
    pub secret: SecretKey<E>,
    pub public: PublicKey<E>,
}
// TODO: Serialization

impl<E: EngineBLS> Keypair<E> {
    /// Generate a `Keypair`
    pub fn generate<R: Rng>(rng: R) -> Self {
        let secret = SecretKey::generate(rng);
        let public = secret.into_public();
        Keypair { secret, public }
    }

    /// Sign a message creating a `SignedMessage` using a user supplied CSPRNG for the key splitting.
    pub fn sign_with_rng<R: Rng>(&mut self, message: Message, rng: R) -> SignedMessage<E> {
        let signature = self.secret.sign(message,rng);
        SignedMessage {
            message,
            publickey: self.public,
            signature,
        }
    }

    /// Create a `SignedMessage` using the default `ThreadRng`.
    pub fn sign(&mut self, message: Message) -> SignedMessage<E> {
        self.sign_with_rng(message,thread_rng())
    }
}


/// Message with attached BLS signature
/// 
/// 
#[derive(Clone)]
pub struct SignedMessage<E: EngineBLS> {
    pub message: Message,
    pub publickey: PublicKey<E>,
    pub signature: Signature<E>,
}
// TODO: Serialization

// borrow_wrapper!(Signature,SignatureGroup,signature);
// borrow_wrapper!(PublicKey,PublicKeyGroup,publickey);

impl<'a,E: EngineBLS> Signed for &'a SignedMessage<E> {
    type E = E;

    type M = Message;
    type PKG = PublicKey<E>;

    type PKnM = ::std::iter::Once<(Message, PublicKey<E>)>;

    fn messages_and_publickeys(self) -> Self::PKnM {
        once((self.message.clone(), self.publickey))    // TODO:  Avoid clone
    }

    fn signature(&self) -> Signature<E> { self.signature }

    fn verify(self) -> bool {
        self.signature.verify(self.message, &self.publickey)
    }
}

impl<E: EngineBLS> SignedMessage<E> {
    /// Raw bytes output from a BLS signature regarded as a VRF.
    ///
    /// If you are not the signer then you must verify the VRF before calling this method.
    ///
    /// If called with distinct contexts then outputs should be independent.
    ///
    /// We incorporate both the input and output to provide the 2Hash-DH
    /// construction from Theorem 2 on page 32 in appendex C of
    /// ["Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain"](https://eprint.iacr.org/2017/573.pdf)
    /// by Bernardo David, Peter Gazi, Aggelos Kiayias, and Alexander Russell.
    pub fn make_bytes<Out: Default + AsMut<[u8]>>(&self, context: &'static [u8]) -> Out {
        // use sha3::{Shake128, digest::{Input,ExtendableOutput,XofReader}};
        // let mut h = Shake128::default();
        // h.input(&self.message.0[..]);
        // h.input(self.signature.0.into_affine().into_uncompressed().as_ref());        
        let mut t = ::merlin::Transcript::new(context);
        t.commit_bytes(b"msg",&self.message.0[..]);
        t.commit_bytes(b"out",self.signature.0.into_affine().into_uncompressed().as_ref());        
        let mut seed = Out::default();
        // h.xof_result().read(seed.as_mut());
        t.challenge_bytes(b"", seed.as_mut());
        seed
    }

    /* TODO: Switch to this whenever pairing upgrades to rand 0.5 or later
    /// VRF output converted into any `SeedableRng`.
    ///
    /// If you are not the signer then you must verify the VRF before calling this method.
    ///
    /// We expect most users would prefer the less generic `VRFInOut::make_chacharng` method.
    pub fn make_rng<R: SeedableRng>(&self, context: &'static [u8]) -> R {
        R::from_seed(self.make_bytes::<R::Seed>(context))
    }
    */

    /// VRF output converted into a `ChaChaRng`.
    ///
    /// If you are not the signer then you must verify the VRF before calling this method.
    ///
    /// If called with distinct contexts then outputs should be independent.
    /// Independent output streams are available via `ChaChaRng::set_stream` too.
    ///
    /// We incorporate both the input and output to provide the 2Hash-DH
    /// construction from Theorem 2 on page 32 in appendex C of
    /// ["Ouroboros Praos: An adaptively-secure, semi-synchronous proof-of-stake blockchain"](https://eprint.iacr.org/2017/573.pdf)
    /// by Bernardo David, Peter Gazi, Aggelos Kiayias, and Alexander Russell.
    pub fn make_chacharng(&self, context: &'static [u8]) -> ChaChaRng {
        // self.make_rng::<ChaChaRng>(context)
        // TODO: Remove this ugly hack whenever rand gets updated to 0.5 or later
        let bytes = self.make_bytes::<[u8;32]>(context);
        let mut words = [0u32; 8];
        for (w,bs) in words.iter_mut().zip(bytes.chunks(4)) {
            let mut b = [0u8; 4];
            b.copy_from_slice(bs);
            *w = u32::from_le_bytes(b);
        }
        ChaChaRng::from_seed(&words)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use pairing::bls12_381::Bls12;
    use rand::{SeedableRng, XorShiftRng};

    // #[test]
    // fn foo() { }
}
