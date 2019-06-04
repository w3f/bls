//! ## Unaggreagated BLS signatures
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

use ff::{Field, PrimeField, PrimeFieldRepr, PrimeFieldDecodingError}; // ScalarEngine, SqrtField
use pairing::{CurveAffine, CurveProjective, EncodedPoint, GroupDecodingError};  // Engine, PrimeField, SqrtField
use rand::{Rng, thread_rng, SeedableRng, chacha::ChaChaRng};
// use rand::prelude::*; // ThreadRng,thread_rng
// use rand_chacha::ChaChaRng;

// use std::borrow::{Borrow,BorrowMut};
use std::iter::once;
use std::io;

use super::*;


// //////////////// SECRETS //////////////// //

/// Secret signing key lacking the side channel protections from
/// key splitting.  Avoid using directly in production.
pub struct SecretKeyVT<E: EngineBLS>(pub E::Scalar);

impl<E: EngineBLS> Clone for SecretKeyVT<E> {
    fn clone(&self) -> Self { SecretKeyVT(self.0) }
}

// TODO: Serialization

impl<E: EngineBLS> SecretKeyVT<E> {
    /// Convert our secret key to its representation type, which
    /// satisfies both `AsRef<[u64]>` and `ff::PrimeFieldRepr`.
    /// We suggest `ff::PrimeFieldRepr::write_le` for serialization,
    /// invoked by our `write` method.
    pub fn to_repr(&self) -> <E::Scalar as PrimeField>::Repr {
        self.0.into_repr()
    }
    pub fn write<W: io::Write>(&self, writer: W) -> io::Result<()> {
        self.to_repr().write_le(writer)
    }

    /// Convert our secret key from its representation type, which
    /// satisfies `Default`, `AsMut<[u64]>`, and `ff::PrimeFieldRepr`.
    /// We suggest `ff::PrimeFieldRepr::read_le` for deserialization,
    /// invoked via our `read` method, which requires a seperate call.
    pub fn from_repr(repr: <E::Scalar as PrimeField>::Repr) -> Result<Self,PrimeFieldDecodingError> {
        Ok(SecretKeyVT(<E::Scalar as PrimeField>::from_repr(repr) ?))
    }
    pub fn read<R: io::Read>(reader: R) -> io::Result<<E::Scalar as PrimeField>::Repr> {
        let mut repr = <E::Scalar as PrimeField>::Repr::default();
        repr.read_le(reader) ?;
        Ok(repr)
    }
    
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
    pub fn into_split_dirty(&self) -> SecretKey<E> {
        SecretKey {
            key: [ self.0.clone(), E::Scalar::zero() ],
            old_unsigned: E::SignatureGroup::zero(),
            old_signed: E::SignatureGroup::zero(),
        } 
    }

    /// Convert into a `SecretKey` applying side channel protections.
    pub fn into_split<R: Rng>(&self, mut rng: R) -> SecretKey<E> {
        let mut s = self.into_split_dirty();
        s.resplit(&mut rng);
        s.init_point_mutation(rng);
        s
    }

    /// Derive our public key from our secret key
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
/// A simple key splitting works because
/// `self.key[0] * H(message) + self.key[1] * H(message) = (self.key[0] + self.key[1]) * H(message)`.
/// In our case, we mutate the point being signed too by keeping
/// an old point in both signed and unsigned forms, so our message
/// point becomes `new_unsigned = H(message) - old_unsigned`, 
/// we compute `new_signed = self.key[0] * new_unsigned + self.key[1] * new_unsigned`,
/// and our signature becomes `new_signed + old_signed`.
/// We save the new signed and unsigned values as old ones, so that adversaries
/// also cannot know the curves points being multiplied by scalars.
/// In this, our `init_point_mutation` method signs some random point,
/// so that even an adversary who tracks all signed messages cannot
/// foresee the curve points being signed. 
///
/// We require mutable access to the secret key, but interior mutability
/// can easily be employed, which might resemble:
/// ```rust,no_run
/// # extern crate bls_like as bls;
/// # extern crate rand;
/// # use bls::{SecretKey,ZBLS,Message};
/// # use rand::thread_rng;
/// # let message = Message::new(b"ctx",b"test message");
/// let mut secret = ::std::cell::RefCell::new(SecretKey::<ZBLS>::generate(thread_rng()));
/// let signature = secret.borrow_mut().sign(message,thread_rng());
/// ```
/// If however `secret: Mutex<SecretKey>` or `secret: RwLock<SecretKey>`
/// then one might avoid holding the write lock while signing, or even
/// while sampling the random numbers by using other methods.
///
/// Right now, we serialize using `SecretKey::into_vartime` and
/// `SecretKeyVT::write`, so `secret.into_vartime().write(writer)?`.
/// We deserialize using the `read`, `from_repr`, and `into_split`
/// methods of `SecretKeyVT`, so roughly
/// `SecretKeyVT::from_repr(SecretKeyVT::read(reader) ?) ?.into_split(thread_rng())`.
///
/// TODO: Provide sensible `to_bytes` and `from_bytes` methods
/// for `ZBLS` and `TinyBLS<..>`.
///
/// TODO: Is Pippenger’s algorithm, or another fast MSM algorithm,
/// secure when used with key splitting?
pub struct SecretKey<E: EngineBLS> {
    key: [E::Scalar; 2],
    old_unsigned: E::SignatureGroup,
    old_signed: E::SignatureGroup,
}

impl<E: EngineBLS> Clone for SecretKey<E> {
    fn clone(&self) -> Self {
        SecretKey {
            key: self.key.clone(),
            old_unsigned: self.old_unsigned.clone(),
            old_signed: self.old_signed.clone(),
        }
    }
}

// TODO: Serialization

impl<E: EngineBLS> SecretKey<E> {
    /// Initialize the signature curve signed point mutation.
    ///
    /// Amortized over many signings involing this once costs
    /// nothing, but each individual invokation costs as much
    /// as signing.
    pub fn init_point_mutation<R: Rng>(&mut self, mut rng: R) {
        let mut s = rng.gen::<E::SignatureGroup>();
        self.old_unsigned = s;
        self.old_signed = s;
        self.old_signed.mul_assign(self.key[0]);
        s.mul_assign(self.key[1]);
        self.old_signed.add_assign(&s);
    }

    /// Generate a secret key that is already split for side channel protection,
    /// but does not apply signed point mutation.
    pub fn generate_dirty<R: Rng>(mut rng: R) -> Self {
        SecretKey {
            key: [ E::generate(&mut rng), E::generate(&mut rng) ],
            old_unsigned: E::SignatureGroup::zero(),
            old_signed: E::SignatureGroup::zero(),
        }
    }

    /// Generate a secret key that is already split for side channel protection.
    pub fn generate<R: Rng>(mut rng: R) -> Self {
        let mut s = Self::generate_dirty(&mut rng);
        s.init_point_mutation(rng);
        s
    }

    /// Create a representative usable for operations lacking 
    /// side channel protections.  
    pub fn into_vartime(&self) -> SecretKeyVT<E> {
        let mut secret = self.key[0].clone();
        secret.add_assign(&self.key[1]);
        SecretKeyVT(secret)
    }

    /// Randomly adjust how we split our secret signing key. 
    //
    // An initial call to this function after deserialization or
    // `into_split_dirty` incurs a miniscule risk from side channel
    // attacks, but then protects the highly vulnerable signing
    // operations.  `into_split` itself hjandles this.
    #[inline(never)]
    pub fn resplit<R: Rng>(&mut self, mut rng: R) {
        // resplit_with(|| Ok(self), rng).unwrap();
        let x = E::generate(&mut rng);
        self.key[0].add_assign(&x);
        self.key[1].sub_assign(&x);
    }

    /// Sign without doing the key resplit mutation that provides side channel protection.
    ///
    /// Avoid using directly without appropriate `replit` calls, but maybe
    /// useful in proof-of-concenpt code, as it does not require a mutable
    /// secret key.
    pub fn sign_once(&mut self, message: Message) -> Signature<E> {
        let mut z = message.hash_to_signature_curve::<E>();
        z.sub_assign(&self.old_unsigned);
        self.old_unsigned = z.clone();
        let mut t = z.clone();
        t.mul_assign(self.key[0]);
        z.mul_assign(self.key[1]);
        z.add_assign(&t);
        let old_signed = self.old_signed.clone();
        self.old_signed = z.clone();
        z.add_assign(&old_signed);
        // s.normalize();   // VRFs are faster if we only normalize once, but no normalize method exists.
        // E::SignatureGroup::batch_normalization(&mut [&mut s]);  
        Signature(z)
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
        let mut publickey = generator.mul(self.key[0]);
        publickey.add_assign( & generator.mul(self.key[1]) );
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


// ////////////// NON-SECRETS ////////////// //

// /////// BEGIN MACROS /////// //

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

macro_rules! compression {
    ($wrapper:tt,$group:tt) => {

impl<E: EngineBLS> $wrapper<E> {
    /// Convert our signature or public key type to its compressed form.
    ///
    /// These compressed forms are wraper types on either a `[u8; 48]` 
    /// or `[u8; 96]` which satisfy `pairing::EncodedPoint` and permit
    /// read access with `AsRef<[u8]>`.
    pub fn compress(&self) -> <<<E as EngineBLS>::$group as CurveProjective>::Affine as CurveAffine>::Compressed {
        self.0.into_affine().into_compressed()
    }

    /// Decompress our signature or public key type from its compressed form.
    ///
    /// These compressed forms are wraper types on either a `[u8; 48]` 
    /// or `[u8; 96]` which satisfy `pairing::EncodedPoint` and permit
    /// creation and write access with `pairing::EncodedPoint::empty()`
    /// and `AsMef<[u8]>`, respectively.
    pub fn decompress(compressed: <<<E as EngineBLS>::$group as CurveProjective>::Affine as CurveAffine>::Compressed) -> Result<Self,GroupDecodingError> {
        Ok($wrapper(compressed.into_affine()?.into_projective()))
    }

    pub fn decompress_from_slice(slice: &[u8]) -> Result<Self,GroupDecodingError> {
        let mut compressed = <<<E as EngineBLS>::$group as CurveProjective>::Affine as CurveAffine>::Compressed::empty();
        if slice.len() != compressed.as_mut().len() {
            // We should ideally return our own error here, but this seems acceptable for now.
            return Err(GroupDecodingError::UnexpectedInformation);
        } // <<<E as EngineBLS>::$group as CurveProjective>::Affine as CurveAffine>::Compressed::size() 
        compressed.as_mut().copy_from_slice(slice);
        $wrapper::<E>::decompress(compressed)
    }
}

    }
}  // macro_rules!


macro_rules! zbls_serialization {
    ($wrapper:tt,$orientation:tt,$size:expr) => {

impl $wrapper<$orientation<::pairing::bls12_381::Bls12>> {
    pub fn to_bytes(&self) -> [u8; $size] {
        let mut bytes = [0u8; $size];
        bytes.copy_from_slice(self.compress().as_ref());
        bytes
    }

    pub fn from_bytes(bytes: [u8; $size]) -> Result<Self,GroupDecodingError> {
        $wrapper::<$orientation<::pairing::bls12_381::Bls12>>::decompress_from_slice(&bytes[..])
    }
}

    }
}  // macro_rules!

// //////// END MACROS //////// //


/// Detached BLS Signature
#[derive(Debug)]
pub struct Signature<E: EngineBLS>(pub E::SignatureGroup);
// TODO: Serialization

broken_derives!(Signature);  // Actually the derive works for this one, not sure why.
// borrow_wrapper!(Signature,SignatureGroup,0);
compression!(Signature,SignatureGroup);
zbls_serialization!(Signature,UsualBLS,96);
zbls_serialization!(Signature,TinyBLS,48);

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
compression!(PublicKey,PublicKeyGroup);
zbls_serialization!(PublicKey,UsualBLS,48);
zbls_serialization!(PublicKey,TinyBLS,96);

impl<E: EngineBLS> PublicKey<E> {
    pub fn verify(&self, message: Message, signature: &Signature<E>) -> bool {
        signature.verify(message,self)
    }
}



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

impl<E: EngineBLS> Clone for KeypairVT<E> {
    fn clone(&self) -> Self { KeypairVT {
        secret: self.secret.clone(),
        public: self.public.clone(),
    } }
}

// TODO: Serialization

impl<E: EngineBLS> KeypairVT<E> {
    /// Generate a `Keypair`
    pub fn generate<R: Rng>(rng: R) -> Self {
        let secret = SecretKeyVT::generate(rng);
        let public = secret.into_public();
        KeypairVT { secret, public }
    }

    /// Convert into a `SecretKey` applying side channel protections.
    pub fn into_split<R: Rng>(&self, rng: R) -> Keypair<E> {
        let secret = self.secret.into_split(rng);
        let public = self.public;
        Keypair { secret, public }
    }

    /// Sign a message creating a `SignedMessage` using a user supplied CSPRNG for the key splitting.
    pub fn sign(&self, message: Message) -> SignedMessage<E> {
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

impl<E: EngineBLS> Clone for Keypair<E> {
    fn clone(&self) -> Self { Keypair {
        secret: self.secret.clone(),
        public: self.public.clone(),
    } }
}

// TODO: Serialization

impl<E: EngineBLS> Keypair<E> {
    /// Generate a `Keypair`
    pub fn generate<R: Rng>(rng: R) -> Self {
        let secret = SecretKey::generate(rng);
        let public = secret.into_public();
        Keypair { secret, public }
    }

    /// Create a representative usable for operations lacking 
    /// side channel protections.  
    pub fn into_vartime(&self) -> KeypairVT<E> {
        let secret = self.secret.into_vartime();
        let public = self.public;
        KeypairVT { secret, public }
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
#[derive(Debug,Clone)]
pub struct SignedMessage<E: EngineBLS> {
    pub message: Message,
    pub publickey: PublicKey<E>,
    pub signature: Signature<E>,
}
// TODO: Serialization

// borrow_wrapper!(Signature,SignatureGroup,signature);
// borrow_wrapper!(PublicKey,PublicKeyGroup,publickey);

impl<E: EngineBLS>  PartialEq<Self> for SignedMessage<E> {
    fn eq(&self, other: &Self) -> bool {
        self.message.eq(&other.message)
        && self.publickey.eq(&other.publickey)
        && self.signature.eq(&other.signature)
    }
}

impl <E: EngineBLS> Eq for SignedMessage<E> {}

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
    #[cfg(test)]
    fn verify_slow(&self) -> bool {
        let g1_one = <E::PublicKeyGroup as CurveProjective>::Affine::one();
        let message = self.message.hash_to_signature_curve::<E>().into_affine();
        E::pairing(g1_one, self.signature.0.into_affine()) == E::pairing(self.publickey.0.into_affine(), message)
    }

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

    #[test]
    fn single_messages() {
        let good = Message::new(b"ctx",b"test message");

        let mut keypair  = Keypair::<ZBLS>::generate(thread_rng());
        let good_sig = keypair.sign(good);
        assert!(good_sig.verify_slow());

        let keypair_vt = keypair.into_vartime();
        assert!( keypair_vt.secret.0 == keypair_vt.into_split(thread_rng()).into_vartime().secret.0 );
        assert!( good_sig == keypair.sign(good) );
        assert!( good_sig == keypair_vt.sign(good) );

        let bad = Message::new(b"ctx",b"wrong message");
        let bad_sig = keypair.sign(bad);
        assert!( bad_sig == keypair.into_vartime().sign(bad) );
        assert!( bad_sig.verify() );

        let another = Message::new(b"ctx",b"another message");
        let another_sig = keypair.sign(another);
        assert!( another_sig == keypair.into_vartime().sign(another) );
        assert!( another_sig.verify() );

        assert!(keypair.public.verify(good, &good_sig.signature),
                "Verification of a valid signature failed!");

        assert!(!keypair.public.verify(good, &bad_sig.signature),
                "Verification of a signature on a different message passed!");
        assert!(!keypair.public.verify(bad, &good_sig.signature),
                "Verification of a signature on a different message passed!");
        assert!(!keypair.public.verify(Message::new(b"other",b"test message"), &good_sig.signature),
                "Verification of a signature on a different message passed!");
    }
}
