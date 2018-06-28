
extern crate pairing;
extern crate rand;

use pairing::{CurveAffine, CurveProjective, Engine, Field, PrimeField, SqrtField};
use rand::{Rand, Rng};
use std::collections::HashSet;
use std::marker::PhantomData;


pub trait BLS {
    type Engine: Engine<Fr = Self::Scalar>;
    type Scalar: PrimeField + SqrtField;
    type PublicKeyGroup: 
		CurveProjective<Engine = Self::Engine, Scalar = Self::Scalar>
		+ Into<<Self::PublicKeyGroup as CurveProjective>::Affine>;
    type SignatureGroup: 
		CurveProjective<Engine = Self::Engine, Scalar = Self::Scalar>
		+ Into<<Self::SignatureGroup as CurveProjective>::Affine>;

	fn generate<R: Rng>(csprng: &mut R) -> Self::Scalar {
		Self::Scalar::rand(csprng)
	}
    fn hash_to_curve(message: &[u8]) -> Self::SignatureGroup {
        <Self::SignatureGroup as CurveProjective>::hash(message)
    }
    fn sign(secret: Self::Scalar, message: &[u8]) -> Self::SignatureGroup {
		let mut s = Self::hash_to_curve(message);
		s.mul_assign(secret);
		s
	}

    /// Performs a complete pairing operation `(p, q)`.
    fn pairing<G1, G2>(p: G1, q: G2) -> <Self::Engine as Engine>::Fqk
    where
        G1: Into<<Self::SignatureGroup as CurveProjective>::Affine>,
        G2: Into<<Self::PublicKeyGroup as CurveProjective>::Affine>;

    fn verify_lhs(signature: Self::SignatureGroup) -> <Self::Engine as Engine>::Fqk {
    	Self::pairing(signature, <Self::PublicKeyGroup as CurveProjective>::Affine::one())
    }
    fn verify_rhs(public_key: Self::PublicKeyGroup, message: &[u8]) -> <Self::Engine as Engine>::Fqk {
    	Self::pairing(Self::hash_to_curve(message), public_key)
    }
    fn verify(public_key: Self::PublicKeyGroup, message: &[u8], signature: Self::SignatureGroup) -> bool {
		Self::verify_lhs(signature) == Self::verify_rhs(public_key, message)
    }
}

pub struct FastBLS<E: Engine>(PhantomData<E>);

impl<E: Engine> BLS for FastBLS<E> {
	type Engine = E;
	type Scalar = <Self::Engine as Engine>::Fr;
    type PublicKeyGroup = E::G2;
    type SignatureGroup = E::G1;

    fn pairing<G1, G2>(p: G1, q: G2) -> <E as Engine>::Fqk
    where
        G1: Into<<Self::SignatureGroup as CurveProjective>::Affine>,
        G2: Into<<Self::PublicKeyGroup as CurveProjective>::Affine>,
    {
		E::pairing(p,q)
	}
}

pub struct SlowBLS<E: Engine>(PhantomData<E>);

impl<E: Engine> BLS for SlowBLS<E> {
	type Engine = E;
	type Scalar = <Self::Engine as Engine>::Fr;
    type PublicKeyGroup = E::G1;
    type SignatureGroup = E::G2;

    fn pairing<G1, G2>(p: G1, q: G2) -> <E as Engine>::Fqk
    where
		G1: Into<<Self::SignatureGroup as CurveProjective>::Affine>,
    	G2: Into<<Self::PublicKeyGroup as CurveProjective>::Affine>,
    {
		E::pairing(q,p)
	}
}

pub struct Signature<S: BLS>(S::SignatureGroup);

impl<S: BLS> AsRef<<S as BLS>::SignatureGroup> for Signature<S> {
	fn as_ref(&self) -> &<S as BLS>::SignatureGroup { &self.0 }
}

pub struct SecretKey<S: BLS>(S::Scalar);

pub struct PublicKey<S: BLS>(S::PublicKeyGroup);

impl<S: BLS> SecretKey<S> {
    pub fn generate<R: Rng>(csprng: &mut R) -> Self {
        SecretKey( S::generate(csprng) )
    }

    pub fn sign(&self, message: &[u8]) -> Signature<S> {
		Signature( S::sign(self.0,message) )
    }

	pub fn into_public(&self) -> PublicKey<S> {
        // TODO str4d never decided on projective vs affine here, so check that everywhere
		PublicKey( <S::PublicKeyGroup as CurveProjective>::Affine::one().mul(self.0) )
	}
}

impl<S: BLS> PublicKey<S> {
    pub fn verify(&self, message: &[u8], signature: &Signature<S>) -> bool {
		S::verify(self.0,message,signature.0)
    }
}

/// We should depricate this because public and private keys will not
/// be used together much except in tests.
pub struct Keypair<S: BLS> {
    pub secret: SecretKey<S>,
    pub public: PublicKey<S>,
}

impl<S: BLS> Keypair<S> {
    pub fn generate<R: Rng>(csprng: &mut R) -> Self {
        let secret = SecretKey::generate(csprng);
		let public = secret.into_public();
        Keypair { secret, public }
    }

    pub fn sign(&self, message: &[u8]) -> Signature<S> {
        self.secret.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature<S>) -> bool {
        self.public.verify(message, signature)
    }
}


/// We may aggregate signatures trivially either
/// if the messages are distinct or else 
/// if we checked a proof-of-possision.
///
/// In principle, a proof-of-possision requires another seperate
/// signature verification, which saves no coputation time.
/// There are however dituations in which we may trust that
/// this signature verification happened once in the past,
/// making proof-of-posesion extremely efficent, but doing
/// so risks making our 
pub struct AggregatePoP<S: BLS>(S::SignatureGroup);

impl<S: BLS> AsRef<<S as BLS>::SignatureGroup> for AggregatePoP<S> {
	fn as_ref(&self) -> &<S as BLS>::SignatureGroup { &self.0 }
}

impl<S: BLS> AggregatePoP<S> {
    pub fn new() -> Self {
        AggregatePoP( S::SignatureGroup::zero() )
    }

	/// Construct an initial aggregate signature from other signatures.
	pub fn from_signatures<I,Sig>(sigs: I) -> Self
	where I: IntoIterator<Item = Sig>, Sig: AsRef<<S as BLS>::SignatureGroup>
	{
		let mut s = Self::new();
		for sig in sigs { s.aggregate(sig) }
        s
	}

	/// Aggregate both stand alone and aggregate signatures.
    pub fn aggregate<Sig: AsRef<<S as BLS>::SignatureGroup>>(&mut self, sig: Sig) {
        self.0.add_assign(sig.as_ref());
    }

	/// Compute the RHS of an aggregate signature verification equation,
	/// assuming the protocol verifies proof-of-possesion elsewhere.
    pub fn verify_pop_rhs<'a,I>(message: &[u8], public_keys: I) -> <S::Engine as Engine>::Fqk
	where I: IntoIterator<Item = &'a PublicKey<S>>, S: 'a
	{
		let mut agg_public_key = S::PublicKeyGroup::zero();
		for pk in public_keys { agg_public_key.add_assign(&pk.0); }
		S::verify_rhs(agg_public_key, message)
	}

	/// Verify an aggregate signature on one messages with an 
	/// asigning keys given as an iterator.  
	///
	/// We require the protocol verifies proof-of-possesion elsewhere,
	/// when more than one key is provided.  Otherwise, the signature
	/// scheme is insecure.  Even if used correctly, we reduce signature
	/// security to the proof-of-possesion, which will be fragile, 
	/// meaning it depends on protocol correctness elsehwere.
    pub fn verify_pop_one<'a,I>(&self, message: &[u8], public_keys: I) -> bool
	where I: IntoIterator<Item = &'a PublicKey<S>>, S: 'a
	{
		S::verify_lhs(self.0) == Self::verify_pop_rhs(message, public_keys)
	}

	/// Verify an aggregate signature on an iterator of pairs of messages 
	/// each with another iterator of keys signing each message. 
    /// 
	/// We require the protocol verifies proof-of-possesion elsewhere,
	/// when more than one key is provided.  Otherwise, the signature
	/// scheme is insecure.  Even if used correctly, we reduce signature
	/// security to the proof-of-possesion, which will be fragile, 
	/// meaning it depends on protocol correctness elsehwere.
	///
	/// We require that messages cannot be duplicated but do not detect duplicates,
	/// except by panicing upon noticing adjact duplicates.  You must ensure
	/// duplicates cannot occur ever by refusing to aggregate them, requiring the
	/// signing keys appear in the message, or similar, merely combinging them
	/// before calling this is insecure.
    pub fn verify_pop_unchecked<'a,I,J>(&self, inputs: I) -> bool
	where I: IntoIterator<Item = (&'a [u8], J)>,
	      J: IntoIterator<Item = &'a PublicKey<S>> + 'a, S: 'a
	{
        let mut rhs = <S::Engine as Engine>::Fqk::one();
		let mut o_message : Option<&'a [u8]> = None;
		for (message,public_keys) in inputs.into_iter() {
			if o_message == Some(message) {
				panic!("Internal error: Duplicate message found in aggregate signature, indicating signature aggregation is being used insecurely.");
			} else { o_message = Some(message); }
			rhs.mul_assign( & Self::verify_pop_rhs(message,public_keys) );
		}
		rhs == S::verify_lhs(self.0)
	}

	/// Verify an aggregate signature on an iterator of pairs of messages 
	/// each with another iterator of keys signing each message. 
	/// Enforces message distinctness.
    /// 
	/// We require the protocol verifies proof-of-possesion elsewhere,
	/// when more than one key is provided.  Otherwise, the signature
	/// scheme is insecure.  Even if used correctly, we reduce signature
	/// security to the proof-of-possesion, which will be fragile, 
	/// meaning it depends on protocol correctness elsehwere.
    pub fn verify_pop_distinct(&self, inputs: &[(&[u8],&[PublicKey<S>])]) -> bool
	{
        let messages: HashSet<&[u8]> = inputs.into_iter().map(|&(m, _)| m).collect();
        if messages.len() != inputs.len() {
            return false;
        }
		self.verify_pop_unchecked(inputs.iter().map(
			|&(m,pk)| (m,pk) 
		))
	}
}




#[cfg(test)]
mod tests {
    use super::*;

    use pairing::bls12_381::Bls12;
    use rand::{SeedableRng, XorShiftRng};

	/*
    fn do_hash_speed<S: BLS>() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        for i in 0..128 {
            let message = format!("My silly message is {}", i);
	        assert_ne!(S::hash_to_curve(message.as_bytes()), <S::SignatureGroup as CurveProjective>::one() );
        }
    }

    #[test]
    fn hash_speed_fast() { do_hash_speed::<FastBLS<Bls12>>(); }

    #[test]
    fn hash_speed_slow() { do_hash_speed::<SlowBLS<Bls12>>(); }
	*/

    fn do_sign_verify<S: BLS>() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        for i in 0..128 {
            let keypair = Keypair::<S>::generate(&mut rng);
            let message = format!("My silly message is {}", i);
			let message = message.as_bytes();
            let sig = keypair.sign(message);
            assert!( keypair.verify(message, &sig) );
        }
    }

    #[test]
    fn sign_verify_fast() { do_sign_verify::<FastBLS<Bls12>>(); }

    #[test]
    fn sign_verify_slow() { do_sign_verify::<SlowBLS<Bls12>>(); }

	/*
    fn do_aggregate_one<S: BLS>() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        for i in 0..8 {
            let secretkey = SecretKey::<S>::generate(&mut rng);
            let message = format!("My silly message is {}", i);
			let message = message.as_bytes();
            let sig = secretkey.sign(message);
			assert!( secretkey.into_public().verify(message, &sig) );
			let sigs = AggregatePoP::<S>::from_signatures(&[sig]);
			let input = (message, &[secretkey.into_public()][..]);
            assert!( sigs.verify_pop_distinct(&[input]) );
        }
    }

    #[test]
    fn aggregate_one_fast() { do_aggregate_one::<FastBLS<Bls12>>(); }

    #[test]
    fn aggregate_one_slow() { do_aggregate_one::<SlowBLS<Bls12>>(); }
	*/

    fn do_aggregate_signatures<S: BLS>() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

	    let mut secretkeys = Vec::with_capacity(32);
	    let mut publickeys = Vec::with_capacity(32);
		for _ in 0..32 {
			let secret = SecretKey::<S>::generate(&mut rng);
			publickeys.push( secret.into_public() );
			secretkeys.push( secret );
		}
	    let messages = (0..16).map(
			|i| format!("My silly message {} is {}", i, rng.next_u32())
		).collect::<Vec<_>>();
	    let mut inputs = Vec::with_capacity(256);
        let mut aggregate_signature = AggregatePoP::<S>::new();
		for (i,message) in messages.iter().map(|m| m.as_bytes()).enumerate() {
			inputs.push( (message,&publickeys[i..i+16]) );
			for j in 0..16 {
	            aggregate_signature.aggregate( secretkeys[i+j].sign(message) );

	            // Only test near the beginning and the end, to reduce test runtime
				if (i % 5 == 0 && j == 15) || (i % 3 == 0 && j % 5 == 0) {
					let b = aggregate_signature.verify_pop_distinct( inputs.as_slice() );
	                assert_eq!(b, j == 15);
				}
			}
        }
    }

    #[test]
    fn aggregate_signatures_fast() { do_aggregate_signatures::<FastBLS<Bls12>>(); }

    #[test]
    fn aggregate_signatures_slow() { do_aggregate_signatures::<SlowBLS<Bls12>>(); }

	/* 
    #[test]
    fn aggregate_signatures_duplicated_messages() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        let mut inputs = Vec::new();
        let mut asig = AggregateSignature::new();

        // Create the first signature
        let keypair = Keypair::<Bls12>::generate(&mut rng);
        let message = "My silly first message";
        let signature = keypair.sign(&message.as_bytes());
        inputs.push((keypair.public, message));
        asig.aggregate(&signature);

        // The first "aggregate" signature should pass
        assert_eq!(
            asig.verify(&inputs
                .iter()
                .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                .collect()),
            true
        );

        // Create the second signature
        let keypair = Keypair::<Bls12>::generate(&mut rng);
        let message = "My silly second message";
        let signature = keypair.sign(&message.as_bytes());
        inputs.push((keypair.public, message));
        asig.aggregate(&signature);

        // The second (now-)aggregate signature should pass
        assert_eq!(
            asig.verify(&inputs
                .iter()
                .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                .collect()),
            true
        );

        // Create the third signature, reusing the second message
        let keypair = Keypair::<Bls12>::generate(&mut rng);
        let signature = keypair.sign(&message.as_bytes());
        inputs.push((keypair.public, message));
        asig.aggregate(&signature);

        // The third aggregate signature should fail
        assert_eq!(
            asig.verify(&inputs
                .iter()
                .map(|&(ref pk, ref m)| (pk, m.as_bytes()))
                .collect()),
            false
        );
    }
	*/
}
