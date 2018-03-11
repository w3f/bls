extern crate pairing;
extern crate rand;

use pairing::{CurveAffine, Engine};
use rand::{Rand, Rng};

const HASH_KEY: &[u8] = b"BLSSignatureSeed";

pub struct Signature<E: Engine> {
    s: E::G1,
}

pub struct SecretKey<E: Engine> {
    x: E::Fr,
}

impl<E: Engine> SecretKey<E> {
    pub fn generate<R: Rng>(csprng: &mut R) -> Self {
        SecretKey {
            x: E::Fr::rand(csprng),
        }
    }

    pub fn sign(&self, message: &[u8]) -> Signature<E> {
        let h = E::G1Affine::hash(HASH_KEY, message);
        Signature { s: h.mul(self.x) }
    }
}

pub struct PublicKey<E: Engine> {
    p_pub: E::G2,
}

impl<E: Engine> PublicKey<E> {
    pub fn from_secret(secret: &SecretKey<E>) -> Self {
        // TODO Decide on projective vs affine
        PublicKey {
            p_pub: E::G2Affine::one().mul(secret.x),
        }
    }

    pub fn verify(&self, message: &[u8], signature: &Signature<E>) -> bool {
        let h = E::G1Affine::hash(HASH_KEY, message);
        let lhs = E::pairing(signature.s, E::G2Affine::one());
        let rhs = E::pairing(h, self.p_pub);
        lhs == rhs
    }
}

pub struct Keypair<E: Engine> {
    pub secret: SecretKey<E>,
    pub public: PublicKey<E>,
}

impl<E: Engine> Keypair<E> {
    pub fn generate<R: Rng>(csprng: &mut R) -> Self {
        let secret = SecretKey::generate(csprng);
        let public = PublicKey::from_secret(&secret);
        Keypair { secret, public }
    }

    pub fn sign(&self, message: &[u8]) -> Signature<E> {
        self.secret.sign(message)
    }

    pub fn verify(&self, message: &[u8], signature: &Signature<E>) -> bool {
        self.public.verify(message, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::Keypair;

    use pairing::bls12_381::Bls12;
    use rand::{SeedableRng, XorShiftRng};

    #[test]
    fn sign_verify() {
        let mut rng = XorShiftRng::from_seed([0xbc4f6d44, 0xd62f276c, 0xb963afd0, 0x5455863d]);

        for i in 0..500 {
            let keypair = Keypair::<Bls12>::generate(&mut rng);
            let message = format!("Message {}", i);
            let sig = keypair.sign(&message.as_bytes());
            assert_eq!(keypair.verify(&message.as_bytes(), &sig), true);
        }
    }
}
