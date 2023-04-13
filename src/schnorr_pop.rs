//! ## Implementation of ProofofPossion trait for BLS keys using schnorr sginature
//! ## TODO: I assume this can also moved to pop.rs but for now I put it separately to help reviews
use crate::engine::EngineBLS;
use crate::{ProofOfPossessionGenerator, ProofOfPossessionVerifier};

use crate::serialize::SerializableToBytes;
use crate::single::{Keypair, PublicKey};

use digest::Digest;

use ark_ec::Group;
use ark_ff::PrimeField;

pub type SchnorrProof<E> = (<E as EngineBLS>::Scalar, <E as EngineBLS>::Scalar);
// }
/// Generate Schnorr Signature for an arbitrary message using a key ment to use in BLS scheme
trait BLSSchnorrPoPGenerator<E: EngineBLS, H: Digest>: ProofOfPossessionGenerator<E, H> {
    /// Produce a secret witness scalar `k`, aka nonce, from hash of
    /// H( H(s) | H(public_key)) because our key does not have the
    /// randomness redundacy exists in EdDSA secret key.
    fn witness_scalar(&self) -> <<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField;
}

impl<E: EngineBLS, H: Digest> BLSSchnorrPoPGenerator<E, H> for Keypair<E> {
    //The pseudo random witness is generated similar to eddsa witness
    //hash(secret_key|publick_key)
    fn witness_scalar(&self) -> <<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField {
        let secret_key_as_bytes = self.secret.to_bytes();
        let public_key_as_bytes = <E as EngineBLS>::public_key_point_to_byte(&self.public.0);

        let mut scalar_bytes = <H as Digest>::new()
            .chain_update(secret_key_as_bytes)
            .chain_update(public_key_as_bytes)
            .finalize();

        let random_scalar: &mut [u8] = scalar_bytes.as_mut_slice();
        <<<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField>::from_be_bytes_mod_order(
            &*random_scalar,
        )
    }
}

impl<E: EngineBLS, H: Digest> ProofOfPossessionGenerator<E, H> for Keypair<E> {
    //TODO: Message must be equal to public key.
    fn generate_pok(&self) -> SchnorrProof<E> {
        //First we should figure out the base point in E, I think the secret key trait/struct knows about it.

        //choose random scaler k
        //For now we don't we just use a trick similar to Ed25519
        //we use hash of concatination of hash the secret key and the public key

        //schnorr equations

        //R = rG.
        //k = H(R|M)
        //s = k*private_key + r
        // publishing (s, R) verifying that (s*G = H(R|M)*Publickey + R => H(R|M)*Publickey + R - s*G = 0)
        // so either we need to two into_affine and one curve addition or or two curve additions.
        // instead we actually doing H(s*G - H(R|M)*Publickey|M) == H(R|M) == k
        // avoiding one curve addition (or two field divisions) in expense of a hash.
        let mut r = <dyn BLSSchnorrPoPGenerator<E, H>>::witness_scalar(self);

        let mut r_point = <<E as EngineBLS>::PublicKeyGroup as Group>::generator();
        r_point *= r; //todo perhaps we need to mandate E to have  a hard coded point

        let r_point_as_bytes = <E as EngineBLS>::public_key_point_to_byte(&r_point);
        let public_key_as_bytes = <E as EngineBLS>::public_key_point_to_byte(&self.public.0); //it *must* be the public key (fixed) otherwise secret key can be recovered from the two different proves

        let mut k_as_hash = <H as Digest>::new()
            .chain_update(r_point_as_bytes)
            .chain_update(public_key_as_bytes)
            .finalize();
        let random_scalar: &mut [u8] = k_as_hash.as_mut_slice();

        let k = <<<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField>::from_be_bytes_mod_order(
            &*random_scalar,
        );
        let s = (k * self.secret.into_vartime().0) + r;

        ::zeroize::Zeroize::zeroize(&mut r); //clear secret witness from memory

        (s, k)
    }
}

impl<E: EngineBLS, H: Digest> ProofOfPossessionVerifier<E, H> for PublicKey<E> {
    /// verify the validity of schnoor proof for a given publick key by
    /// making sure this is equal to zero
    /// H(+s*G - k*Publkey|M) ==  k  
    fn verify_pok(&self, schnorr_proof: SchnorrProof<E>) -> bool {
        let mut schnorr_point = <<E as EngineBLS>::PublicKeyGroup as Group>::generator();
        schnorr_point *= schnorr_proof.0;
        let mut k_public_key = self.0;
        k_public_key *= -schnorr_proof.1;
        schnorr_point += k_public_key;

        let schnorr_point_as_bytes = <E as EngineBLS>::public_key_point_to_byte(&schnorr_point);
        let public_key_as_bytes = <E as EngineBLS>::public_key_point_to_byte(&self.0); //it *must* be the public key (fixed) otherwise secret key can be recovered from the two different proves

        let mut scalar_bytes = <H as Digest>::new()
            .chain_update(schnorr_point_as_bytes)
            .chain_update(public_key_as_bytes)
            .finalize();

        let random_scalar =
            <<<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField>::from_be_bytes_mod_order(
                scalar_bytes.as_mut_slice(),
            );
        random_scalar == schnorr_proof.1
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    #[test]
    fn bls_pop_sign() {
        use crate::engine::ZBLS;
        use crate::single::Keypair;
        use crate::ProofOfPossessionGenerator;
        use rand::thread_rng;
        use sha2::Sha512;

        let keypair = Keypair::<ZBLS>::generate(thread_rng());
        <Keypair<ZBLS> as ProofOfPossessionGenerator<ZBLS, Sha512>>::generate_pok(&keypair);
    }

    #[test]
    fn bls_pop_sign_and_verify() {
        use rand::thread_rng;
        use sha2::Sha512;

        use crate::engine::ZBLS;
        use crate::single::Keypair;
        use crate::{ProofOfPossessionGenerator, ProofOfPossessionVerifier};

        let keypair = Keypair::<ZBLS>::generate(thread_rng());
        let proof_pair = <dyn ProofOfPossessionGenerator<ZBLS, Sha512>>::generate_pok(&keypair);
        assert!(
            <dyn ProofOfPossessionVerifier<ZBLS, Sha512>>::verify_pok(&keypair.public, proof_pair),
            "valid pok does not verify"
        )
    }
}
