//! ## Implementation of ProofofPossion trait for BLS keys using schnorr sginature
//! ## TODO: I assume this can also moved to pop.rs but for now I put it separately to help reviews
use crate::engine::{EngineBLS, ZBLS, UsualBLS}; //{PoP}
use crate::pop::{ProofOfPossessionGenerator, ProofOfPossessionVerifier, SchnorrProof};

use crate::single::{SecretKey,PublicKey};

use digest::{Digest};

use pairing::fields::{Field, PrimeField, SquareRootField};
use pairing::serialize::{CanonicalSerialize};
use pairing::curves::ProjectiveCurve;
use pairing::{One, Zero};

use rand::{Rng, thread_rng, SeedableRng};
use pairing::bytes::{FromBytes, ToBytes};
use sha3::{Shake256};
use sha2::Sha512;

// TODO: Delete after migration to secret key model
// pub struct BLSSchnorrProof<E: EngineBLS> : trait B: {
//     pub public_key : PublicKey<E>,
//     pub proof_of_possession : SchnorrProof<E>,
// }

/// Generate Schnorr Signature for an arbitrary message 
trait BLSSchnorrPoPGenerator<E: EngineBLS, H: Digest> : ProofOfPossessionGenerator<E,H> {
    /// Produce a secret witness scalar `k`, aka nonce, from hash of
    /// H( H(s) | H(public_key)) because our key does not have the
    /// randomness redundacy exists in EdDSA secret key.
    fn witness_scalar(&self) -> <<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::ScalarField;
}

impl<E: EngineBLS, H: Digest> BLSSchnorrPoPGenerator<E,H> for SecretKey<E>
{
    /// TODO: BROKEN NOW Switch to https://github.com/arkworks-rs/algebra/pull/164/files
    fn witness_scalar(&self) -> <<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::ScalarField {
        let mut secret_key_as_bytes = vec![0;  self.into_vartime().0.serialized_size()];

        let mut affine_public_key = self.into_public().0.into_affine();
        let mut public_key_as_bytes = vec![0;  affine_public_key.serialized_size()];

        self.into_vartime().0.serialize(&mut secret_key_as_bytes[..]).unwrap();
        affine_public_key.serialize(&mut public_key_as_bytes[..]).unwrap();        
        
        let secret_key_hash = <H as Digest>::new().chain(secret_key_as_bytes);
        let public_key_hash = <H as Digest>::new().chain(public_key_as_bytes);

        let mut scalar_bytes = <H as Digest>::new().chain(secret_key_hash.finalize()).chain(public_key_hash.finalize()).finalize();
	    let random_scalar : &mut [u8] = scalar_bytes.as_mut_slice();
	    random_scalar[31] &= 31; // BROKEN HACK DO BOT DEPLOY
        <<<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::ScalarField as FromBytes>::read(&*random_scalar).unwrap()
    }

}

impl<E: EngineBLS, H: Digest> ProofOfPossessionGenerator<E,H> for SecretKey<E> {

    fn generate_pok(&self) -> SchnorrProof<E> {
        //First we should figure out the base point in E, I think the secret key trait/struct knows about it.

        //choose random scaler k
        //For now we don't we just use  a trick similar to Ed25519
        //we use hash of concatination of hash the secret key and the public key

        //schnorr equations

        //R = rG.
        //k = H(R|M)
        //s = k*private_key + r
        // publishing (s, R) verifying that (s*G = H(R|M)*Publickey + R
        let mut r = <BLSSchnorrPoPGenerator<E,H>>::witness_scalar(self);
        
        let mut r_point = <<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::prime_subgroup_generator();
        r_point *= r; //todo perhaps we need to mandate E to have  a hard coded point

        let mut r_point_as_bytes = Vec::<u8>::new();
        let mut public_key_as_bytes = Vec::<u8>::new();
        r_point.into_affine().write(&mut r_point_as_bytes);
        self.into_public().0.into_affine().write(&mut public_key_as_bytes);

        //.chain(public_key_as_bytes) M is empty for now
        let mut k_as_hash = <H as Digest>::new().chain(r_point_as_bytes).finalize();
	    let random_scalar : &mut [u8] = k_as_hash.as_mut_slice();
	    random_scalar[31] &= 31; // BROKEN HACK DO BOT DEPLOY

        let k = <<<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::ScalarField as FromBytes>::read(&*random_scalar).unwrap();
        let s = (k * self.into_vartime().0) + r;

        r = E::Scalar::zero();
        //::zeroize::Zeroize::zeroize(&mut r); //clear secret key from memory

        (s,k)
    }
}

impl<E: EngineBLS, H: Digest> ProofOfPossessionVerifier<E,H> for PublicKey<E> {
    /// verify the validity of schnoor proof for a given publick key by
    /// making sure this is equal to zero
    /// H(+s G - k Publkey|M) ==  k  
    fn verify_pok(&self, schnorr_proof: SchnorrProof<E>) -> bool {
        let mut schnorr_point = <<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::prime_subgroup_generator();
        schnorr_point *= schnorr_proof.0;
        let mut k_public_key = self.0;
        k_public_key *= -schnorr_proof.1;
        schnorr_point += k_public_key;

        let mut schnorr_point_as_bytes = Vec::<u8>::new();
        schnorr_point.into_affine().write(&mut schnorr_point_as_bytes);

        let mut scalar_bytes = <H as Digest>::new().chain(schnorr_point_as_bytes).finalize();
	    let random_scalar = scalar_bytes.as_mut_slice();
	    random_scalar[31] &= 31; // BROKEN HACK DO BOT DEPLOY

        let witness_scaler = schnorr_proof.1;

        <<<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::ScalarField as FromBytes>::read(&*random_scalar).unwrap() == witness_scaler
        
    }

}

#[cfg(test)]
use rand_core::{RngCore,CryptoRng};
use crate::single::{Keypair};

mod tests {
    use super::*;
    
    #[test]
    fn bls_pop_sign() {
        let mut keypair  = Keypair::<ZBLS>::generate(thread_rng());
        <ProofOfPossessionGenerator<ZBLS, Sha512>>::generate_pok(&keypair.secret);
    }

    #[test]
    fn bls_pop_sign_and_verify()
    {
        let mut keypair  = Keypair::<ZBLS>::generate(thread_rng());
        let mut secret_key = keypair.secret;
        let proof_pair = <ProofOfPossessionGenerator<ZBLS, Sha512>>::generate_pok(&secret_key);
        assert!(<ProofOfPossessionVerifier<ZBLS, Sha512>>::verify_pok(&keypair.public, proof_pair), "valid pok does not verify")

    }
    
}
