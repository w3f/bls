//! ## Implementation of ProofofPossion trait for BLS keys using schnorr sginature
//! ## TODO: I assume this can also moved to pop.rs but for now I put it separately to help reviews
use crate::engine::{EngineBLS, ZBLS, UsualBLS}; //{PoP}
use crate::pop::{ProofOfPossession};
use crate::single::{Keypair,PublicKey};

use digest::{Digest};

use pairing::fields::{Field, PrimeField, SquareRootField};
use pairing::serialize::{CanonicalSerialize};
use pairing::curves::ProjectiveCurve;
use pairing::{One, Zero};

use rand::{Rng, thread_rng, SeedableRng};
use pairing::bytes::{FromBytes, ToBytes};
use sha3::{Shake256};
use sha2::Sha512;

pub struct BLS_Schnorr_Proof<E: EngineBLS>(PublicKey<E>, E::Scalar);

impl<E: EngineBLS> BLS_Schnorr_Proof<E> 
{
    /// Produce a secret witness scalar `k`, aka nonce, from hash of
    /// H( H(s) | H(public_key)) because our key does not have the
    /// randomness redundacy exists in EdDSA secret key.
    fn witness_scalar<H: Digest>(&self, secret_key: E::Scalar, public_key: PublicKey<E>) -> <<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::ScalarField {
        let mut secret_key_as_bytes = vec![0;  secret_key.serialized_size()];

        let mut affine_public_key = public_key.0.into_affine();
        let mut public_key_as_bytes = vec![0;  affine_public_key.serialized_size()];

        secret_key.serialize(&mut secret_key_as_bytes[..]).unwrap();
        affine_public_key.serialize(&mut public_key_as_bytes[..]).unwrap();        
        
        let secret_key_hash = <H as Digest>::new().chain(secret_key_as_bytes);
        let public_key_hash = <H as Digest>::new().chain(public_key_as_bytes);

        let scalar_bytes = <H as Digest>::new().chain(secret_key_hash.finalize()).chain(public_key_hash.finalize()).finalize();
        <<<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::ScalarField as FromBytes>::read(scalar_bytes.as_slice()).unwrap()
    }

}

impl<E: EngineBLS, H: Digest> ProofOfPossession<E,H> for BLS_Schnorr_Proof<E> {

    fn sign_pok(&self, secret_key: E::Scalar, public_key: PublicKey<E>) -> Self::SchnorrProof {
        //First we should figure out the base point in E, I think the secret key trait/struct knows about it.

        //choose random scaler k
        //For now we don't we just use  a trick similar to Ed25519
        //we use hash of concatination of hash the secret key and the public key

        //schnorr equations

        //R = rG.
        //k = H(R|M)
        //s = k*private_key + r
        // publishing (s, R) verifying that (s*G = H(R|M)*Publickey + R
        // publising  (s, k) verifying H(+s G - k Publkey|M) = k
        
        let mut r = self.witness_scalar::<H>(secret_key, public_key);
        
        let mut r_point = <<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::prime_subgroup_generator();
        r_point *= r; //todo perhaps we need to mandate E to have  a hard coded point

        let mut r_point_as_bytes = Vec::<u8>::new();
        let mut public_key_as_bytes = Vec::<u8>::new();
        r_point.into_affine().write(&mut r_point_as_bytes);
        public_key.0.into_affine().write(&mut public_key_as_bytes);
        
        let k_as_hash = <H as Digest>::new().chain(r_point_as_bytes).chain(public_key_as_bytes).finalize();
        let k = <<<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::ScalarField as FromBytes>::read(k_as_hash.as_slice()).unwrap();
        let s = (k * secret_key) + r;

        r = E::Scalar::zero();
        //::zeroize::Zeroize::zeroize(&mut r); //clear secret key from memory

        (s,k)


    }

    fn verify_pok(&self) -> bool {
        unimplemented!();
    }

}

#[cfg(test)]
use rand_core::{RngCore,CryptoRng};

mod tests {
    use super::*;
    
    #[test]
    fn bls_pop_sign() {

        let mut keypair  = Keypair::<ZBLS>::generate(thread_rng());
        let mut secret_key = keypair.secret.into_vartime();
        let mut proof_of_possession = BLS_Schnorr_Proof(keypair.public, secret_key.0);
        <BLS_Schnorr_Proof<_> as ProofOfPossession<_, Sha512>>::sign_pok(&proof_of_possession,secret_key.0, keypair.public);
    }
}
