//! ## Implementation of ProofofPossion trait for BLS keys using schnorr sginature
//! ## TODO: I assume this can also moved to pop.rs but for now I put it separately to help reviews
use crate::engine::{EngineBLS}; //{PoP}
use crate::pop::{ProofOfPossession};

use digest::{Digest};

pub struct BLS_Schnorr_Proof<E: EngineBLS>(E::PublicKeyGroup, E::Scalar);

impl<E: EngineBLS>  BLS_Schnorr_Proof<E> 
{
    /// Produce a secret witness scalar `k`, aka nonce, from hash of
    /// H( H(s) | H(public_key)) because our key does not have the
    /// randomness redundacy exists in EdDSA secret key.
    fn witness_scalar<H: Digest>(&self, secret_key: E::Scalar, public_key: E::Scalar) -> E::Scalar {
        let secret_key_hash = H::new().chain(secret_key);

        let scalar_bytes =  H::new.chain(secret_key_hash).chain(public_key);
        Self::E::Scalar::from_bytes_mod_order_wide(&scalar_bytes)
    }

}

impl<E: EngineBLS, H: Digest> ProofOfPossession<E,H> for BLS_Schnorr_Proof<E> {

    fn sign_pok(&self, secret_key: E::Scalar, public_key: Self::PublicKey) -> Self::SchnorrProof {
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
        
        let mut r = self.witness_scalar(secret_key, public_key); 
        let R = r.mul_assign(public_key.one()); //todo perhaps we need to mandate E to have  a hard coded point

        let k_as_hash = Self::H::new().chain(R.as_bytes()).chain(public_key);
        let k = Self::E::Scalar::from_bytes_mod_order_wide(k_as_hash);
        let s: Self::E::Scalar = &(&k * &secret_key) + &r;

        ::zeroize::Zeroize::zeroize(&mut r);

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
        let mut proof_of_possession = BLS_Schnorr_Proof(keypair_vt.pubkey, keypair_vt.secret);
        proof_of_possession.sign_pok(keypair_vt.secret, keypair_vt.pubkey);
    }
}
