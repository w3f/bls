//! ## Implementation of ProofofPossion trait for BLS keys using schnorr sginature
//! ## TODO: I assume this can also moved to pop.rs but for now I put it separately to help reviews
use crate::engine::{EngineBLS, ZBLS, UsualBLS}; //{PoP}
use crate::pop::{ProofOfPossession, SchnorrProof};

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

pub struct BLSSchnorrProof<E: EngineBLS>{
    pub public_key : PublicKey<E>,
    pub proof_of_possession : SchnorrProof<E>,
}

impl<E: EngineBLS> BLSSchnorrProof<E> 
{
    /// Produce a secret witness scalar `k`, aka nonce, from hash of
    /// H( H(s) | H(public_key)) because our key does not have the
    /// randomness redundacy exists in EdDSA secret key.
    ///
    /// TODO: BROKEN NOW Switch to https://github.com/arkworks-rs/algebra/pull/164/files
    fn witness_scalar<H: Digest>(&self, secret_key: E::Scalar) -> <<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::ScalarField {
        let mut secret_key_as_bytes = vec![0;  secret_key.serialized_size()];

        let mut affine_public_key = self.public_key.0.into_affine();
        let mut public_key_as_bytes = vec![0;  affine_public_key.serialized_size()];

        secret_key.serialize(&mut secret_key_as_bytes[..]).unwrap();
        affine_public_key.serialize(&mut public_key_as_bytes[..]).unwrap();        
        
        let secret_key_hash = <H as Digest>::new().chain(secret_key_as_bytes);
        let public_key_hash = <H as Digest>::new().chain(public_key_as_bytes);

        let mut scalar_bytes = <H as Digest>::new().chain(secret_key_hash.finalize()).chain(public_key_hash.finalize()).finalize();
	let random_scalar : &mut [u8] = scalar_bytes.as_mut_slice();
	random_scalar[31] &= 127; // BROKEN HACK DO BOT DEPLOY
        <<<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::ScalarField as FromBytes>::read(&*random_scalar).unwrap()
    }

}

impl<E: EngineBLS, H: Digest> ProofOfPossession<E,H> for BLSSchnorrProof<E> {

    fn generate_pok(&self, secret_key: E::Scalar) -> SchnorrProof<E> {
        //First we should figure out the base point in E, I think the secret key trait/struct knows about it.

        //choose random scaler k
        //For now we don't we just use  a trick similar to Ed25519
        //we use hash of concatination of hash the secret key and the public key

        //schnorr equations

        //R = rG.
        //k = H(R|M)
        //s = k*private_key + r
        // publishing (s, R) verifying that (s*G = H(R|M)*Publickey + R
        
        let mut r = self.witness_scalar::<H>(secret_key);
        
        let mut r_point = <<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::prime_subgroup_generator();
        r_point *= r; //todo perhaps we need to mandate E to have  a hard coded point

        let mut r_point_as_bytes = Vec::<u8>::new();
        let mut public_key_as_bytes = Vec::<u8>::new();
        r_point.into_affine().write(&mut r_point_as_bytes);
        self.public_key.0.into_affine().write(&mut public_key_as_bytes);
        
        let mut k_as_hash = <H as Digest>::new().chain(r_point_as_bytes).chain(public_key_as_bytes).finalize();
	let random_scalar : &mut [u8] = k_as_hash.as_mut_slice();
	random_scalar[31] &= 127; // BROKEN HACK DO BOT DEPLOY

        let k = <<<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::ScalarField as FromBytes>::read(&*random_scalar).unwrap();
        let s = (k * secret_key) + r;

        r = E::Scalar::zero();
        //::zeroize::Zeroize::zeroize(&mut r); //clear secret key from memory

        (s,k)
    }

    /// verify the validity of schnoor proof for a given publick key by
    /// making sure this is equal to zero
    /// H(+s G - k Publkey|M) ==  k  
    fn verify_pok(schnorr_proof: SchnorrProof<E>, public_key: PublicKey<E>) -> bool {
        let mut schnorr_point = <<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::prime_subgroup_generator();
        schnorr_point *= schnorr_proof.0;
        schnorr_point += public_key.0;
        let mut schnorr_point_as_bytes = Vec::<u8>::new();
        schnorr_point.into_affine().write(&mut schnorr_point_as_bytes);

        let mut scalar_bytes = <H as Digest>::new().chain(schnorr_point_as_bytes).finalize();
	let random_scalar = scalar_bytes.as_mut_slice();
	random_scalar[31] &= 127; // BROKEN HACK DO BOT DEPLOY

        let witness_scaler = schnorr_proof.1;

        <<<E as EngineBLS>::PublicKeyGroup as ProjectiveCurve>::ScalarField as FromBytes>::read(&*random_scalar).unwrap() == witness_scaler
        
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
        let mut proof_of_possession = BLSSchnorrProof{ public_key : keypair.public, proof_of_possession: (<ZBLS as EngineBLS>::Scalar::zero(),<ZBLS as EngineBLS>::Scalar::zero())};
        <BLSSchnorrProof<ZBLS> as ProofOfPossession<ZBLS, Sha512>>::generate_pok(&proof_of_possession, secret_key.0);
    }

    #[test]
    fn bls_pop_sign_and_verify()
    {
        let mut keypair  = Keypair::<ZBLS>::generate(thread_rng());
        let mut secret_key = keypair.secret.into_vartime();
        let mut proof_of_possession = BLSSchnorrProof{ public_key : keypair.public, proof_of_possession: (<ZBLS as EngineBLS>::Scalar::zero(),<ZBLS as EngineBLS>::Scalar::zero())};
        let mut proof_pair = <BLSSchnorrProof<ZBLS> as ProofOfPossession<ZBLS, Sha512>>::generate_pok(&proof_of_possession, secret_key.0);
        assert!(<BLSSchnorrProof<_> as ProofOfPossession<_, Sha512>>::verify_pok(proof_pair, proof_of_possession.public_key), "valid pok does not verify")
        

    }
}
