//! ## Implementation of ProofofPossion trait for BLS keys using schnorr sginature
//! ## TODO: I assume this can also moved to pop.rs but for now I put it separately to help reviews
use crate::engine::{EngineBLS};
use crate::pop::{ProofOfPossessionGenerator, ProofOfPossessionVerifier, SchnorrProof};

use crate::single::{SecretKey,PublicKey,Keypair};

use digest::{Digest};

use ark_serialize::{CanonicalSerialize};
use ark_ec::{Group, CurveGroup};
use ark_ff::{PrimeField};

use super::Message;

// TODO: Delete after migration to secret key model
// pub struct BLSSchnorrProof<E: EngineBLS> : trait B: {
//     pub public_key : PublicKey<E>,
//     pub proof_of_possession : SchnorrProof<E>,
// }

/// Generate Schnorr Signature for an arbitrary message using a key ment to use in BLS scheme
trait BLSSchnorrPoPGenerator<E: EngineBLS, H: Digest> : ProofOfPossessionGenerator<E,H> {
    /// Produce a secret witness scalar `k`, aka nonce, from hash of
    /// H( H(s) | H(public_key)) because our key does not have the
    /// randomness redundacy exists in EdDSA secret key.
    fn witness_scalar(&self) -> <<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField;
}

impl<E: EngineBLS, H: Digest> BLSSchnorrPoPGenerator<E,H> for Keypair<E>
{
    //The pseudo random witness is generated similar to eddsa witness
    //hash(secret_key|publick_key)
    fn witness_scalar(&self) -> <<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField {
        let mut secret_key_as_bytes = vec![0;  self.secret.into_vartime().0.compressed_size()];

        let affine_public_key = self.public.0.into_affine();
        let mut public_key_as_bytes = vec![0;  affine_public_key.compressed_size()];

        self.secret.into_vartime().0.serialize_compressed(&mut secret_key_as_bytes[..]).unwrap();
        affine_public_key.serialize_compressed(&mut public_key_as_bytes[..]).unwrap();        
        
        let mut scalar_bytes = <H as Digest>::new().chain_update(secret_key_as_bytes).chain_update(public_key_as_bytes).finalize();
	    let random_scalar : &mut [u8] = scalar_bytes.as_mut_slice();
        <<<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField>::from_be_bytes_mod_order(&*random_scalar)
    }

}

impl<E: EngineBLS, H: Digest> ProofOfPossessionGenerator<E,H> for Keypair<E> {

    //TODO: Message must be equal to public key. 
    fn generate_pok(&self, message: Message) -> SchnorrProof<E> {
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
        let mut r = <dyn BLSSchnorrPoPGenerator<E,H>>::witness_scalar(self);
        
        let mut r_point = <<E as EngineBLS>::PublicKeyGroup as Group>::generator();
        r_point *= r; //todo perhaps we need to mandate E to have  a hard coded point

        let mut r_point_as_bytes : Vec::<u8> = vec![0;  r_point.compressed_size()];
        r_point.serialize_compressed(&mut r_point_as_bytes).unwrap();

        let mut k_as_hash = <H as Digest>::new().chain_update(r_point_as_bytes).chain_update(message.0).finalize();
	    let random_scalar : &mut [u8] = k_as_hash.as_mut_slice();

        let k = <<<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField>::from_be_bytes_mod_order(&*random_scalar);
        let s = (k * self.secret.into_vartime().0) + r;

        ::zeroize::Zeroize::zeroize(&mut r); //clear secret witness from memory

        (s,k)
    }
}

impl<E: EngineBLS, H: Digest> ProofOfPossessionVerifier<E,H> for PublicKey<E> {
    /// verify the validity of schnoor proof for a given publick key by
    /// making sure this is equal to zero
    /// H(+s*G - k*Publkey|M) ==  k  
    fn verify_pok(&self, message: Message, schnorr_proof: SchnorrProof<E>) -> bool {
        let mut schnorr_point = <<E as EngineBLS>::PublicKeyGroup as Group>::generator();
        schnorr_point *= schnorr_proof.0;
        let mut k_public_key = self.0;
        k_public_key *= -schnorr_proof.1;
        schnorr_point += k_public_key;

        let mut schnorr_point_as_bytes = Vec::<u8>::new();
        schnorr_point.into_affine().serialize_compressed(&mut schnorr_point_as_bytes).unwrap();

        let mut scalar_bytes = <H as Digest>::new().chain_update(schnorr_point_as_bytes).chain_update(message.0).finalize();
	    let random_scalar = scalar_bytes.as_mut_slice();

        let witness_scaler = schnorr_proof.1;

        <<<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField>::from_be_bytes_mod_order(random_scalar) == witness_scaler
    }

}

#[cfg(all(test,feature="std"))]
mod tests {
    #[test]
    fn bls_pop_sign() {
        use crate::pop::{ProofOfPossessionGenerator};
        use crate::single::{Keypair};
        use crate::engine::{ZBLS};
        use crate::Message;
        use rand::{thread_rng};
        use sha2::Sha512;    

        let challenge_message = Message::new(b"ctx",b"sign this message, if you really have the secret key");
        let keypair  = Keypair::<ZBLS>::generate(thread_rng());
        <Keypair<ZBLS> as ProofOfPossessionGenerator<ZBLS, Sha512>>::generate_pok(&keypair, challenge_message);
    }

    #[test]
    fn bls_pop_sign_and_verify()
    {
        use rand::{thread_rng};
        use sha2::Sha512;    

        use crate::single::{Keypair};
        use crate::engine::{ZBLS};
        use crate::Message;
        use crate::pop::{ProofOfPossessionGenerator, ProofOfPossessionVerifier};


        let challenge_message = Message::new(b"ctx",b"sign this message, if you really have the secret key");
        let keypair  = Keypair::<ZBLS>::generate(thread_rng());
        let proof_pair = <dyn ProofOfPossessionGenerator<ZBLS, Sha512>>::generate_pok(&keypair, challenge_message);
        assert!(<ProofOfPossessionVerifier<ZBLS, Sha512>>::verify_pok(&keypair.public, challenge_message, proof_pair), "valid pok does not verify")

    }
    
}
