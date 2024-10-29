#[cfg(feature = "std")]
use sha2::Sha256;
#[cfg(feature = "std")]
use w3f_bls::{
    BLSPoP, DoublePublicKey, Keypair, ProofOfPossessionGenerator, SerializableToBytes, TinyBLS,
};

#[cfg(feature = "std")]
use ark_bls12_381::Bls12_381;
#[cfg(feature = "std")]
use rand::thread_rng;

/// Run using
/// ```sh
/// cargo run --example aggregated_with_public_key_in_signature_group.rs
/// ```
fn main() {
    #[cfg(feature = "std")]
    {
        let mut keypair =
            Keypair::<TinyBLS<Bls12_381, ark_bls12_381::Config>>::generate(thread_rng());

        //generate PoP
        let proof_pair = <dyn ProofOfPossessionGenerator<
            TinyBLS<Bls12_381, ark_bls12_381::Config>,
            Sha256,
            DoublePublicKey<TinyBLS<Bls12_381, ark_bls12_381::Config>>,
            BLSPoP<TinyBLS<Bls12_381, ark_bls12_381::Config>>,
        >>::generate_pok(&mut keypair);

        println!(
            "Proof of possession of {:?} is {:?}",
            keypair.public.to_bytes(),
            proof_pair.to_bytes()
        );
    }
}
