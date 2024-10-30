#[cfg(feature = "std")]
use sha2::Sha256;
#[cfg(feature = "std")]
use w3f_bls::{
    DoublePublicKey, Keypair, NuggetBLSPoP, NuggetBLSnCPPoP, ProofOfPossessionGenerator,
    SerializableToBytes, TinyBLS381,
};

#[cfg(feature = "std")]
use rand::thread_rng;

/// Run using
/// ```sh
/// cargo run --example aggregated_with_public_key_in_signature_group.rs
/// ```
fn main() {
    #[cfg(feature = "std")]
    {
        let mut keypair = Keypair::<TinyBLS381>::generate(thread_rng());

        //generate BLS only PoP
        let proof_pair = <dyn ProofOfPossessionGenerator<
            TinyBLS381,
            Sha256,
            DoublePublicKey<TinyBLS381>,
            NuggetBLSPoP<TinyBLS381>,
        >>::generate_pok(&mut keypair);

        println!(
            "Nugget BLS Proof of possession of {:?} is {:?}",
            keypair.public.to_bytes(),
            proof_pair.to_bytes()
        );

        //generate BLS and CP PoP
        let proof_pair = <dyn ProofOfPossessionGenerator<
            TinyBLS381,
            Sha256,
            DoublePublicKey<TinyBLS381>,
            NuggetBLSnCPPoP<TinyBLS381>,
        >>::generate_pok(&mut keypair);

        println!(
            "Nugget BLS and CP Proof of possession of {:?} is {:?}",
            keypair.public.to_bytes(),
            proof_pair.to_bytes()
        );
    }
}
