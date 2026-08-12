#[cfg(feature = "std")]
use sha2::Sha256;
#[cfg(feature = "std")]
use w3f_bls::{
    pop_aggregator::SignatureAggregatorAssumingPoP, EngineBLS, Keypair, Message, NuggetBLS,
    PublicKeyInSignatureGroup, TinyBLS, TinyBLS377,
};

#[cfg(feature = "std")]
use ark_bls12_377::Bls12_377;
#[cfg(feature = "std")]
use rand::thread_rng;

/// Run using
/// ```sh
/// cargo run --example aggregated_with_public_key_in_signature_group.rs
/// ```
fn main() {
    #[cfg(feature = "std")]
    {
        type EB = TinyBLS<Bls12_377, ark_bls12_377::Config>;

        let message = Message::new(b"ctx", b"I'd far rather be happy than right any day.");
        let mut keypairs: Vec<_> = (0..3)
            .into_iter()
            .map(|_| Keypair::<TinyBLS<Bls12_377, ark_bls12_377::Config>>::generate(thread_rng()))
            .collect();
        let pub_keys_in_sig_grp: Vec<PublicKeyInSignatureGroup<TinyBLS377>> = keypairs
            .iter()
            .map(|k| NuggetBLS::<_, <EB as EngineBLS>::SignatureGroup>::into_public_key_in_signature_group(k))
            .collect();
        let mut verifier_aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();

        //sign, aggregate, and add (publickey, aux) pairs
        for (k, aux) in keypairs.iter_mut().zip(pub_keys_in_sig_grp.iter()) {
            verifier_aggregator.add_signature(&k.sign(&message));
            verifier_aggregator.add_message_n_publickey(&message, &(k.public, *aux));
        }

        assert!(
            verifier_aggregator.verify_using_aggregated_auxiliary_public_keys::<Sha256>(),
            "verifying with honest auxilary public key should pass"
        );
    }
}
