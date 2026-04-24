//! ## Aggregation of BLS signatures using proofs-of-possession
//!
//! In this module, we provide the linear flavor of aggregate
//! BLS signature in which the verifiers has previously checked
//! proofs-of-possession for all public keys.  In other words,
//! we simply add up the signatures because the previously checked
//! proofs-of-possession for all signers prevent rogue key attacks.
//! See the security arguments in The Power of Proofs-of-Possession:
//! Securing Multiparty Signatures against Rogue-Key Attacks
//! by Thomas Ristenpart and Scott Yilek at https://eprint.iacr.org/2007/264.pdf
//!
//! These proof-of-possession are simply self-signed certificates,
//! so a BLS signature by each secret key on its own public key.
//! Importantly, the message for this self-signed certificates
//! must uniquely distinguish the public key for which the signature
//! establishes a proof-of-possession.
//! It follows that each proof-of-possession has a unique message,
//! so distinct message aggregation is optimal for verifying them.
//!
//! In this vein, we note that aggregation under proofs-of-possession
//! cannot improve performance when signers sign distinct messages,
//! so proofs-of-possession help with aggregating votes in a concensus
//! protocol, but should never be used for accounts on a block chain.
//!
//! We assume here that users provide their own data structure for
//! proofs-of-poossession.  We provide more structure for users who
//! one bit per vote in a concensus protocol:  
//! You first verify the proofs-of-possession when building a data
//! structure that holds the voters' keys.  You implement the
//! `ProofsOfPossession` trait for this data strtcuture as well,
//! so that the `BitPoPSignedMessage` type provides a signature
//! data type with reasonable sanity checks.

// Aside about proof-of-possession in the DLOG setting
// https://twitter.com/btcVeg/status/1085490561082183681

use core::borrow::Borrow;
// We use BTreeMap instead of HashMap for no_std compatibility.
use alloc::collections::BTreeMap;

use ark_ff::Zero;

use super::verifiers::{
    verify_using_aggregated_auxiliary_public_keys, verify_with_distinct_messages,
};
use super::*;

use digest::FixedOutputReset;

/// Batch or aggregate BLS signatures with attached messages and
/// signers, for whom we previously checked proofs-of-possession.
///
/// In this type, we provide a high-risk low-level batching and
/// aggregation mechanism that merely adds up signatures under the
/// assumption that all required proofs-of-possession were previously
/// checked.
///
/// We say a signing key has provided a proof-of-possession if the
/// verifier remembers having checked some self-signed certificate
/// by that key.  It's insecure to use this aggregation strategy
/// without first cehcking proofs-of-possession.  In particular
/// it is insecure to use this aggregation strategy when checking
/// proofs-of-possession, and could not improve performance anyways.  
/// Distinct message aggregation is always optimal for checking
/// proofs-of-possession.  Please see the module level doumentation
/// for additional discussion and notes on security.
///
/// We foresee this type primarily being used to batch several
/// `BitPoPSignedMessage`s into one verification.  We do not track
/// aggreggated public keys here, instead merging multiples signers
/// public keys anytime they sign the same message, so this type
/// essentially provides only fast batch verificartion.  
/// In principle, our `add_*` methods suffice for building an actual
/// aggregate signature type.  Yet, normally direct approaches like
/// `BitPoPSignedMessage` work better for aggregation because
/// the `ProofsOfPossession` trait tooling permits both enforce the
/// proofs-of-possession and provide a compact serialization.
/// We see no reason to support serialization for this type as present.
/// message assumptions, or other aggre
///
/// In principle, one might combine proof-of-possession with distinct
/// message assumptions, or other aggregation strategies, when
/// verifiers have only observed a subset of the proofs-of-possession,
/// but this sounds complex or worse fragile.
///
/// TODO: Implement gaussian elimination verification scheme.
use nugget::PublicKeyInSignatureGroup;
use single::PublicKey;

#[derive(Clone)]
pub struct SignatureAggregatorAssumingPoP<E: EngineBLS> {
    messages_n_publickeys: BTreeMap<Message, (PublicKey<E>, PublicKeyInSignatureGroup<E>)>,
    signature: Signature<E>,
}

impl<E: EngineBLS> SignatureAggregatorAssumingPoP<E> {
    pub fn new() -> SignatureAggregatorAssumingPoP<E> {
        SignatureAggregatorAssumingPoP {
            messages_n_publickeys: BTreeMap::new(),
            signature: Signature(E::SignatureGroup::zero()),
        }
    }

    /// Add only a `Signature<E>` to our internal signature.
    pub fn add_signature(&mut self, signature: &Signature<E>) {
        self.signature.0 += &signature.0;
    }

    /// Add a `Message` and public key to our internal data.
    ///
    /// Public keys signing the same message are merged so that each
    /// distinct message ends up paired with a single aggregated key.
    /// If the public key carries an auxiliary key in the signature group,
    /// it is automatically aggregated as well.
    pub fn add_message_n_publickey(&mut self, message: &Message, publickey: &impl GeneralizedBLSPublicKey<E>) {
        let pk = publickey.public_key();
        let aux = publickey.public_key_in_signature_group();
        self.messages_n_publickeys
            .entry(message.clone())
            .and_modify(|(pk0, aux0)| {
                pk0.0 += &pk.0;
                aux0.0 += &aux.0;
            })
            .or_insert((pk, aux));
    }

    /// Add an auxiliary public key for an existing `(message, publickey)` entry.
    /// Used by the verifier to aggregate a public key in the signature group
    /// for a message signed by an already aggregated public key.
    ///
    /// If the message already exists with the same public key, the auxiliary
    /// key is aggregated into the existing entry. If the message does not
    /// exist yet, inserts a new entry.
    ///
    /// Returns an error if the message already exists with a different
    /// public key — the main public key for each message should have been
    /// completely aggregated before calling this function.
    pub fn aggregate_aux_publickey_for_message_n_publickey(
        &mut self,
        message: &Message,
        publickey: &PublicKey<E>,
        aux: &PublicKeyInSignatureGroup<E>,
    ) -> Result<(), &'static str> {
        match self.messages_n_publickeys.get_mut(message) {
            Some((existing_pk, existing_aux)) if existing_pk.0 == publickey.0 => {
                existing_aux.0 += &aux.0;
                Ok(())
            }
            Some(_) => {
                Err("message already exists with a different public key")
            }
            None => {
                self.messages_n_publickeys
                    .insert(message.clone(), (*publickey, *aux));
                Ok(())
            }
        }
    }

    /// Aggregate BLS signatures assuming they have proofs-of-possession.
    ///
    /// Folds in every `(message, publickey)` pair carried by `signed`
    /// and adds its signature to our running total.  Public keys signing
    /// the same message are merged together.
    pub fn aggregate<'a, S>(&mut self, signed: &'a S)
    where
        &'a S: Signed<E = E>,
    {
        let signature = signed.signature();
        for (message, publickey) in signed.messages_and_publickeys() {
            self.add_message_n_publickey(message.borrow(), &publickey);
        }
        self.add_signature(&signature);
    }

    pub fn verify_using_aggregated_auxiliary_public_keys<
        RandomOracle: FixedOutputReset + Default + Clone,
    >(
        &self,
    ) -> bool {
        verify_using_aggregated_auxiliary_public_keys::<E, RandomOracle>(
            self,
            true,
        )
    }
}

impl<'a, E: EngineBLS> Signed for &'a SignatureAggregatorAssumingPoP<E> {
    type E = E;

    type M = &'a Message;
    type PKG = &'a (PublicKey<E>, PublicKeyInSignatureGroup<E>);
    type PKnM = alloc::collections::btree_map::Iter<'a, Message, (PublicKey<E>, PublicKeyInSignatureGroup<E>)>;

    fn messages_and_publickeys(self) -> Self::PKnM {
        self.messages_n_publickeys.iter()
    }

    fn signature(&self) -> Signature<E> {
        self.signature
    }

    fn verify(self) -> bool {
        // We have already aggregated distinct messages, so our distinct
        // message verification code provides reasonable optimizations,
        // except the public keys might not be normalized here.
        // We foresee verification via gaussian elimination being faster,
        // but requires affine keys or normalization.
        verify_with_distinct_messages(self, true)
        // TODO: verify_with_gaussian_elimination(self)
    }
}

#[cfg(test)]
mod tests {

    use crate::EngineBLS;
    use crate::Keypair;
    use crate::Message;
    use crate::TinyBLS;
    use crate::UsualBLS;
    use rand::SeedableRng;
    use rand::rngs::StdRng;
    use sha2::Sha256;

    use ark_bls12_377::Bls12_377;
    use ark_bls12_381::Bls12_381;

    use super::*;

    #[test]
    fn verify_aggregate_single_message_single_signer() {
        let good = Message::new(b"ctx", b"test message");

        let mut keypair =
            Keypair::<UsualBLS<Bls12_381, ark_bls12_381::Config>>::generate(StdRng::from_seed([0u8; 32]));
        let good_sig0 = keypair.sign(&good);
        assert!(good_sig0.verify(&good, &keypair.public));
    }

    #[test]
    fn verify_aggregate_single_message_multi_signers() {
        let good = Message::new(b"ctx", b"test message");

        let mut keypair0 =
            Keypair::<UsualBLS<Bls12_381, ark_bls12_381::Config>>::generate(StdRng::from_seed([0u8; 32]));
        let good_sig0 = keypair0.sign(&good);

        let mut keypair1 =
            Keypair::<UsualBLS<Bls12_381, ark_bls12_381::Config>>::generate(StdRng::from_seed([1u8; 32]));
        let good_sig1 = keypair1.sign(&good);

        let mut aggregated_sigs = SignatureAggregatorAssumingPoP::<
            UsualBLS<Bls12_381, ark_bls12_381::Config>,
        >::new();
        aggregated_sigs.add_signature(&good_sig0);
        aggregated_sigs.add_signature(&good_sig1);

        aggregated_sigs.add_message_n_publickey(&good, &keypair0.public);
        aggregated_sigs.add_message_n_publickey(&good, &keypair1.public);

        assert!(
            aggregated_sigs.verify() == true,
            "good aggregated signature of a single message with multiple key does not verify"
        );
    }

    #[test]
    fn verify_aggregate_multi_messages_single_signer() {
        let good0 = Message::new(b"ctx", b"Tab over Space");
        let good1 = Message::new(b"ctx", b"Space over Tab");

        let mut keypair =
            Keypair::<UsualBLS<Bls12_381, ark_bls12_381::Config>>::generate(StdRng::from_seed([0u8; 32]));

        let good_sig0 = keypair.sign(&good0);
        let good_sig1 = keypair.sign(&good1);

        let mut aggregated_sigs = SignatureAggregatorAssumingPoP::<
            UsualBLS<Bls12_381, ark_bls12_381::Config>,
        >::new();
        aggregated_sigs.add_signature(&good_sig0);
        aggregated_sigs.add_signature(&good_sig1);

        aggregated_sigs.add_message_n_publickey(&good0, &keypair.public);
        aggregated_sigs.add_message_n_publickey(&good1, &keypair.public);

        assert!(
            aggregated_sigs.verify() == true,
            "good aggregated signature of multiple messages with a single key does not verify"
        );
    }

    #[test]
    fn verify_aggregate_multi_messages_multi_signers() {
        let good0 = Message::new(b"ctx", b"in the beginning");
        let good1 = Message::new(b"ctx", b"there was a flying spaghetti monster");

        let mut keypair0 =
            Keypair::<UsualBLS<Bls12_381, ark_bls12_381::Config>>::generate(StdRng::from_seed([0u8; 32]));
        let good_sig0 = keypair0.sign(&good0);

        let mut keypair1 =
            Keypair::<UsualBLS<Bls12_381, ark_bls12_381::Config>>::generate(StdRng::from_seed([1u8; 32]));
        let good_sig1 = keypair1.sign(&good1);

        let mut aggregated_sigs = SignatureAggregatorAssumingPoP::<
            UsualBLS<Bls12_381, ark_bls12_381::Config>,
        >::new();
        aggregated_sigs.add_signature(&good_sig0);
        aggregated_sigs.add_signature(&good_sig1);

        aggregated_sigs.add_message_n_publickey(&good0, &keypair0.public);
        aggregated_sigs.add_message_n_publickey(&good1, &keypair1.public);

        assert!(
            aggregated_sigs.verify() == true,
            "good aggregated signature of multiple messages with multiple keys does not verify"
        );
    }

    #[test]
    fn verify_aggregate_single_message_repetative_signers() {
        let good = Message::new(b"ctx", b"test message");

        let mut keypair =
            Keypair::<UsualBLS<Bls12_381, ark_bls12_381::Config>>::generate(StdRng::from_seed([0u8; 32]));
        let good_sig = keypair.sign(&good);

        let mut aggregated_sigs = SignatureAggregatorAssumingPoP::<
            UsualBLS<Bls12_381, ark_bls12_381::Config>,
        >::new();
        aggregated_sigs.add_signature(&good_sig);
        aggregated_sigs.add_signature(&good_sig);

        aggregated_sigs.add_message_n_publickey(&good, &keypair.public);
        aggregated_sigs.add_message_n_publickey(&good, &keypair.public);

        assert!(
            aggregated_sigs.verify() == true,
            "good aggregate of a repetitive signature does not verify"
        );
    }

    #[test]
    fn aggregate_of_signature_of_a_wrong_message_should_not_verify() {
        let good0 = Message::new(b"ctx", b"Space over Tab");
        let bad1 = Message::new(b"ctx", b"Tab over Space");

        let mut keypair0 =
            Keypair::<UsualBLS<Bls12_381, ark_bls12_381::Config>>::generate(StdRng::from_seed([0u8; 32]));
        let good_sig0 = keypair0.sign(&good0);

        let mut keypair1 =
            Keypair::<UsualBLS<Bls12_381, ark_bls12_381::Config>>::generate(StdRng::from_seed([1u8; 32]));
        let bad_sig1 = keypair1.sign(&bad1);

        let mut aggregated_sigs = SignatureAggregatorAssumingPoP::<
            UsualBLS<Bls12_381, ark_bls12_381::Config>,
        >::new();
        aggregated_sigs.add_signature(&good_sig0);
        aggregated_sigs.add_signature(&bad_sig1);

        aggregated_sigs.add_message_n_publickey(&good0, &keypair0.public);
        aggregated_sigs.add_message_n_publickey(&good0, &keypair1.public);

        assert!(
            aggregated_sigs.verify() == false,
            "aggregated signature of a wrong message should not verify"
        );
    }

    #[test]
    fn test_aggregate_tiny_sigs_and_verify_in_g1() {
        let message = Message::new(b"ctx", b"test message");
        let mut keypairs: Vec<_> = (0..3)
            .into_iter()
            .map(|i| Keypair::<TinyBLS<Bls12_377, ark_bls12_377::Config>>::generate(StdRng::from_seed([i; 32])))
            .collect();
        let pub_keys_in_sig_grp: Vec<PublicKeyInSignatureGroup<TinyBLS377>> = keypairs
            .iter()
            .map(|k| {
                nugget::NuggetBLS::<
                    TinyBLS<Bls12_377, ark_bls12_377::Config>,
                    <TinyBLS<Bls12_377, ark_bls12_377::Config> as EngineBLS>::SignatureGroup,
                >::into_public_key_in_signature_group(k)
            })
            .collect();

        // Prover: knows individual keys, aggregates signatures and (pk, aux) pairs.
        let mut prover_aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();

        for (k, aux) in keypairs.iter_mut().zip(pub_keys_in_sig_grp.iter()) {
            prover_aggregator.add_signature(&k.sign(&message));
            prover_aggregator.add_message_n_publickey(&message, &(k.public, *aux));
        }

        assert!(
            prover_aggregator.verify_using_aggregated_auxiliary_public_keys::<Sha256>(),
            "prover: verifying with honest auxilary public key should pass"
        );

        // Verifier: receives aggregated signature + per-message aggregated pk
        // from the prover, then adds individual aux keys separately.
        let mut verifier_aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();
        verifier_aggregator.add_signature(&(&prover_aggregator).signature());

        for (msg, (pk, _aux)) in (&prover_aggregator).messages_and_publickeys() {
            verifier_aggregator.add_message_n_publickey(msg, pk);
        }

        let aggregated_pk = (&prover_aggregator).messages_and_publickeys().next().unwrap().1.0;
        for aux in &pub_keys_in_sig_grp {
            verifier_aggregator
                .aggregate_aux_publickey_for_message_n_publickey(&message, &aggregated_pk, aux)
                .expect("public key should match");
        }

        assert!(
            verifier_aggregator.verify_using_aggregated_auxiliary_public_keys::<Sha256>(),
            "verifier: verifying with honest auxilary public key should pass"
        );

        // Verifier with wrong aux: signer 1's aux used in place of signer 0's.
        let mut bad_verifier = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();
        bad_verifier.add_signature(&(&prover_aggregator).signature());
        for (msg, (pk, _aux)) in (&prover_aggregator).messages_and_publickeys() {
            bad_verifier.add_message_n_publickey(msg, pk);
        }
        bad_verifier
            .aggregate_aux_publickey_for_message_n_publickey(&message, &aggregated_pk, &pub_keys_in_sig_grp[1])
            .unwrap();
        bad_verifier
            .aggregate_aux_publickey_for_message_n_publickey(&message, &aggregated_pk, &pub_keys_in_sig_grp[1])
            .unwrap();
        bad_verifier
            .aggregate_aux_publickey_for_message_n_publickey(&message, &aggregated_pk, &pub_keys_in_sig_grp[2])
            .unwrap();

        assert!(
            !bad_verifier.verify_using_aggregated_auxiliary_public_keys::<Sha256>(),
            "verifier: non-matching auxilary public key should fail"
        );

        // Verifier tries to add aux with an individual signer's pk instead of
        // the aggregated pk — should error because the message already has a
        // different (aggregated) public key.
        let mut mismatched_verifier = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();
        mismatched_verifier.add_signature(&(&prover_aggregator).signature());
        mismatched_verifier.add_message_n_publickey(&message, &aggregated_pk);

        let result = mismatched_verifier.aggregate_aux_publickey_for_message_n_publickey(
            &message,
            &keypairs[0].public, // individual pk, not the aggregated one
            &pub_keys_in_sig_grp[0],
        );
        assert!(
            result.is_err(),
            "aggregate_aux should error when public key does not match existing entry"
        );
    }

    #[test]
    fn test_aggregate_tiny_sigs_multi_messages_and_verify_in_g1() {
        let messages: Vec<Message> = (0..3)
            .map(|i| Message::new(b"ctx", &[b'm', b'0' + i as u8]))
            .collect();
        let mut keypairs: Vec<_> = (0..3)
            .map(|i| Keypair::<TinyBLS<Bls12_377, ark_bls12_377::Config>>::generate(StdRng::from_seed([i; 32])))
            .collect();
        let pub_keys_in_sig_grp: Vec<PublicKeyInSignatureGroup<TinyBLS377>> = keypairs
            .iter()
            .map(|k| {
                nugget::NuggetBLS::<
                    TinyBLS<Bls12_377, ark_bls12_377::Config>,
                    <TinyBLS<Bls12_377, ark_bls12_377::Config> as EngineBLS>::SignatureGroup,
                >::into_public_key_in_signature_group(k)
            })
            .collect();

        // Prover: each signer signs their own distinct message.
        let mut prover_aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();

        for ((k, m), aux) in keypairs.iter_mut().zip(messages.iter()).zip(pub_keys_in_sig_grp.iter()) {
            prover_aggregator.add_signature(&k.sign(m));
            prover_aggregator.add_message_n_publickey(m, &(k.public, *aux));
        }

        assert!(
            prover_aggregator.verify_using_aggregated_auxiliary_public_keys::<Sha256>(),
            "prover: multi-message aggregate with honest auxilary public keys should pass"
        );

        // Verifier: receives aggregated data from prover, adds aux keys separately.
        // Collect per-message (msg, pk, aux) from the prover to preserve association.
        let prover_entries: Vec<_> = (&prover_aggregator)
            .messages_and_publickeys()
            .map(|(m, (pk, aux))| (m.clone(), *pk, *aux))
            .collect();

        let mut verifier_aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();
        verifier_aggregator.add_signature(&(&prover_aggregator).signature());

        for (msg, pk, _) in &prover_entries {
            verifier_aggregator.add_message_n_publickey(msg, pk);
        }

        for (msg, pk, aux) in &prover_entries {
            verifier_aggregator
                .aggregate_aux_publickey_for_message_n_publickey(msg, pk, aux)
                .expect("public key should match");
        }

        assert!(
            verifier_aggregator.verify_using_aggregated_auxiliary_public_keys::<Sha256>(),
            "verifier: multi-message aggregate with honest auxilary public keys should pass"
        );

        // Verifier with wrong aux: rotate aux keys so each entry gets the wrong one.
        let mut bad_verifier = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();
        bad_verifier.add_signature(&(&prover_aggregator).signature());
        for (msg, pk, _) in &prover_entries {
            bad_verifier.add_message_n_publickey(msg, pk);
        }
        for (i, (msg, pk, _)) in prover_entries.iter().enumerate() {
            let wrong_aux = &prover_entries[(i + 1) % prover_entries.len()].2;
            bad_verifier
                .aggregate_aux_publickey_for_message_n_publickey(msg, pk, wrong_aux)
                .unwrap();
        }

        assert!(
            !bad_verifier.verify_using_aggregated_auxiliary_public_keys::<Sha256>(),
            "verifier: non-matching auxilary public key should fail"
        );
    }

    #[test]
    fn test_aggregate_tiny_sigs_with_mislabeled_message_fails_verification_in_g1() {
        // Each signer signs its real message, but in the verifier we
        // deliberately pair every signer's public key with the *wrong*
        // message (rotated by one).  The aggregated signature is honest,
        // yet the (message, publickey) bookkeeping the verifier consumes
        // is a lie, so verification must fail.
        let real_messages: Vec<Message> = (0..3)
            .map(|i| Message::new(b"ctx", &[b'm', b'0' + i as u8]))
            .collect();
        let mut keypairs: Vec<_> = (0..3)
            .map(|i| Keypair::<TinyBLS<Bls12_377, ark_bls12_377::Config>>::generate(StdRng::from_seed([i; 32])))
            .collect();
        let pub_keys_in_sig_grp: Vec<PublicKeyInSignatureGroup<TinyBLS377>> = keypairs
            .iter()
            .map(|k| {
                nugget::NuggetBLS::<
                    TinyBLS<Bls12_377, ark_bls12_377::Config>,
                    <TinyBLS<Bls12_377, ark_bls12_377::Config> as EngineBLS>::SignatureGroup,
                >::into_public_key_in_signature_group(k)
            })
            .collect();

        // Prover: signs real messages honestly.
        let mut prover_aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();
        for ((i, k), aux) in keypairs.iter_mut().enumerate().zip(pub_keys_in_sig_grp.iter()) {
            prover_aggregator.add_signature(&k.sign(&real_messages[i]));
            prover_aggregator.add_message_n_publickey(&real_messages[i], &(k.public, *aux));
        }

        // Verifier: receives aggregated data from prover but pairs keys with wrong messages.
        let prover_entries: Vec<_> = (&prover_aggregator)
            .messages_and_publickeys()
            .map(|(m, (pk, _))| (m.clone(), *pk))
            .collect();

        let mut verifier_aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();
        verifier_aggregator.add_signature(&(&prover_aggregator).signature());

        // Deliberately rotate messages so each pk is paired with the wrong one.
        for (i, (_msg, pk)) in prover_entries.iter().enumerate() {
            let wrong_message = &real_messages[(i + 1) % real_messages.len()];
            verifier_aggregator.add_message_n_publickey(wrong_message, pk);
        }
        for (i, (_msg, pk)) in prover_entries.iter().enumerate() {
            let wrong_message = &real_messages[(i + 1) % real_messages.len()];
            verifier_aggregator
                .aggregate_aux_publickey_for_message_n_publickey(wrong_message, pk, &pub_keys_in_sig_grp[i])
                .expect("public key should match");
        }

        assert!(
            !verifier_aggregator.verify_using_aggregated_auxiliary_public_keys::<Sha256>(),
            "verification must fail when public keys are paired with the wrong messages"
        );
    }
}
