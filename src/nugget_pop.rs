//! ## Implementation of ProofofPossion trait for Double BLS public keys using
//! the scheme described in [https://eprint.iacr.org/2022/1611] which also
//! complies with the proof of possession proposed in
//! [draft-irtf-cfrg-bls-signature-05](https://www.ietf.org/archive/id/draft-irtf-cfrg-bls-signature-05.html)

use crate::dual_scalar_mul::DualScalarMultiplication;
use crate::engine::EngineBLS;
use crate::{Message, NuggetSignature, ProofOfPossession, ProofOfPossessionGenerator};

use crate::double_nugget::NuggetDoublePublicKey;
use crate::nugget::{NuggetBLS, NuggetPublicKey};
use crate::serialize::SerializableToBytes;
use crate::single::{Keypair, PublicKey};

use alloc::vec::Vec;
use digest::FixedOutputReset;

use ark_ec::PrimeGroup;
use ark_ff::field_hashers::{DefaultFieldHasher, HashToField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};

/// Proof Of Possession of the secret key as the secret scaler genarting both public
/// keys in G1 and G2 by generating a BLS Signature of public key (in G2)
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct NuggetBLSPoP<E: EngineBLS>(pub E::SignatureGroup);

//The bls proof of possession for single or double public key schemes are the same
impl<E: EngineBLS, H: FixedOutputReset + Default + Clone + 'static>
    ProofOfPossessionGenerator<E, H, NuggetDoublePublicKey<E>, NuggetBLSPoP<E>> for Keypair<E>
where
    E::SignatureGroup: SerializableToBytes + DualScalarMultiplication,
{
    fn generate_pok(&mut self) -> NuggetBLSPoP<E> {
        //We simply classicaly BLS sign public key in G2 based on https://eprint.iacr.org/2022/1611
        let sigma_pop = ProofOfPossessionGenerator::<
            E,
            H,
            NuggetDoublePublicKey<E>,
            NuggetBLSnCPPoP<E>,
        >::generate_pok(self);
        NuggetBLSPoP::<E>(sigma_pop.0 .0)
    }
}

/// Serialization for DoublePublickey
impl<E: EngineBLS> SerializableToBytes for NuggetBLSPoP<E> {
    const SERIALIZED_BYTES_SIZE: usize = E::SIGNATURE_SERIALIZED_SIZE;
}

/// The verification process for verifying both possession of one secret key
/// for two public key is different.
impl<E: EngineBLS, H: FixedOutputReset + Default + Clone + 'static>
    ProofOfPossession<E, H, NuggetDoublePublicKey<E>> for NuggetBLSPoP<E>
{
    /// verify the validity of PoP by performing the following Pairing
    /// e(H_pop(pk_2) + t.g_1, pk_2) = e(sign(H_pop(pk_2))+ t.pk_1, g_2)
    /// we verifying by calling the verify_prepared ⎈function from the
    /// engine.
    fn verify(&self, public_key_of_prover: &NuggetDoublePublicKey<E>) -> bool {
        //First we need to generate our randomness in a way that
        //prover is unable to predict. We assume g1 and g2 are fixed.

        let public_key_as_bytes =
            <E as EngineBLS>::public_key_point_to_byte(&public_key_of_prover.1);
        let public_key_in_signature_group = public_key_of_prover.0;
        let public_key_in_signature_group_as_bytes =
            E::signature_point_to_byte(&public_key_in_signature_group);

        let public_key_hashed_to_signature_group =
            Message::new_pop_message(b"", &public_key_as_bytes).hash_to_signature_curve::<E>();
        let public_key_hashed_to_signature_group_as_bytes =
            E::signature_point_to_byte(&public_key_hashed_to_signature_group);
        let mut random_oracle_seed = Vec::with_capacity(
            public_key_hashed_to_signature_group_as_bytes.len()
                + public_key_as_bytes.len()
                + public_key_in_signature_group_as_bytes.len()
                + E::SIGNATURE_SERIALIZED_SIZE,
        );

        random_oracle_seed.extend_from_slice(&public_key_hashed_to_signature_group_as_bytes);
        random_oracle_seed.extend_from_slice(&public_key_as_bytes);
        random_oracle_seed.extend_from_slice(&public_key_in_signature_group_as_bytes);
        random_oracle_seed.extend_from_slice(&E::signature_point_to_byte(&self.0));

        let hasher = <DefaultFieldHasher<H> as HashToField<
            <<E as EngineBLS>::PublicKeyGroup as PrimeGroup>::ScalarField,
        >>::new(&[]);

        let randomization_coefficient: E::Scalar =
            hasher.hash_to_field::<1>(random_oracle_seed.as_slice())[0];

        let mut randomized_pub_in_g1 = public_key_in_signature_group;
        randomized_pub_in_g1 *= randomization_coefficient;
        let signature = E::prepare_signature(self.0 + randomized_pub_in_g1);
        let public_key_affine: <E as EngineBLS>::PublicKeyGroupAffine =
            public_key_of_prover.1.into();
        if !E::validate_public_key(&public_key_affine) {
            return false;
        }
        let prepared_public_key = E::prepare_public_key(public_key_affine);
        let prepared = [
            (
                prepared_public_key.clone(),
                E::prepare_signature(public_key_hashed_to_signature_group),
            ),
            (
                prepared_public_key.clone(),
                E::prepare_signature(E::generator_of_signature_group() * randomization_coefficient),
            ),
        ];
        E::verify_prepared(signature, prepared.iter())
    }
}

/// Proof Of Possession of the secret key as the secret scaler genarting both public
/// keys in G1 and G2 by generating a BLS Signature of public key (in G2) plus proof
/// of knowledge of the secret key of the chaum-pedersen key (samae secret key)
#[derive(CanonicalSerialize, CanonicalDeserialize)]
pub struct NuggetBLSnCPPoP<E: EngineBLS>(pub NuggetSignature<E>);

//The implement the generation of bls proof of possession including  chaum-pederesno PoP for double public key schemes
impl<E: EngineBLS, H: FixedOutputReset + Default + Clone + 'static>
    ProofOfPossessionGenerator<E, H, NuggetDoublePublicKey<E>, NuggetBLSnCPPoP<E>> for Keypair<E>
where
    E::SignatureGroup: SerializableToBytes + DualScalarMultiplication,
{
    fn generate_pok(&mut self) -> NuggetBLSnCPPoP<E> {
        //We simply classicaly BLS sign public key in G2 based on https://eprint.iacr.org/2022/1611
        let public_key_as_bytes = self.public.to_bytes();
        let sigma_pop = NuggetBLS::<E, E::SignatureGroup>::sign(
            self,
            &Message::new_pop_message(b"", &public_key_as_bytes.as_slice()),
        );

        NuggetBLSnCPPoP::<E>(sigma_pop)
    }
}

/// Serialization for NuggetBLSnCPPoP
impl<E: EngineBLS> SerializableToBytes for NuggetBLSnCPPoP<E> {
    const SERIALIZED_BYTES_SIZE: usize =
        <NuggetSignature<E> as SerializableToBytes>::SERIALIZED_BYTES_SIZE;
}

/// The verification process for verifying both nugget BLS and CP
impl<E: EngineBLS, H: FixedOutputReset + Default + Clone + 'static>
    ProofOfPossession<E, H, NuggetDoublePublicKey<E>> for NuggetBLSnCPPoP<E>
where
    E::SignatureGroup: SerializableToBytes + DualScalarMultiplication,
{
    /// verify the validity of PoP by verifying nugget PoP and the CP
    /// signature
    fn verify(&self, public_key_of_prover: &NuggetDoublePublicKey<E>) -> bool {
        let public_key_in_public_key_group_as_bytes =
            PublicKey::<E>(public_key_of_prover.1).to_bytes();
        //verify double pairing && verify cp
        <NuggetBLSPoP<E> as ProofOfPossession<E, H, NuggetDoublePublicKey<E>>>::verify(
            &NuggetBLSPoP::<E>(self.0 .0),
            public_key_of_prover,
        ) && public_key_of_prover.verify(
            &Message::new_pop_message(b"", &public_key_in_public_key_group_as_bytes.as_slice()),
            &self.0,
        )
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use crate::double_nugget::DoubleNuggetBLS;
    use crate::engine::{EngineBLS, TinyBLS381};
    use crate::serialize::SerializableToBytes;
    use crate::single::Keypair;
    use crate::{nugget_pop::NuggetBLSPoP, NuggetDoublePublicKey};
    use crate::{ProofOfPossession, ProofOfPossessionGenerator};

    use ark_ff::Zero;
    use rand::thread_rng;
    use sha2::Sha256;

    use super::NuggetBLSnCPPoP;

    fn double_bls_pop_sign<
        PoPFlavor: ProofOfPossession<TinyBLS381, Sha256, NuggetDoublePublicKey<TinyBLS381>>,
    >()
    where
        Keypair<TinyBLS381>: ProofOfPossessionGenerator<
            TinyBLS381,
            Sha256,
            NuggetDoublePublicKey<TinyBLS381>,
            PoPFlavor,
        >,
    {
        let mut keypair = Keypair::<TinyBLS381>::generate(thread_rng());
        <Keypair<TinyBLS381> as ProofOfPossessionGenerator<
            TinyBLS381,
            Sha256,
            NuggetDoublePublicKey<TinyBLS381>,
            PoPFlavor,
        >>::generate_pok(&mut keypair);
    }

    #[test]
    fn nugget_bls_pop_sign() {
        double_bls_pop_sign::<NuggetBLSPoP<TinyBLS381>>();
    }

    #[test]
    fn nugget_bls_and_cp_pop_sign() {
        double_bls_pop_sign::<NuggetBLSnCPPoP<TinyBLS381>>();
    }

    fn double_bls_pop_sign_and_verify<
        PoPFlavor: ProofOfPossession<TinyBLS381, Sha256, NuggetDoublePublicKey<TinyBLS381>>,
    >()
    where
        Keypair<TinyBLS381>: ProofOfPossessionGenerator<
            TinyBLS381,
            Sha256,
            NuggetDoublePublicKey<TinyBLS381>,
            PoPFlavor,
        >,
    {
        let mut keypair = Keypair::<TinyBLS381>::generate(thread_rng());
        let proof_pair = <dyn ProofOfPossessionGenerator<
            TinyBLS381,
            Sha256,
            NuggetDoublePublicKey<TinyBLS381>,
            PoPFlavor,
        >>::generate_pok(&mut keypair);
        assert!(
            ProofOfPossession::<TinyBLS381, Sha256, NuggetDoublePublicKey::<TinyBLS381>>::verify(
                &proof_pair,
                &DoubleNuggetBLS::into_nugget_double_public_key(&keypair)
            ),
            "valid pok does not verify"
        );
    }

    #[test]
    fn nugget_bls_pop_sign_and_verify() {
        double_bls_pop_sign_and_verify::<NuggetBLSPoP<TinyBLS381>>();
    }

    #[test]
    fn nugget_bls_and_cp_pop_sign_and_verify() {
        double_bls_pop_sign_and_verify::<NuggetBLSnCPPoP<TinyBLS381>>();
    }

    fn double_bls_pop_of_random_public_key_should_fail<
        PoPFlavor: ProofOfPossession<TinyBLS381, Sha256, NuggetDoublePublicKey<TinyBLS381>>,
    >()
    where
        Keypair<TinyBLS381>: ProofOfPossessionGenerator<
            TinyBLS381,
            Sha256,
            NuggetDoublePublicKey<TinyBLS381>,
            PoPFlavor,
        >,
    {
        let mut keypair_good = Keypair::<TinyBLS381>::generate(thread_rng());
        let proof_pair = <dyn ProofOfPossessionGenerator<
            TinyBLS381,
            Sha256,
            NuggetDoublePublicKey<TinyBLS381>,
            PoPFlavor,
        >>::generate_pok(&mut keypair_good);
        let keypair_bad = Keypair::<TinyBLS381>::generate(thread_rng());
        assert!(
            !ProofOfPossession::<TinyBLS381, Sha256, NuggetDoublePublicKey::<TinyBLS381>>::verify(
                &proof_pair,
                &DoubleNuggetBLS::into_nugget_double_public_key(&keypair_bad)
            ),
            "invalid pok of unrelated public key should not verify"
        );
    }

    #[test]
    fn nugget_bls_pop_of_random_public_key_should_fail() {
        double_bls_pop_of_random_public_key_should_fail::<NuggetBLSPoP<TinyBLS381>>();
    }

    #[test]
    fn nugget_bls_and_cp_pop_of_random_public_key_should_fail() {
        double_bls_pop_of_random_public_key_should_fail::<NuggetBLSnCPPoP<TinyBLS381>>();
    }

    fn pop_of_a_double_public_key_should_serialize_and_deserialize_for_bls12_381<
        PoPFlavor: ProofOfPossession<TinyBLS381, Sha256, NuggetDoublePublicKey<TinyBLS381>>
            + SerializableToBytes,
    >()
    where
        Keypair<TinyBLS381>: ProofOfPossessionGenerator<
            TinyBLS381,
            Sha256,
            NuggetDoublePublicKey<TinyBLS381>,
            PoPFlavor,
        >,
    {
        let mut keypair = Keypair::<TinyBLS381>::generate(thread_rng());

        let proof_pair = <dyn ProofOfPossessionGenerator<
            TinyBLS381,
            Sha256,
            NuggetDoublePublicKey<TinyBLS381>,
            PoPFlavor,
        >>::generate_pok(&mut keypair);

        let serialized_proof = proof_pair.to_bytes();
        let deserialized_proof = PoPFlavor::from_bytes(&serialized_proof).unwrap();

        assert!(
            ProofOfPossession::<TinyBLS381, Sha256, NuggetDoublePublicKey::<TinyBLS381>>::verify(
                &deserialized_proof,
                &DoubleNuggetBLS::into_nugget_double_public_key(&keypair)
            ),
            "valid pok does not verify"
        );
    }

    #[test]
    fn nugget_bls_pop_should_serialize_and_deserialize_for_bls12_381() {
        pop_of_a_double_public_key_should_serialize_and_deserialize_for_bls12_381::<
            NuggetBLSPoP<TinyBLS381>,
        >();
    }

    #[test]
    fn nugget_bls_and_cp_pop_should_serialize_and_deserialize_for_bls12_381() {
        pop_of_a_double_public_key_should_serialize_and_deserialize_for_bls12_381::<
            NuggetBLSnCPPoP<TinyBLS381>,
        >();
    }

    /// A keypair with secret scalar zero and identity public key.
    /// `SecretKeyVT::sign` returns `sk * H(msg) = identity` for such
    /// a keypair, so the PoP produced by `generate_pok` is itself
    /// identity. The pairing equation in `NuggetBLSPoP::verify` then
    /// reduces to `identity == identity`, so without `validate_public_key`
    /// the verifier would accept — rejection here is attributable to
    /// the public key check.
    #[test]
    fn nugget_bls_pop_rejects_identity_pk() {
        use crate::single::{PublicKey, SecretKeyVT};
        let mut keypair = Keypair::<TinyBLS381> {
            public: PublicKey::<TinyBLS381>(
                <TinyBLS381 as EngineBLS>::PublicKeyGroup::zero(),
            ),
            secret: SecretKeyVT::<TinyBLS381>(<TinyBLS381 as EngineBLS>::Scalar::zero())
                .into_split(thread_rng()),
        };
        let pop = <Keypair<TinyBLS381> as ProofOfPossessionGenerator<
            TinyBLS381,
            Sha256,
            NuggetDoublePublicKey<TinyBLS381>,
            NuggetBLSPoP<TinyBLS381>,
        >>::generate_pok(&mut keypair);
        let double_pk = DoubleNuggetBLS::into_nugget_double_public_key(&keypair);
        assert!(!<NuggetBLSPoP<TinyBLS381> as ProofOfPossession<
            TinyBLS381,
            Sha256,
            NuggetDoublePublicKey<TinyBLS381>,
        >>::verify(&pop, &double_pk));
    }
}
