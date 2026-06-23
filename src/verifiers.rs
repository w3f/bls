//! ## Algorithms for optimized verification of aggregate and batched BLS signatures.
//!
//!
//!

use core::borrow::Borrow;

// We use BTreeMap instead of HashMap for no_std compatibility.
use alloc::collections::BTreeMap;
use ark_ec::AffineRepr;
use ark_ff::{field_hashers::{DefaultFieldHasher, HashToField}};
use ark_serialize::CanonicalSerialize;
use digest::FixedOutputReset;

use ark_ec::CurveGroup;

use alloc::vec;
use alloc::vec::Vec;

use super::*;

// We define these convenience type alias here instead of engine.rs
// because seemingly only verifier implementations really employ them.
// And we `pub use engine::*` in lib.rs.

/// Convenience type alias for projective form of `PublicKeyGroup`
pub type PublicKeyProjective<E> = <E as EngineBLS>::PublicKeyGroup;

/// Convenience type alias for affine form of `PublicKeyGroup`
pub type PublicKeyAffine<E> = <<E as EngineBLS>::PublicKeyGroup as CurveGroup>::Affine;

/// Convenience type alias for projective form of `SignatureGroup`
pub type SignatureProjective<E> = <E as EngineBLS>::SignatureGroup;

/// Convenience type alias for affine form of `SignatureGroup`
pub type SignatureAffine<E> = <<E as EngineBLS>::SignatureGroup as CurveGroup>::Affine;

// ── Shared helpers ──────────────────────────────────────────────────

/// Verify from fully normalized (affine) inputs.
/// All public keys, messages, and the signature must already be in affine form.
/// This prepares the pairing inputs and calls `verify_prepared`.
///
/// Rejects an empty `(publickeys, messages)` pairing set: with no
/// signers, `verify_prepared` reduces to `e(-g1, sig) == 1`, which
/// any identity signature satisfies. IETF `CoreAggregateVerify`
/// mandates `n ≥ 1`; we enforce the same here.
fn verify_normalized<E: EngineBLS>(
    affine_publickeys: &[PublicKeyAffine<E>],
    affine_messages: &[SignatureAffine<E>],
    affine_signature: SignatureAffine<E>,
) -> bool {
    if affine_publickeys.is_empty() {
        return false;
    }
    if !E::verify_signature_in_signature_subgroup(&affine_signature) {
        return false;
    }
    let prepared_sig = E::prepare_signature(affine_signature);
    let mut prepared = Vec::with_capacity(affine_publickeys.len());
    for (pk, m) in affine_publickeys.iter().zip(affine_messages) {
        if !E::verify_public_key_in_public_key_subgroup(pk) {
            return false;
        }
        prepared.push((E::prepare_public_key(*pk), E::prepare_signature(*m)));
    }
    E::verify_prepared(prepared_sig, prepared.iter())
}

/// Collect messages and public keys from a `Signed` value, hashing
/// messages to the signature curve.
///
/// We call `messages_and_publickeys()` only once to support unstable iterators.
fn collect_messages_and_publickeys<S: Signed>(
    s: S,
) -> (
    SignatureProjective<S::E>,
    Vec<PublicKeyProjective<S::E>>,
    Vec<SignatureProjective<S::E>>,
) {
    let signature = s.signature().0;
    // We could write this more idiomatically using iterator adaptors,
    // and avoiding an unecessary allocation for publickeys, but only
    // by calling self.messages_and_publickeys() repeatedly.
    let itr = s.messages_and_publickeys();
    let l = {
        let (lower, upper) = itr.size_hint();
        upper.unwrap_or(lower)
    };
    let mut publickeys = Vec::with_capacity(l);
    let mut messages = Vec::with_capacity(l);
    for (message, publickey) in itr {
        publickeys.push(publickey.public_key().0);
        messages.push(message.borrow().hash_to_signature_curve::<S::E>());
    }
    (signature, publickeys, messages)
}

/// Accumulate message points that share the same signer, reducing the
/// number of pairings needed for verification.
///
/// We could avoid the allocation here if we sorted both arrays in
/// parallel.  This might mean (a) some sort function using
/// `ops::IndexMut` instead of slices, and (b) wrapper types to make
/// tuples of slices satisfy `ops::IndexMut`.
// TODO:  Impl PartialEq, Eq, Hash for pairing::EncodedPoint
// to avoid  struct H(E::PublicKeyGroup::Affine::Uncompressed);
fn merge_by_signer<E: EngineBLS>(
    affine_publickeys: Vec<PublicKeyAffine<E>>,
    messages: Vec<SignatureProjective<E>>,
) -> (Vec<PublicKeyAffine<E>>, Vec<SignatureProjective<E>>) {
    type PkMsg<E> = (PublicKeyAffine<E>, SignatureProjective<E>);
    let mut pks_n_ms: BTreeMap<Vec<u8>, PkMsg<E>> = BTreeMap::new();
    for (pk, m) in affine_publickeys.into_iter().zip(messages) {
        let mut pk_bytes = vec![0; pk.uncompressed_size()];
        pk.serialize_uncompressed(&mut pk_bytes[..]).unwrap();
        pks_n_ms
            .entry(pk_bytes)
            .and_modify(|(_, m0)| *m0 += m)
            .or_insert((pk, m));
    }
    pks_n_ms.into_values().unzip()
}

/// Like `merge_by_signer` but keyed on `(public_key, aux_public_key)`.
/// Only message points are merged for entries sharing the same signer pair.
/// returns `None` if the same public key appears with conflicting auxiliary
/// keys.
fn merge_by_signer_with_aux<E: EngineBLS>(
    affine_publickeys: Vec<PublicKeyAffine<E>>,
    aux_keys: Vec<SignatureProjective<E>>,
    messages: Vec<SignatureProjective<E>>,
) -> Option<(
    Vec<PublicKeyAffine<E>>,
    Vec<SignatureAffine<E>>,
    Vec<SignatureProjective<E>>,
)> {
    type PkAuxMsg<E> = (
        PublicKeyAffine<E>,
        SignatureAffine<E>,
        SignatureProjective<E>,
    );
    let mut map: BTreeMap<Vec<u8>, PkAuxMsg<E>> = BTreeMap::new();
    for ((pk, aux), m) in affine_publickeys
        .into_iter()
        .zip(aux_keys)
        .zip(messages)
    {
        let aux_affine = aux.into_affine();
        let mut pk_bytes = vec![0; pk.uncompressed_size()];
        pk.serialize_uncompressed(&mut pk_bytes[..]).unwrap();
        match map.entry(pk_bytes) {
            alloc::collections::btree_map::Entry::Occupied(mut e) => {
                let (_, existing_aux, existing_msg) = e.get_mut();
                if *existing_aux != aux_affine {
                    return None;
                }
                *existing_msg += m;
            }
            alloc::collections::btree_map::Entry::Vacant(e) => {
                e.insert((pk, aux_affine, m));
            }
        }
    }
    let mut pks = Vec::with_capacity(map.len());
    let mut auxs = Vec::with_capacity(map.len());
    let mut msgs = Vec::with_capacity(map.len());
    for (pk, aux, m) in map.into_values() {
        pks.push(pk);
        auxs.push(aux);
        msgs.push(m);
    }
    Some((pks, auxs, msgs))
}

/// Batch-normalize projective public keys, or convert to affine individually
/// when they are already expected to be normalized.
fn normalize_publickeys<E: EngineBLS>(
    publickeys: &[PublicKeyProjective<E>],
    batch_normalize: bool,
) -> Vec<PublicKeyAffine<E>> {
    if batch_normalize {
        E::PublicKeyGroup::normalize_batch(publickeys)
    } else {
        publickeys.iter().map(|pk| pk.into_affine()).collect()
    }
}


/// Batch-normalize message points together with the aggregate signature,
/// returning the affine messages and the affine signature separately.
// TODO: Assess if we could cache normalized message hashes anyplace
// using interior mutability, but probably this does not work well
// with our optimization of collecting messages with the same signer.
fn normalize_messages_and_signature<E: EngineBLS>(
    mut messages: Vec<SignatureProjective<E>>,
    signature: SignatureProjective<E>,
) -> (Vec<SignatureAffine<E>>, SignatureAffine<E>) {
    messages.push(signature);
    let mut affine = E::SignatureGroup::normalize_batch(&messages);
    let signature = affine.pop().unwrap();
    (affine, signature)
}

// ── Public verification functions ───────────────────────────────────

/// Simple unoptimized BLS signature verification.  Useful for testing.
///
/// Rejects an empty `(message, publickey)` set — see `verify_normalized`
/// for the rationale.
pub fn verify_unoptimized<S: Signed>(s: S) -> bool {
    let affine_signature = s.signature().0.into();
    if !S::E::verify_signature_in_signature_subgroup(&affine_signature) {
        return false;
    }
    let signature = S::E::prepare_signature(affine_signature);
    let mut prepared = Vec::new();
    for (message, public_key) in s.messages_and_publickeys() {
        let pk_affine: PublicKeyAffine<S::E> = public_key.public_key().0.into();
        if !S::E::verify_public_key_in_public_key_subgroup(&pk_affine) {
            return false;
        }
        prepared.push((
            S::E::prepare_public_key(pk_affine),
            S::E::prepare_signature(message.borrow().hash_to_signature_curve::<S::E>()),
        ));
    }
    if prepared.is_empty() {
        return false;
    }
    S::E::verify_prepared(signature, prepared.iter())
}

/// Simple universal BLS signature verification
///
/// We support an unstable `Signed::messages_and_publickeys()`
/// securely by calling it only once and batch normalizing all
/// points, as do most other verification routines here.
/// We do no optimizations that reduce the number of pairings
/// by combining repeated messages or signers.
pub fn verify_simple<S: Signed>(s: S) -> bool {
    let (signature, publickeys, messages) = collect_messages_and_publickeys(s);
    let affine_pks = PublicKeyProjective::<S::E>::normalize_batch(&publickeys);
    let (affine_msgs, affine_sig) =
        normalize_messages_and_signature::<S::E>(messages, signature);
    verify_normalized::<S::E>(&affine_pks, &affine_msgs, affine_sig)
}

/// BLS signature verification optimized for all unique messages
///
/// Assuming all messages are distinct, the minimum number of pairings
/// is the number of unique signers, which we achieve here.
/// We do not verify message uniqueness here, but leave this to the
/// aggregate signature type, like `DistinctMessages`.
///
/// We merge any messages with identical signers and batch normalize
/// message points and the signature itself.
/// We optionally batch normalize the public keys in the event that
/// they are provided by algerbaic operaations, but this sounds
/// unlikely given our requirement that messages be distinct.
pub fn verify_with_distinct_messages<S: Signed>(signed: S, normalize_public_keys: bool) -> bool {
    // We first hash the messages to the signature curve and
    // normalize the public keys to operate on them as bytes.
    let (signature, publickeys, messages) = collect_messages_and_publickeys(signed);
    let affine_publickeys = normalize_publickeys::<S::E>(&publickeys, normalize_public_keys);

    // We next accumulate message points with the same signer.
    let (merged_pks, merged_msgs) = merge_by_signer::<S::E>(affine_publickeys, messages);

    // And verify the aggregate signature.
    let (affine_msgs, affine_sig) =
        normalize_messages_and_signature::<S::E>(merged_msgs, signature);
    verify_normalized::<S::E>(&merged_pks, &affine_msgs, affine_sig)
}

/// BLS signature verification optimized for all unique messages
/// with auxiliary public keys.
///
/// Similar to `verify_with_distinct_messages` but for each merged
/// (signer, message) entry, derives a per-entry pseudo-random scalar
/// and folds the auxiliary key contribution into the message point
/// and signature.
///
/// Each `t_i` is derived from a global transcript that covers the
/// aggregated signature and every merged `(message, apk1, apk2)`
/// triple, so any change to one entry changes every `t_i`:
///
/// ```text
/// transcript = asig || (m_1 || apk1_1 || apk2_1) || ... || (m_n || apk1_n || apk2_n)
/// t_1 = H(transcript)
/// t_i = H(transcript || i)        for i >= 2
/// ```
///
/// `apk1_i` is the auxiliary public key (in the signature group),
/// `apk2_i` is the public key (in the public-key group).
///
/// **Entry ordering is part of the spec.** Entries `1..=n` are emitted
/// in **ascending lexicographic order of the affine, uncompressed
/// serialization of `apk2_i`** (the public key). This is the order
/// imposed by `merge_by_signer_with_aux`'s internal `BTreeMap` keyed
/// on `pk.serialize_uncompressed(..)`. Prover and verifier must both
/// follow this canonical ordering — otherwise their `t_i` indices
/// disagree and verification fails on honest inputs. The merge step
/// also collapses any entries sharing the same `apk2` into a single
/// transcript slot (with summed messages and a shared `apk1`).
// e(asig + \sum_i ( t_i*apk1_i) , g_2) = \sum_i (e(H(m_i) + (t_i*g_1), apk2_i))
pub fn verify_using_aggregated_auxiliary_public_keys<
    S: Signed,
    H: FixedOutputReset + Default + Clone,
>(
    signed: S,
    normalize_public_keys: bool,
) -> bool {
    let mut signature = signed.signature().0;

    let mut signature_as_bytes = vec![0; signature.compressed_size()];
    signature
        .serialize_compressed(&mut signature_as_bytes[..])
        .expect("compressed size has been alocated");

    let itr = signed.messages_and_publickeys();
    let l = {
        let (lower, upper) = itr.size_hint();
        upper.unwrap_or(lower)
    };

    // Collect public keys, auxiliary keys, and message points.
    let mut publickeys = Vec::with_capacity(l);
    let mut aux_keys = Vec::with_capacity(l);
    let mut messages = Vec::with_capacity(l);
    for (m, pk) in itr {
        publickeys.push(pk.public_key().0);
        aux_keys.push(pk.public_key_in_signature_group().0);
        messages.push(m.borrow().hash_to_signature_curve::<S::E>());
    }

    let affine_publickeys = normalize_publickeys::<S::E>(&publickeys, normalize_public_keys);

    // Merge message points that share the same signer.
    // Returns None if same public key appears with conflicting aux keys.
    let (merged_pks, merged_aux, mut merged_msgs) = match
        merge_by_signer_with_aux::<S::E>(affine_publickeys, aux_keys, messages)
    {
        Some(v) => v,
        None => return false,
    };

    let hasher =
        <DefaultFieldHasher<H> as HashToField<<S::E as EngineBLS>::Scalar>>::new(&[]);

    // Build the transcript once:
    //   asig || (msg_1 || apk1_1 || apk2_1) || ... || (msg_n || apk1_n || apk2_n)
    // We affine-batch the message points up front because the per-entry
    // loop below mutates `merged_msgs`, so we cannot read their values
    // again after we have started folding in the `t_i * g_1` terms.
    let n = merged_pks.len();
    let affine_merged_msgs =
        <<S::E as EngineBLS>::SignatureGroup as CurveGroup>::normalize_batch(&merged_msgs);

    let entry_size = 2 * <S::E as EngineBLS>::SIGNATURE_SERIALIZED_SIZE
        + <S::E as EngineBLS>::PUBLICKEY_SERIALIZED_SIZE;
    let transcript_size =
        <S::E as EngineBLS>::SIGNATURE_SERIALIZED_SIZE + n * entry_size;
    // Reserve a little extra for the per-entry index suffix used by t_i (i >= 2).
    let mut seed = Vec::with_capacity(transcript_size + core::mem::size_of::<u64>());
    seed.extend_from_slice(&signature_as_bytes);
    for i in 0..n {
        affine_merged_msgs[i]
            .serialize_compressed(&mut seed)
            .expect("compressed size known");
        merged_aux[i]
            .serialize_compressed(&mut seed)
            .expect("compressed size known");
        merged_pks[i]
            .serialize_compressed(&mut seed)
            .expect("compressed size known");
    }
    let transcript_len = seed.len();

    for i in 0..n {
        // t_1 hashes the bare transcript; t_i for i >= 2 appends the
        // 1-based index so each scalar is domain-separated by position
        // while still binding the whole transcript.
        seed.truncate(transcript_len);
        if i > 0 {
            let index = (i as u64) + 1;
            seed.extend_from_slice(&index.to_be_bytes());
        }

        let pseudo_random_scalar: <S::E as EngineBLS>::Scalar =
            hasher.hash_to_field::<1>(&seed[..])[0];

        signature += merged_aux[i] * pseudo_random_scalar;
        merged_msgs[i] +=
            <S::E as EngineBLS>::SignatureGroupAffine::generator() * pseudo_random_scalar;
    }

    // And verify the aggregate signature.
    let (affine_msgs, affine_sig) =
        normalize_messages_and_signature::<S::E>(merged_msgs, signature);
    // `verify_normalized` runs `verify_public_key_in_public_key_subgroup`
    // on every entry of `merged_pks`. That subgroup check is critical for
    // this scheme: the auxiliary-key construction binds each per-entry
    // aux key to the corresponding signer via the pseudo-random scalar,
    // . A public key that sits outside the prime-order subgroup would
    // let an attacker choose an aux key with a small-subgroup component
    // that cancels against the mismatched public-key component in the
    // pairing, forging a matching aggregated aux key and passing
    // verification. Do not drop it.
    verify_normalized::<S::E>(&merged_pks, &affine_msgs, affine_sig)
}

/*
/// Excessively optimized BLS signature verification
///
/// We minimize the number of pairing operations by doing two
/// basis change operation using Gaussian elimination, first in the
/// message space and then in the signer space.  As a result, we
/// do only `1 + min(msg_d,pk_d)` pairings where `msg_d` and `pk_d`
/// are the numbers of distinct messages and signers, respectively.
///
/// We expect this to improve performance dramatically when both
/// signers and messages are repeated enough, simpler strategies
/// work as well or better when say messages are distinct.
///
/// Explination:
///
/// We consider the bipartite graph with vertex sets given by points
/// on the two curves and edges given by desired pairings between them.
/// We let $M$ denote the bipartite adjacency matrix for this graph,
/// so that multiplying $M$ on the the right and left by the vectors
/// of messages and signers respectively reproduces our original sum
/// of pairings.
///
/// We first use elementary "row" operations to make $M$ upper
/// triangular, as in Gaussian elimination, but at the cost of also
/// performing one-sided "change of basis" operations that collect
/// our original "basis vectors" into sums of curve points.
/// We next use elementary "column" operations to make $M$ diagonal,
/// again adjusting the basis with curve point operations.
///
/// In this, we regard $M$ as a matrix over the scalar field $F_p$
/// so we may do row or column swaps and row or column addition
/// operations with small scalars, but not lone row or column scalar
/// multiplication because these always involve divisions, which
/// produces large curve points that slow us down thereafter.
/// We do not require such divisions because we do not solve any
/// system of equations and do not need ones on the diagonal.
///
/// TODO:
/// We leave implementing this optimization to near future work
/// because it benifits from public keys being affine or having
/// another hashable representation.
///
///
/// As a curiosity, we note one interesting but suboptimal algorithm
/// that avoids small scalar multiplications when doing this:
///
/// If we ignore subtraction, then the minimal number of pairing
/// operations required to verify aggregated BLS signatures is the
/// minimal bipartite edge cover, aka bipartite dimension, of the
/// bipartite graph with vertices given by points on the two curves
/// and edges given by desired pairings.
/// In general, this problem is NP-hard even to approximate.
/// See:  https://en.wikipedia.org/wiki/Bipartite_dimension
///
/// There are polynomial time algorithms for bipartite edge cover in
/// special cases, with domino-free graphs being among the widest
/// known classes.  See:
/// Amilhastre, Jérôme; Janssen, Philippe; Vilarem, Marie-Catherine,
/// "Computing a minimum biclique cover is polynomial for bipartite domino-free graphs" (1997)
/// https://core.ac.uk/download/pdf/82546650.pdf
///
/// If we now exploit subtraction, then these dominos can be
/// completed into $K_{3,3}$s, like
///  $(a,x)+(a,y)+(b,x)+(b,y)+(b,z)+(c,y)+(c,z) = (a+b+c,x+y+z) - (a,z) - (c,z)$
/// which looks optimal for itself, and likely permits the further
/// aggregation, and maybe the subtracted terms can be aggregated later.
///
/// We could not however find the optimal numbers of pairings by
/// completing dominos like this because (a+b+c,x+y+z) - (b,y),
/// which looks optimal for itself, but only has one subtraction.
fn verify_with_gaussian_elimination<S: Signed>(s: S) -> bool {
    unimplemented!()
}

*/

#[cfg(test)]
mod tests {
    use super::*;
    use crate::single::SignedMessage;
    use crate::{Keypair, Message, PublicKey, Signature, UsualBLS};
    use ark_bls12_381::{Bls12_381, Fq, Fq2, G1Affine, G2Affine};
    use ark_ec::{AffineRepr, CurveGroup, PrimeGroup};
    use ark_ff::{BitIteratorBE, PrimeField, UniformRand};
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    type EB = UsualBLS<Bls12_381, ark_bls12_381::Config>;

    /// Multiply `point` by an integer `scalar` (big-endian limbs) using
    /// plain double-and-add over the curve. We deliberately bypass the
    /// `Group::mul_bigint` path because arkworks' BLS12-381 curves use a
    /// GLV-optimized scalar multiplication that decomposes the scalar
    /// modulo `r`. For a point `P` outside the prime-order subgroup the
    /// GLV identity `ϕ(P) = λ·P` does not hold, and any scalar that is
    /// `0 mod r` would also reduce away, breaking the cofactor-projection
    /// arithmetic we rely on below. Bit-by-bit double-and-add computes
    /// `scalar·P` as a literal integer multiple on the curve.
    fn mul_by_int_no_glv<G: PrimeGroup + Copy, S: AsRef<[u64]>>(point: G, scalar: S) -> G {
        let mut result = G::zero();
        for b in BitIteratorBE::without_leading_zeros(scalar) {
            result.double_in_place();
            if b {
                result += point;
            }
        }
        result
    }

    /// Sample a random point on E(Fq), then multiply by `r`. This kills
    /// the r-torsion component and leaves a point in the cofactor
    /// subgroup G1[h₁]. Such a point pairs to 1 with any G2[r] element
    /// under the optimal-ate pairing — so attaching it to a public key
    /// shifts the key out of the prime-order subgroup *without disturbing
    /// the verification equation*. The subgroup check is therefore the
    /// only thing that can reject inputs built from it.
    fn cofactor_subgroup_g1() -> G1Affine {
        let mut rng = StdRng::from_seed([42u8; 32]);
        let r = <ark_bls12_381::Fr as PrimeField>::MODULUS;
        loop {
            let x = Fq::rand(&mut rng);
            let Some(point) = G1Affine::get_point_from_x_unchecked(x, false) else {
                continue;
            };
            let projected = mul_by_int_no_glv(point.into_group(), r).into_affine();
            if !projected.is_zero() {
                return projected;
            }
        }
    }

    /// G2 analogue of `cofactor_subgroup_g1`: a point in `E'(Fq²)[h₂]`,
    /// obtained by multiplying a random `E'(Fq²)` point by `r` to clear
    /// the r-torsion component.
    ///
    /// **Asymmetry with the G1 case.** Unlike the G1 cofactor point,
    /// this one does **not** pair to 1 with `G1[r]` under optimal-ate pairing.
    /// For BLS12-381's sextic twist, `E'(Fq²)` has order exactly `r·h₂`
    /// with `gcd(r, h₂) = 1`, so `E'(Fq²)[r]` is cyclic of order `r` and
    /// equals G2 itself — there is no Fq²-rational "anti-G2" subspace.
    /// The other ψ-eigenspace of `E'[r]` lives in `E'(Fq¹²)` and cannot
    /// be represented as a `G2Affine`. Consequently, the cofactor-attack
    /// shape `e(g1, q_g2) = 1` simply does not hold on the G2 side of
    /// BLS12-381: a non-G2 candidate in `E'(Fq²)` either fails the
    /// subgroup check **or** produces a non-trivial Fq¹² residue through
    /// the pairing.
    ///
    /// The point produced here still drives the rejection tests: it sits
    /// outside `E'(Fq²)[r]` (because `[r]·random` retains the h₂-cofactor
    /// component) and is rejected by `verify_signature_in_signature_subgroup`.
    /// The pairing equation would also reject it, so on the G2 side the
    /// subgroup check is belt-and-braces, in contrast to the G1 side
    /// where it is the sole defence.
    fn cofactor_subgroup_g2() -> G2Affine {
        let mut rng = StdRng::from_seed([43u8; 32]);
        let r = <ark_bls12_381::Fr as PrimeField>::MODULUS;
        loop {
            let x = Fq2::rand(&mut rng);
            let Some(point) = G2Affine::get_point_from_x_unchecked(x, false) else {
                continue;
            };
            let projected = mul_by_int_no_glv(point.into_group(), r).into_affine();
            if !projected.is_zero() {
                return projected;
            }
        }
    }

    /// Build a `SignedMessage` whose public key carries a G1-cofactor
    /// component. Under optimal-ate `e(Q_g1, ·) = 1`, so the pairing
    /// equation still balances — an unprotected verifier accepts. The
    /// G1 subgroup check is the only thing that catches this.
    ///
    /// Construction (E = UsualBLS, PK in G1, sig in G2):
    ///   pk'  = sk · (g1 + Q_g1) = pk + sk · Q_g1   with Q_g1 ∈ G1[h₁]
    ///   sig' = sk · H(m)                          (unchanged)
    fn signed_with_g1_cofactor_pk() -> SignedMessage<EB> {
        let message = Message::new(b"ctx", b"test message");
        let mut keypair = Keypair::<EB>::generate(StdRng::from_seed([0u8; 32]));
        let signed = keypair.signed_message(&message);
        let sk = keypair.into_vartime().secret.0;

        let q_g1: <EB as EngineBLS>::PublicKeyGroup = cofactor_subgroup_g1().into();
        let bad_pk = q_g1 * sk + signed.publickey.0;

        SignedMessage {
            message: signed.message,
            publickey: PublicKey::<EB>(bad_pk),
            signature: signed.signature,
        }
    }

    /// Build a `SignedMessage` whose signature carries a G2-cofactor
    /// component. Unlike the G1 case the pairing equation does **not**
    /// remain balanced (see `cofactor_subgroup_g2` for why), so on
    /// BLS12-381 this attack would be rejected by `verify_prepared` even
    /// without the subgroup check. It still drives the rejection tests
    /// because the subgroup check trips first.
    ///
    /// Construction:
    ///   pk'  = sk · g1                            (unchanged)
    ///   sig' = sk · (H(m) + Q_g2) = sig + sk · Q_g2   with Q_g2 ∈ E'(Fq²)[h₂]
    fn signed_with_g2_cofactor_sig() -> SignedMessage<EB> {
        let message = Message::new(b"ctx", b"test message");
        let mut keypair = Keypair::<EB>::generate(StdRng::from_seed([0u8; 32]));
        let signed = keypair.signed_message(&message);
        let sk = keypair.into_vartime().secret.0;

        let q_g2: <EB as EngineBLS>::SignatureGroup = cofactor_subgroup_g2().into();
        let bad_sig = q_g2 * sk + signed.signature.0;

        SignedMessage {
            message: signed.message,
            publickey: signed.publickey,
            signature: Signature::<EB>(bad_sig),
        }
    }

    #[test]
    fn verify_simple_single_signature() {
        let good = Message::new(b"ctx", b"test message");
        let mut keypair = Keypair::<EB>::generate(StdRng::from_seed([0u8; 32]));
        let signed = keypair.signed_message(&good);
        assert!(verify_simple(&signed));
    }

    #[test]
    fn verify_simple_rejects_wrong_message() {
        let good = Message::new(b"ctx", b"test message");
        let bad = Message::new(b"ctx", b"wrong message");
        let mut keypair = Keypair::<EB>::generate(StdRng::from_seed([0u8; 32]));
        let sig = keypair.sign(&good);
        let wrong_signed = single::SignedMessage {
            message: bad,
            publickey: keypair.public,
            signature: sig,
        };
        assert!(!verify_simple(&wrong_signed));
    }

    #[test]
    fn verify_unoptimized_single_signature() {
        let good = Message::new(b"ctx", b"test message");
        let mut keypair = Keypair::<EB>::generate(StdRng::from_seed([0u8; 32]));
        let signed = keypair.signed_message(&good);
        assert!(verify_unoptimized(&signed));
    }

    /// Sanity check that `e(Q_g1, g2_gen) = 1`: this is the mathematical
    /// basis for the G1-side cofactor attack — without it the G1
    /// rejection tests would have no meaning.
    ///
    /// We do **not** assert the symmetric `e(g1_gen, Q_g2) = 1`. For
    /// BLS12-381's sextic twist no such non-trivial `Q_g2 ∈ E'(Fq²)`
    /// exists (see `cofactor_subgroup_g2`); the G2 rejection tests
    /// succeed because the subgroup check **and** the pairing equation
    /// independently reject the doctored input, not because of a
    /// pair-to-1 property.
    #[test]
    fn cofactor_points_pair_to_one() {
        use ark_ec::pairing::Pairing;
        let q_g1 = cofactor_subgroup_g1();
        let g2_gen = G2Affine::generator();
        let p1 = Bls12_381::pairing(q_g1, g2_gen);
        if !p1.0.is_one() {
            eprintln!("e(Q_g1, g2_gen) = {:?} (expected 1)", p1.0);
        }
        assert!(p1.0.is_one(), "e(Q_g1, g2_gen) != 1");
    }

    /// With only the G1-cofactor component spliced into the public key,
    /// the underlying pairing equation still balances (because
    /// `e(Q_g1, ·) = 1`). `verify_prepared`, which performs no subgroup
    /// validation, accepts. This proves the high-level verifier
    /// rejections below are attributable solely to the subgroup checks,
    /// not to broken pairing math.
    #[test]
    fn verify_prepared_accepts_cofactor_components() {
        let bad = signed_with_g1_cofactor_pk();
        let prepared_pk = <EB as EngineBLS>::prepare_public_key(bad.publickey.0);
        let prepared_msg = <EB as EngineBLS>::prepare_signature(
            bad.message.hash_to_signature_curve::<EB>(),
        );
        let prepared_sig = <EB as EngineBLS>::prepare_signature(bad.signature.0);
        let pairs = [(prepared_pk, prepared_msg)];
        assert!(<EB as EngineBLS>::verify_prepared(prepared_sig, pairs.iter()));
    }

    #[test]
    fn verify_simple_rejects_g1_cofactor_pk() {
        assert!(!verify_simple(&signed_with_g1_cofactor_pk()));
    }

    #[test]
    fn verify_unoptimized_rejects_g1_cofactor_pk() {
        assert!(!verify_unoptimized(&signed_with_g1_cofactor_pk()));
    }

    #[test]
    fn verify_with_distinct_messages_rejects_g1_cofactor_pk() {
        assert!(!verify_with_distinct_messages(
            &signed_with_g1_cofactor_pk(),
            true
        ));
    }

    #[test]
    fn verify_simple_rejects_g2_cofactor_sig() {
        assert!(!verify_simple(&signed_with_g2_cofactor_sig()));
    }

    #[test]
    fn verify_unoptimized_rejects_g2_cofactor_sig() {
        assert!(!verify_unoptimized(&signed_with_g2_cofactor_sig()));
    }

    #[test]
    fn verify_with_distinct_messages_rejects_g2_cofactor_sig() {
        assert!(!verify_with_distinct_messages(
            &signed_with_g2_cofactor_sig(),
            true
        ));
    }
}
