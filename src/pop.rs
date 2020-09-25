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


use std::borrow::{Borrow}; // BorrowMut
use std::collections::HashMap;

//use pairing::{CurveProjective}; // CurveAffine, Engine
use pairing::curves::ProjectiveCurve as CurveProjective;

use super::*;
use super::verifiers::verify_with_distinct_messages;


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
//
// In principle, one might combine proof-of-possession with distinct
// message assumptions, or other aggregation strategies, when
// verifiers have only observed a subset of the proofs-of-possession,
// but this sounds complex or worse fragile.
//
// TODO: Implement gaussian elimination verification scheme.
#[derive(Clone)]
pub struct BatchAssumingProofsOfPossession<E: EngineBLS> {
    messages_n_publickeys: HashMap<Message,PublicKey<E>>,
    signature: Signature<E>,
}

impl<E: EngineBLS> BatchAssumingProofsOfPossession<E> {
    pub fn new() -> BatchAssumingProofsOfPossession<E> {
        BatchAssumingProofsOfPossession {
            messages_n_publickeys: HashMap::new(),
            signature: Signature(E::SignatureGroup::zero()),
        }
    }

    /// Add only a `Signature<E>` to our internal signature.
    ///
    /// Useful for constructing an aggregate signature, but we
    /// recommend instead using a custom types like `BitPoPSignedMessage`.
    pub fn add_signature(&mut self, signature: &Signature<E>) {
        self.signature.0.add_assign(&signature.0);
    }

    /// Add only a `Message` and `PublicKey<E>` to our internal data.
    ///
    /// Useful for constructing an aggregate signature, but we
    /// recommend instead using a custom types like `BitPoPSignedMessage`.
    pub fn add_message_n_publickey(&mut self, message: &Message, publickey: &PublicKey<E>) {
        self.messages_n_publickeys.entry(*message)
            .and_modify(|pk0| pk0.0.add_assign(&publickey.0) )
            .or_insert(*publickey);
    }

    /// Aggregage BLS signatures assuming they have proofs-of-possession
    pub fn aggregate<'a,S>(&mut self, signed: &'a S) 
    where
        &'a S: Signed<E=E>,
        <&'a S as Signed>::PKG: Borrow<PublicKey<E>>,
    {
        let signature = signed.signature();
        for (message,pubickey) in signed.messages_and_publickeys() {
            self.add_message_n_publickey(message.borrow(),pubickey.borrow());
        }
        self.add_signature(&signature);
    }
}


impl<'a,E: EngineBLS> Signed for &'a BatchAssumingProofsOfPossession<E> {
    type E = E;

    type M = &'a Message;
    type PKG = &'a PublicKey<Self::E>;
    type PKnM = ::std::collections::hash_map::Iter<'a,Message,PublicKey<E>>;

    fn messages_and_publickeys(self) -> Self::PKnM {
        self.messages_n_publickeys.iter()
    }

    fn signature(&self) -> Signature<E> { self.signature }

    fn verify(self) -> bool {
        // We have already aggregated distinct messages, so our distinct
        // message verification code provides reasonable optimizations,
        // except the public keys might not be normalized here. 
        // We foresee verification via gaussian elimination being faster,
        // but requires affine keys or normalization.
        verify_with_distinct_messages(self,true)
        // TODO: verify_with_gaussian_elimination(self)
    }
}




