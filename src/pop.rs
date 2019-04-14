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
//! (TODO: cite Ari too???)
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

use std::borrow::{Borrow,BorrowMut};
use std::collections::HashMap;
use std::iter::{once};  // FromIterator

use super::*;
use super::single::SignedMessage;
use super::verifiers::verify_with_distinct_messages;

/// Batch BLS signatures with attached messages and signers,
/// for whom we previously checked proofs-of-possession.
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
/// `BitPoPSignedMessage`s into one verification.  We do not provide
/// aggreggation in the usual sense here, instead merging multiples
/// signers public keys anytime they sign the same message, so the.
/// this type essentially provides only fast batch verificartion. 
///
/// We therefore do not bother providing serialization for this
/// type.  Actual aggregation should be done with types like 
/// `BitPoPSignedMessage` that utilize a `ProofsOfPossession` to
/// efficently serialize subsets of the set of signers. 
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
// TODO: Serialization

impl<E: EngineBLS> BatchAssumingProofsOfPossession<E> {
    pub fn new() -> BatchAssumingProofsOfPossession<E> {
        BatchAssumingProofsOfPossession {
            messages_n_publickeys: HashMap::new(),
            signature: Signature(E::SignatureGroup::zero()),
        }
    }

    /// Aggregage BLS signatures with proofs-of-possession
    pub fn aggregate<'a,S>(&mut self, signed: &'a S) 
    where
        &'a S: Signed<E=E>,
        <&'a S as Signed>::PKG: Borrow<PublicKey<E>>,
    {
        let signature : E::SignatureGroup = signed.signature().0;
        for (m,pk) in signed.messages_and_publickeys() {
            self.messages_n_publickeys.entry(*m.borrow())
                    .and_modify(|pk0| pk0.0.add_assign(&pk.borrow().0) )
                    .or_insert(*pk.borrow());
        }
        self.signature.0.add_assign(&signature);
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


// Bitfield-style proof-of-possession aggreggation //

// Slice equality with bytewise equality hack because
// std does not expose `slice::BytewiseEquality`
fn slice_eq_bytewise<T: PartialEq<T>>(x: &[T], y: &[T]) -> bool {
    if x.len() != y.len() { return false; }
    if ::std::ptr::eq(x,y) { return true; }
    x == y
}

/// Proof-of-possession table.
///
/// We provide a signers bitfield for efficent 
pub trait ProofsOfPossession<E: EngineBLS> {
    /// Returns true if two ProofsOfPossession databases match exactly.
    ///
    /// We could employ a PartialEq<Self> + Eq bound for this, except
    /// those are frequently slow even for small for databases.
    fn agreement(&self, other: &Self) -> bool;

    /// Bitfield type used to represent a signers set
    ///
    /// Must not permit altering length, so `Box<[u8]>` or `[u8; 128]` not `Vec<u8>`.
    type Signers: Borrow<[u8]>+BorrowMut<[u8]>+Clone+Sized;
    /// Create a new signers set bitfield
    fn new_signers(&self) -> Self::Signers;

    /// Lookup the public key with a particular bit index.
    ///
    /// Must succeed if `index < signers.borrow().len()`, but
    /// should panic if `index > signers.borrow().len()`.
    /// It may return `None` if the position is empty.
    ///
    /// Must satisfy `self.lookup(i).and_then(|i| self.find(i)) == Some(i)` when `i` is occupied.
    fn lookup(&self, index: usize) -> Option<PublicKey<E>>;

    /// Find the bit index for a particular public key.
    ///
    /// Must succeed if the public key is present, and fail otherwise.
    /// 
    /// Must satisfy `self.find(pk).and_then(|i| self.lookup(i)) == Some(pk)` when `pk` is present.
    fn find(&self, publickey: &PublicKey<E>) -> Option<usize>;
}

/// TODO: Evaluate using Deref vs Borrow in this context
/// TODO: Use specialization here
impl<E,V> ProofsOfPossession<E> for V
where
    E: EngineBLS,
    V: ::std::ops::Deref<Target=[PublicKey<E>]>
{
    fn agreement(&self, other: &Self) -> bool {
        slice_eq_bytewise(self.deref(),other.deref())
    }

    type Signers = Box<[u8]>;
    fn new_signers(&self) -> Self::Signers {
        vec![0u8; (self.deref().len() + 7) / 8].into_boxed_slice()
    }

    fn lookup(&self, index: usize) -> Option<PublicKey<E>> {
        self.deref().get(index).cloned()
        // .map(|pk| { debug_assert!( Some(index) == self.find(&pk) ); pk })
    }
    fn find(&self, publickey: &PublicKey<E>) -> Option<usize> {
        self.deref().iter().position(|pk| *pk==*publickey)
        // .map(|i| { debug_assert!( Some(publickey) == self.lookup(i) ); i })
    }
}

/// Error type for bitfield-style proof-of-possession aggreggation
///
/// These do not necessarily represent attacks pr se.  We therefore
/// permit users to recover from them, although actual recovery sounds
/// impossible nomrally.
#[derive(Debug)]
pub enum BitPoPError {
    /// Attempted to use missmatched proof-of-possession tables. 
    BadPoP(&'static str),
    /// Attempted to aggregate distint messages, which requires the 
    /// the more general BatchAssumingProofsOfPossession type instead.
    MismatchedMessage,
    /// Aggregation is impossible due to signers being repeated in both sets.
    RepeatedSigners,
}

impl ::std::fmt::Display for BitPoPError {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        use self::BitPoPError::*;
        match self {
            BadPoP(s) => write!(f, "{}", s),
            MismatchedMessage => write!(f, "Cannot aggregate distinct messages with only a bit field."),
            RepeatedSigners => write!(f, "Cannot aggregate due to duplicate signers."),
        }
    }
}

impl ::std::error::Error for BitPoPError {
    fn description(&self) -> &str {
        use self::BitPoPError::*;
        match self {
            BadPoP(s) => s,
            MismatchedMessage => "Cannot aggregate distinct messages with only a bit field.",
            RepeatedSigners => "Cannot aggregate due to duplicate signers",
        }
    }
    fn cause(&self) -> Option<&::std::error::Error> { None }
}

/// One individual message with attached aggreggate BLS signatures
/// from signers for whom we previously checked proofs-of-possession,
/// and with the singers presented as a compact bitfield.
///
/// You must provide a `ProofsOfPossession` for this, likely by
/// implementing it for your own data structures.
#[derive(Clone)]
pub struct BitPoPSignedMessage<E: EngineBLS, POP: ProofsOfPossession<E>> {
    proofs_of_possession: POP,
    signers: <POP as ProofsOfPossession<E>>::Signers,
    message: Message,
    signature: Signature<E>,
}

impl<'a,E,POP> Signed for &'a BitPoPSignedMessage<E,POP> 
where
    E: EngineBLS,
    POP: ProofsOfPossession<E>,
{
    type E = E;

    type M = Message;
    type PKG = PublicKey<E>;

    type PKnM = ::std::iter::Once<(Message, PublicKey<E>)>;

    fn messages_and_publickeys(self) -> Self::PKnM {
        let mut publickey = E::PublicKeyGroup::zero();
        for i in 0..8*self.signers.borrow().len() {
            if self.signers.borrow()[i / 8] & (1 << (i % 8)) != 0 {
                let pop_pk = self.proofs_of_possession.lookup(i).unwrap().0;
                publickey.add_assign(&pop_pk);
            }
        }
        once((self.message.clone(), PublicKey(publickey)))
    }

    fn signature(&self) -> Signature<E> { self.signature }

    fn verify(self) -> bool {
        // We have already aggregated distinct messages, so our distinct
        // message verification code provides reasonable optimizations,
        // except the public keys need not be normalized here. 
        // We foresee verification via gaussian elimination being
        // significantly faster, but requiring affine keys.
        verify_with_distinct_messages(self,true)
    }
}

impl<E,POP> BitPoPSignedMessage<E,POP> 
where
    E: EngineBLS,
    POP: ProofsOfPossession<E>,
{
    pub fn new(proofs_of_possession: POP, message: Message) -> BitPoPSignedMessage<E,POP> {
        let signers = proofs_of_possession.new_signers();
        let signature = Signature(E::SignatureGroup::zero());
        BitPoPSignedMessage { proofs_of_possession, signers, message, signature }
    }

    pub fn add_points(&mut self, publickey: PublicKey<E>, signature: Signature<E>) -> Result<(),BitPoPError> {
        let i = self.proofs_of_possession.find(&publickey)
            .ok_or(BitPoPError::BadPoP("Mismatched proof-of-possession")) ?;
        debug_assert!( self.proofs_of_possession.lookup(i) == Some(publickey), "Invalid ProofsOfPossession implementation" );
        let b = 1 << (i % 8);
        let s = &mut self.signers.borrow_mut()[i / 8];
        if *s & b != 0 { return Err(BitPoPError::RepeatedSigners); }
        *s |= b;
        self.signature.0.add_assign(&signature.0);
        Ok(())
    }

    pub fn add(&mut self, signed: &SignedMessage<E>) -> Result<(),BitPoPError>
    {
        if self.message != signed.message {
            return Err(BitPoPError::MismatchedMessage);
        }
        self.add_points(signed.publickey,signed.signature)
    }

    fn chunk_lookup(&self, index: usize) -> u8 {
        (0..8).into_iter().fold(0u8, |b,j| {
            let i = 8*index + j;
            let pk = self.proofs_of_possession.lookup(i)
                .map(|pk| { debug_assert!( Some(i) == self.proofs_of_possession.find(&pk) ); pk });
            b | pk.map_or(1u8 << j, |_| 0u8)
        })
    }

    pub fn merge(&mut self, other: &BitPoPSignedMessage<E,POP>) -> Result<(),BitPoPError> {
        if self.message != other.message {
            return Err(BitPoPError::MismatchedMessage);
        }
        if ! self.proofs_of_possession.agreement(&other.proofs_of_possession) {
            return Err(BitPoPError::BadPoP("Mismatched proof-of-possession"));
        }
        for (i,(x,y)) in self.signers.borrow().iter().zip(other.signers.borrow()).enumerate() {
            if *x & *y != 0 { return Err(BitPoPError::RepeatedSigners); }
            if *y & self.chunk_lookup(i) != 0 { return Err(BitPoPError::BadPoP("Absent signer")); }
        }
        for (x,y) in self.signers.borrow_mut().iter_mut().zip(other.signers.borrow()) {
            *x |= y;
        }
        self.signature.0.add_assign(&other.signature.0);
        Ok(())
    }
}



#[cfg(test)]
mod tests {
    use rand::{thread_rng};  // Rng

    use super::*;

    #[test]
    fn proof_of_possession() {
        let msg1 = Message::new(b"ctx",b"some message");
        let msg2 = Message::new(b"ctx",b"another message");

        let k = |_| Keypair::<ZBLS>::generate(thread_rng());
        let mut keypairs = (0..4).into_iter().map(k).collect::<Vec<_>>();
        let pop = keypairs.iter().map(|k| k.public).collect::<Vec<_>>();
        let dup = keypairs[3].clone();
        keypairs.push(dup);
        let sigs1 = keypairs.iter_mut().map(|k| k.sign(msg1)).collect::<Vec<_>>();

        let mut bitpop1 = BitPoPSignedMessage::<ZBLS,_>::new(pop.clone(),msg1);
        for (i,sig) in sigs1.iter().enumerate() {
            assert!( bitpop1.add(sig).is_ok() == (i<4));
            assert!( bitpop1.verify() );  // verifiers::verify_with_distinct_messages(&dms,true)
        }
        assert!( verifiers::verify_unoptimized(&bitpop1) );
        assert!( verifiers::verify_simple(&bitpop1) );
        assert!( verifiers::verify_with_distinct_messages(&bitpop1,false) );
        // assert!( verifiers::verify_with_gaussian_elimination(&dms) );

        let sigs2 = keypairs.iter_mut().map(|k| k.sign(msg2)).collect::<Vec<_>>();  
        let mut bitpop2 = BitPoPSignedMessage::<ZBLS,_>::new(pop.clone(),msg2);
        for sig in sigs2.iter().take(3) {
            assert!( bitpop2.add(sig).is_ok() );
        }
        assert!( bitpop1.merge(&bitpop2).is_err() );

        let mut multimsg = BatchAssumingProofsOfPossession::<ZBLS>::new();
        multimsg.aggregate(&bitpop1);
        multimsg.aggregate(&bitpop2);
        assert!( multimsg.verify() );  // verifiers::verify_with_distinct_messages(&dms,true)
        assert!( verifiers::verify_unoptimized(&multimsg) );
        assert!( verifiers::verify_simple(&multimsg) );
        assert!( verifiers::verify_with_distinct_messages(&multimsg,false) );

        let oops = Keypair::<ZBLS>::generate(thread_rng()).sign(msg2);
        assert!( bitpop1.add_points(oops.publickey,oops.signature).is_err() );
        /*
        TODO: Test that adding signers for an incorrect message fails, but this version angers teh borrow checker.
        let mut oops_pop = pop.clone();
        oops_pop.push(oops.publickey);
        // We should constriuvt a better test here because this only works
        // because pop.len() is not a multiple of 8.
        bitpop1.proofs_of_possession = &oops_pop[..];
        bitpop1.add_points(oops.publickey,oops.signature).unwrap();
        assert!( ! bitpop1.verify() );
        assert!( ! verifiers::verify_unoptimized(&bitpop1) );
        assert!( ! verifiers::verify_simple(&bitpop1) );
        assert!( ! verifiers::verify_with_distinct_messages(&bitpop1,false) );
        */
    }
}
