//! Linear aggregation for BLS signatures
//!
//! We handle linear flavors of a aggregate BLS signatures here,
//! including both distinct messages and proof-of-possesion.

use std::borrow::{Borrow,BorrowMut};
use std::collections::HashMap;
use std::iter::once;

use super::*;
use super::verifiers::verify_with_distinct_messages;


// Distinct Messages //

/// Error tyoe for non-distinct messages found during distinct
/// message aggregation.
///
/// There are numerous scenarios that make recovery from such errors
/// impossible.  We therefore destroy the aggregate signature struct
/// whenever creating this, so that users cannot respond incorrectly
/// to an error message.
#[derive(Debug)]
pub struct AggregationAttackViaDuplicateMessages;

impl ::std::fmt::Display for AggregationAttackViaDuplicateMessages {
    fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
        write!(f, "Attempted to aggregate duplicate messages.")
    }
}

impl ::std::error::Error for AggregationAttackViaDuplicateMessages {
    fn description(&self) -> &str {
        "Attempted to aggregate duplicate messages." 
    }
    fn cause(&self) -> Option<&::std::error::Error> { None }
}

/// Distinct messages with attached BLS signature
/// 
/// We can aggregate BLS signatures on distinct messages without
/// additional assuptions or delinearization.  In this variant, there
/// is obviously no aggregation on the signature curve, so verification
/// still requires one pairing per message.  We can however aggregate
/// numerous messages with the same signer, so this works well when
/// a small signer set signs numerous messages, even if the signer set
/// remains unknown.
///
/// We also of course benifit from running one single Miller loop and
/// final exponentiation when compiuting all these pairings.  We note
/// that proofs of possession are necessarily distinct messages because
/// the message singles out the signing key uniquely, so they may be
/// aggregated or batch verified with distinct message mode.
///
/// As an aside, almost all signature schemes permit support extremely
/// efficent signer side batching, which normally out performs BLS. 
/// It's ocasioanlly worth asking if signers can be trusted to such
/// collected signatures.  See also:
/// - RSA:  https://eprint.iacr.org/2018/082.pdf
/// - Boneh-Boyen:  https://crypto.stanford.edu/~dabo/papers/bbsigs.pdf
///     http://sci-gems.math.bas.bg:8080/jspui/bitstream/10525/1569/1/sjc096-vol3-num3-2009.pdf
#[derive(Clone)]
pub struct DistinctMessages<E: EngineBLS> {
    messages_n_publickeys: HashMap<Message,PublicKey<E>>,
    signature: Signature<E>,
}
// TODO: Serialization

/*
We do not require an abstract aggregation routine here since only
two quite different types work in this case.
pub trait SignedWithDistinctMessages : Signed {}
impl<E: EngineBLS,M: Message> SignedWithDistinctMessages for SignedMessage<E,M> {}
impl<E: EngineBLS,M: Message> SignedWithDistinctMessages for DistinctMessages<E,M> {}
*/

impl<E: EngineBLS> DistinctMessages<E> {
    pub fn new() -> DistinctMessages<E> {
        DistinctMessages {
            messages_n_publickeys: HashMap::new(),
            signature: Signature(E::SignatureGroup::zero()),
        }
    }

    /// Aggregage BLS signatures from singletons with distinct messages
    ///
    /// We require that duplicate message halt verification by consuming
    /// self by vaule and return it only if no duplicate occur.
    pub fn add(mut self, signed: &super::single::SignedMessage<E>)
      -> Result<Self,AggregationAttackViaDuplicateMessages>
    {
        if let Some(_old_publickey) = self.messages_n_publickeys.insert(signed.message,signed.publickey) {
            // We need not recover from this error because the hash map gets erased.
            // self.messages_n_publickeys.insert(signed.message,old_publickey);
            return Err(AggregationAttackViaDuplicateMessages);
        }
        self.signature.0.add_assign(&signed.signature.0);
        Ok(self)
    }

    /// Aggregage BLS signatures from sources with distinct messages
    ///
    /// We require that duplicate message halt verification by consuming
    /// self by vaule and return it only if no duplicate occur.
    pub fn merge<S>(mut self, signed: &DistinctMessages<E>)
      -> Result<Self,AggregationAttackViaDuplicateMessages>
    {
        // We need not detect duplicates early for recovery because
        // duplicates cause our hashmap to be freed anyways.
        // for (m,_pk) in signed.messages_n_publickeys.iter() {
        //     if self.messages_n_publickeys.contains_key(m) {
        //      return Err(AggregationAttackViaDuplicateMessages);
        //     }
        // }
        for (m,pk) in signed.messages_n_publickeys.iter() {
            // assert!(self.messages_n_publickeys.insert(*m,*pk).is_none());
            if self.messages_n_publickeys.insert(*m,*pk).is_some() {
                return Err(AggregationAttackViaDuplicateMessages);
            }
        }
        self.signature.0.add_assign(&signed.signature.0);
        Ok(self)
    }
}

impl<'a,E: EngineBLS> Signed for &'a DistinctMessages<E> {
    type E = E;

    type M = &'a Message;
    type PKG = &'a PublicKey<Self::E>;
    type PKnM = ::std::collections::hash_map::Iter<'a,Message,PublicKey<E>>;

    fn messages_and_publickeys(self) -> Self::PKnM {
        self.messages_n_publickeys.iter()
    }

    fn signature(&self) -> Signature<E> { self.signature }

    fn verify(self) -> bool {
        verify_with_distinct_messages(self, false)
    }
}


// Proof-of-Possession //

/// Messages with attached aggreggate BLS signatures from signers
/// for whom we previously checked proofs-of-possession.
///
/// We say a signer has provided a proof-of-possession if the
/// verifier knows they have signed some other message.  In practice,
/// this requires verifying a signature on a message containing the
/// signer's public key, without using proof-of-possession in that
/// verification.
///
/// We may aggregate signatures trivially with simple addition when
/// all signers have previously supplied a proof-of-possession.
/// See the security arguments in The Power of Proofs-of-Possession:
/// Securing Multiparty Signatures against Rogue-Key Attacks
/// by Thomas Ristenpart and Scott Yilek at https://eprint.iacr.org/2007/264.pdf
///
/// In principle, we could combine proof-of-possession with distinct
/// message assumptions, or other aggregation strategies, when
/// verifiers have only observed a subset of the proofs-of-possession,
/// but this sounds complex or worse fragile.
///
/// TODO: Implement gaussian elimination verification scheme.
#[derive(Clone)]
pub struct AggregatedByProofsOfPossession<E: EngineBLS> {
    messages_n_publickeys: HashMap<Message,PublicKey<E>>,
    signature: Signature<E>,
}
// TODO: Serialization

impl<E: EngineBLS> AggregatedByProofsOfPossession<E> {
    pub fn new() -> AggregatedByProofsOfPossession<E> {
        AggregatedByProofsOfPossession {
            messages_n_publickeys: HashMap::new(),
            signature: Signature(E::SignatureGroup::zero()),
        }
    }

    /// Aggregage BLS signatures with proofs-of-possession
    pub fn aggregate<S>(&mut self, signed: &S) 
    where
        for<'a> &'a S: Signed<E=E>,
        for<'a> <&'a S as Signed>::PKG: Borrow<single::PublicKey<E>>,
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

impl<'a,E: EngineBLS> Signed for &'a AggregatedByProofsOfPossession<E> {
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
        // except the public keys need not be normalized here. 
        // We foresee verification via gaussian elimination being
        // significantly faster, but requiring affine keys.
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

/// Proof-of-possession table
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

    /// Lookup an 
    ///
    /// Must succeed if `index < signers.borrow().len()`, 
    /// 
    /// also should panic if `index > signers.borrow().len()`.
    fn lookup(&self, index: usize) -> Option<PublicKey<E>>;

    fn find(&self, publickey: &PublicKey<E>) -> Option<usize>;
}

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
        vec![0u8; self.deref().len() / 8].into_boxed_slice()
    }

    fn lookup(&self, index: usize) -> Option<PublicKey<E>> {
        self.deref().get(index).cloned()
    }
    fn find(&self, publickey: &PublicKey<E>) -> Option<usize> {
        self.deref().iter().position(|pk| *pk==*publickey)
    }
}

/// Error type for bitfield-style proof-of-possession aggreggation
///
/// These do not necessarily represent attacks pr se.  We therefore
/// permit users to recover from them, although actual recovery sounds
/// impossible nomrally.
pub enum BitPoPError {
    /// Any unrecoverable error that indicates missmatched proof-of-possession tables. 
    BadPoP(&'static str),
    /// Aggregation is impossible due to signers being repeated in both sets.
    RepeatedSigners,
}

/// One individual message with attached aggreggate BLS signatures
/// from signers for whom we previously checked proofs-of-possession,
/// and with the singers presented as a compact bitfield.
///
///
#[derive(Clone)]
pub struct BitPoPSignedMessage<E: EngineBLS, POP: ProofsOfPossession<E>> {
    proofs_of_possession: POP,
    signers: <POP as ProofsOfPossession<E>>::Signers,
    message: Message,
    signature: Signature<E>,
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

    pub fn add(&mut self, publickey: PublicKey<E>, signature: Signature<E>) -> Result<(),BitPoPError> {
        let i = self.proofs_of_possession.find(&publickey)
            .ok_or(BitPoPError::BadPoP("Mismatched proof-of-possession")) ?;
        let b = 1 << (i % 8);
        let s = &mut self.signers.borrow_mut()[i / 8];
        if *s & b != 0 { return Err(BitPoPError::RepeatedSigners); }
        *s |= b;
        self.signature.0.add_assign(&signature.0);
        Ok(())
    }

    fn chunk_lookup(&self, index: usize) -> u8 {
        (0..8).into_iter().fold(0u8, |b,j| {
            b | self.proofs_of_possession.lookup(8*index + j).map_or(1u8 << j, |_| 0u8)
        })
    }

    pub fn merge(&mut self, other: &BitPoPSignedMessage<E,POP>) -> Result<(),BitPoPError> {
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




#[cfg(test)]
mod tests {
    use super::*;

    // use rand::{SeedableRng, XorShiftRng};

    // #[test]
    // fn foo() { }
}


