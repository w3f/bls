//! Linear aggregation for BLS signatures
//!
//! We handle linear flavors of a aggregate BLS signatures here,
//! including both distinct messages and proof-of-possesion.

use std::collections::HashMap;
use std::iter::once;

use super::*;


// Distinct Messages //

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
/// additional assuptions.  There is not necessarily an asymptotic
/// improvement in running time with this because verification
/// still requires one pairing per message, unless signers are
/// fequently repeated, so our verification code is optimized
/// for finding duplicate signers. 
///
/// We note that messages generated simultanioiusly by the same signer
/// can be batched or aggregated faster with other systems, incuding
/// - RSA:  https://eprint.iacr.org/2018/082.pdf
/// - Boneh-Boyen:  https://crypto.stanford.edu/~dabo/papers/bbsigs.pdf
///     http://sci-gems.math.bas.bg:8080/jspui/bitstream/10525/1569/1/sjc096-vol3-num3-2009.pdf
///
/// TODO:  Insecure currently because if a developer does not check
/// the return of add or merge then they can think a signature means
/// something incorrect.
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
    	// 		return Err(AggregationAttackViaDuplicateMessages);
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
    let signature = signed.signature().0;
	// We first hash the messages to the signature curve and
	// normalize the public keys to operate on them as bytes.
    // TODO: Assess if we should mutate in place using interior
	// mutability, maybe using `BorrowMut` support in
	// `batch_normalization`.
	let itr = signed.messages_and_publickeys();
    let l = {  let (lower, upper) = itr.size_hint();  upper.unwrap_or(lower)  };
	let mut publickeys = Vec::with_capacity(l);
	let mut messages = Vec::with_capacity(l+1);
    for (m,pk) in itr {
		publickeys.push( pk.borrow().0.clone() );
    	messages.push( m.borrow().hash_to_signature_curve::<S::E>() );
    }
	if normalize_public_keys {
	    <<S as Signed>::E as EngineBLS>::PublicKeyGroup::batch_normalization(publickeys.as_mut_slice());
	}

    // We next accumulate message points with the same signer.
	// We could avoid the allocation here if we sorted both 
	// arrays in parallel.  This might mean (a) some sort function
	// using `ops::IndexMut` instead of slices, and (b) wrapper types
	// types to make tuples of slices satisfy `ops::IndexMut`.
	// TODO:  Impl PartialEq, Eq, Hash for pairing::EncodedPoint
	// to avoid  struct H(E::PublicKeyGroup::Affine::Uncompressed);
    type AA<E> = (PublicKeyAffine<E>, SignatureProjective<E>);
	let mut pks_n_ms = HashMap::with_capacity(l);
    for (pk,m) in publickeys.drain(..)
	                        .map(|pk| pk.into_affine())
							.zip(messages.drain(..)) 
	{
    	pks_n_ms.entry(pk.into_uncompressed())
		        .and_modify(|(_pk0,m0): &mut AA<S::E>| m0.add_assign(&m) )
				.or_insert((pk,m));
    }

	let mut publickeys = Vec::with_capacity(l);
    for (_,(pk,m)) in pks_n_ms.drain() {
    	messages.push(m);
		publickeys.push(pk.prepare());
    }

    // We finally normalize the messages and signature
	messages.push(signature);
	<<S as Signed>::E as EngineBLS>::SignatureGroup::batch_normalization(messages.as_mut_slice());
    let signature = messages.pop().unwrap().into_affine().prepare();
	// TODO: Assess if we could cache normalized message hashes anyplace
	// using interior mutability, but probably this does not work well
	// with our optimization of collecting messages with thesame signer.

    // And verify the aggregate signature.
    let messages = messages.iter().map(|m| m.into_affine().prepare()).collect::<Vec<_>>();
    let prepared = publickeys.iter().zip(&messages);
    S::E::verify_prepared( &signature, prepared )
}


// Proof-of-Possession //

/// Messages with attached BLS signatures from signers who previously
/// provided proofs-of-possession.
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


// Bitfield-srtyle Proof //

pub enum BitPoPError {
    MismatchedPoP,
    RepeatedSigners,
}

#[derive(Clone)]
pub struct BitPoPSignedMessage<E: EngineBLS, POP: Borrow<[PublicKey<E>]>> {
    proofs_of_possession: POP,
    signers: Vec<u8>,
    message: Message,
    signature: Signature<E>,
}

// Slice equality with bytewise equality hack because
// std does not expose `slice::BytewiseEquality`
fn slice_eq_bytewise<T: PartialEq<T>>(x: &[T], y: &[T]) -> bool {
    if x.len() != y.len() { return false; }
    if ::std::ptr::eq(x,y) { return true; }
    x == y
}

impl<E,POP> BitPoPSignedMessage<E,POP> 
where
    E: EngineBLS,
    POP: Borrow<[PublicKey<E>]>,
{
    pub fn new(proofs_of_possession: POP, message: Message) -> BitPoPSignedMessage<E,POP> {
        let signers = vec![0u8; proofs_of_possession.borrow().len()];
		let signature = Signature(E::SignatureGroup::zero());
    	BitPoPSignedMessage { proofs_of_possession, signers, message, signature }
    }

    fn add(&mut self, publickey: PublicKey<E>, signature: Signature<E>) -> Result<(),BitPoPError> {
        let i = self.proofs_of_possession.borrow().iter()
            .position(|pk| *pk==publickey)
            .ok_or(BitPoPError::MismatchedPoP) ?;
        let b = (1 << (i % 8));
        let mut s = &mut self.signers[i / 8];
        if *s & b != 0 { return Err(BitPoPError::RepeatedSigners); }
        *s |= b;
        self.signature.0.add_assign(&signature.0);
        Ok(())
    }

    fn merge(&mut self, other: &BitPoPSignedMessage<E,POP>) -> Result<(),BitPoPError> {
        if ! slice_eq_bytewise(self.proofs_of_possession.borrow(), other.proofs_of_possession.borrow()) {
            return Err(BitPoPError::MismatchedPoP);
        }
        if self.signers.iter().zip(&other.signers[..]).any(|(x,y)| *x & *y != 0) {
            return Err(BitPoPError::RepeatedSigners);
        }
        for (x,y) in self.signers.iter_mut().zip(&other.signers[..]) {
            *x |= y;
        }
        self.signature.0.add_assign(&other.signature.0);
        Ok(())
    }
}

impl<'a,E,POP> Signed for &'a BitPoPSignedMessage<E,POP> 
where
    E: EngineBLS,
    POP: Borrow<[PublicKey<E>]>,
{
	type E = E;

	type M = Message;
    type PKG = PublicKey<E>;

	type PKnM = ::std::iter::Once<(Message, PublicKey<E>)>;

	fn messages_and_publickeys(self) -> Self::PKnM {
        let mut publickey = E::PublicKeyGroup::zero();
        for (i,pop_pk) in self.proofs_of_possession.borrow().iter().enumerate() {
            if self.signers[i / 8] & (1 << (i % 8)) != 0 {
                publickey.add_assign(&pop_pk.0);
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

    use pairing::bls12_381::Bls12;
    use rand::{SeedableRng, XorShiftRng};

    // #[test]
	// fn foo() { }
}


