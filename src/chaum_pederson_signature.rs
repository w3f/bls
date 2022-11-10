use ark_ec::{Group};
use ark_ff::{PrimeField};

use digest::{Digest};

use crate::Message;
use crate::engine::EngineBLS;
use crate::single::{Keypair, PublicKey, PublicKeyInSignatureGroup, Signature, DoublePublicKeyScheme, SerializableToBytes};
use crate::pop::SchnorrProof;

pub type ChaumPedersonSignature<E> = (Signature<E>, SchnorrProof<E>);

/// ProofOfPossion trait which should be implemented by secret
pub trait ChaumPedersonSigner<E: EngineBLS, H: Digest> {
    /// The proof of possession generator is supposed to
    /// to produce a schnoor signature of the message using
    /// the secret key which it claim to possess.
    fn generate_cp_signature(&mut self, message: Message) -> ChaumPedersonSignature<E>;

    fn generate_witness_scaler(&self, message: Message) -> <<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField;

    fn generate_dleq_proof(&mut self, message: Message, bls_signature: E::SignatureGroup) -> SchnorrProof<E>;
}

/// This should be implemented by public key
pub trait ChaumPedersonVerifier<E: EngineBLS, H: Digest> { 
    fn verify_cp_signature(&self, message: Message, signature_proof: ChaumPedersonSignature<E>) -> bool;
}

impl<E: EngineBLS, H: Digest> ChaumPedersonSigner<E,H> for Keypair<E> {
    fn generate_cp_signature(&mut self, message: Message) -> ChaumPedersonSignature<E> {
        //First we generate a vanila BLS Signature;
        let bls_signature = self.sign(message);
        (bls_signature, <Keypair<E> as ChaumPedersonSigner<E, H>>::generate_dleq_proof(self, message, bls_signature.0))
        
    }

    fn generate_dleq_proof(&mut self, message: Message, bls_signature: E::SignatureGroup) -> SchnorrProof<E> {
        let mut k = <Keypair<E> as ChaumPedersonSigner<E, H>>::generate_witness_scaler(self, message);

        let signature_point = bls_signature;
	let message_point = message.hash_to_signature_curve::<E>();

        let A_point = <<E as EngineBLS>::SignatureGroup as Group>::generator() * k;
        let B_point = message_point * k;
        
        let A_point_as_bytes = E::signature_point_to_byte(&A_point);
        let B_point_as_bytes = E::signature_point_to_byte(&B_point);

        let signature_point_as_bytes = E::signature_point_to_byte(&signature_point);

        let random_scalar =  <H as Digest>::new().chain_update(A_point_as_bytes).chain_update(B_point_as_bytes).chain_update(signature_point_as_bytes).finalize();

        let c = <<<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField>::from_be_bytes_mod_order(&*random_scalar);
        let s = k -  c* self.secret.into_vartime().0;

        ::zeroize::Zeroize::zeroize(&mut k); //clear secret witness from memory
        
        (c, s)
    }

    fn generate_witness_scaler(&self, message: Message) -> <<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField {
        let mut secret_key_as_bytes = self.secret.to_bytes();
                
        let mut scalar_bytes = <H as Digest>::new().chain_update(secret_key_as_bytes).chain_update(message.0).finalize();
	    let random_scalar : &mut [u8] = scalar_bytes.as_mut_slice();
        <<<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField>::from_be_bytes_mod_order(&*random_scalar)

    }
    
}

/// This should be implemented by public key
impl<E: EngineBLS, H: Digest>  ChaumPedersonVerifier<E, H> for PublicKeyInSignatureGroup<E> { 
    fn verify_cp_signature(&self, message: Message, signature_proof: ChaumPedersonSignature<E>) -> bool {
        let mut A_check_point = <<E as EngineBLS>::SignatureGroup as Group>::generator() * signature_proof.1.1 +
            self.0 * signature_proof.1.0;

        let mut B_check_point = message.hash_to_signature_curve::<E>() * signature_proof.1.1 +
            signature_proof.0.0 * signature_proof.1.0;

	let A_point_as_bytes = E::signature_point_to_byte(&A_check_point);
        let B_point_as_bytes = E::signature_point_to_byte(&B_check_point);

        let signature_point_as_bytes = signature_proof.0.to_bytes();
        
        let resulting_scalar =  <H as Digest>::new().chain_update(A_point_as_bytes).chain_update(B_point_as_bytes).chain_update(signature_point_as_bytes).finalize();
        let c_check = <<<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField>::from_be_bytes_mod_order(&*resulting_scalar);

        c_check == signature_proof.1.0

    }
}
