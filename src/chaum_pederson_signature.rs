use crate::single::{SecretKey,PublicKey,Keypair};
use crate::schnorr_pop::SchnorrProof;

pub type ChaumPedersonSignature<E> = (Signature<E as EngineBLS>, SchnorrProof<E>);
k

/// ProofOfPossion trait which should be implemented by secret
pub trait ChaumPedersonSigner<E: EngineBLS, H: Digest> {
    /// The proof of possession generator is supposed to
    /// to produce a schnoor signature of the message using
    /// the secret key which it claim to possess.
    fn generate_cp_signature(&self, message: Message) -> ChaumPedersonSignature<E>;

    fn generate_witness_scaler(&self, message: Message) -> <<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField;

    fn generate_dleq_proof((&self,bls_signature: E::SignatureGroup);
}

/// This should be implemented by public key
pub trait ChaumPedersonVerifier<E: EngineBLS, H: Digest> { 
    fn verify_cp_signature(&self, message: Message, signature_proof: ChaumPedersonSignature<E>) -> bool;
}

impl<E: EngineBLS, H: Digest> ChaumPedersonSigner<E,H> for Keypair<E> {
    fn generate_cp_signature(&self, message: Message) -> ChaumPedersonSignature<E> {
        //First we generate a vanila BLS Signature;
        let bls_signature = self.sign(message);
        (bls_signature, self.generate_dleq_proof(message, bls_signature))
        
    }

    fn generate_dleq_proof(&self, message: Message, bls_signature: E::SignatureGroup) {
        let k = self.generate_witness_scaler(message);

        let signature_point = bls_signature.0;

        let A_point = <<E as EngineBLS>::SignatureGroup as Group>::generator() * k;
        let B_point = message_point * k;
        
        let mut A_point_as_bytes : Vec::<u8> = vec![0;  self.A_point_affine().compressed_size()];
        A_point.serialize_compressed(&mut A_point_as_bytes).unwrap();

        let mut B_point_as_bytes : Vec::<u8> = vec![0;  self.B_point.compressed_size()];
        B_point.serialize_compressed(&mut B_point_as_bytes).unwrap();

        let mut signature_point_as_bytes : Vec::<u8> = vec![0;  self.signature_point.compressed_size()];
        signature_point.serialize_compressed(&mut signature_point_as_bytes).unwrap();

        let random_scalar : &mut [u8] =  <H as Digest>::new().chain_update(A_point_as_bytes).chain_update(B_point_as_bytes).chain_update(signature_point_as_bytes).finalize();

        let c = <<<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField>::from_be_bytes_mod_order(&*random_scalar);
        s = k -  c* self.secret.into_vartime().0;

        ::zeroize::Zeroize::zeroize(&mut k); //clear secret witness from memory
        
        (c, s)
    }

    fn generate_witness_scaler(&self, message: Message) -> <<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField {
        let mut secret_key_as_bytes = vec![0;  self.secret.into_vartime().0.compressed_size()];
        self.secret.into_vartime().0.serialize_compressed(&mut secret_key_as_bytes[..]).unwrap();
        
        let mut scalar_bytes = <H as Digest>::new().chain_update(secret_key_as_bytes).chain_update(message.0).finalize();
	    let random_scalar : &mut [u8] = scalar_bytes.as_mut_slice();
        <<<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField>::from_be_bytes_mod_order(&*random_scalar)

    }
    
}

/// This should be implemented by public key
impl<E: EngineBLS, H: Digest>  ChaumPedersonVerifier<E, H> for Keypair<E> { 
    fn verify_cp_signature(&self, message: Message, signature_proof: ChaumPedersonSignature<E>) -> bool {
        let mut A_check_point = <<E as EngineBLS>::SignatureGroup as Group>::generator() * signature_proof.1.1 +
            self.into_public_key_in_signature_group() * signature_proof.1.0;

        let mut B_check_point = message.hash_to_signature_curve::<E>() * signature_proof.1.1 +
            signature_proof.0 * signature_proof.1.0;

        let mut A_point_as_bytes : Vec::<u8> = vec![0;  self.A_point.compressed_size()];
        A_check_point.serialize_compressed(&mut A_point_as_bytes).unwrap();

        let mut B_point_as_bytes : Vec::<u8> = vec![0;  self.B_point.compressed_size()];
        B_check_point.serialize_compressed(&mut B_point_as_bytes).unwrap();
        

        let resulting_scalar : &mut [u8] =  <H as Digest>::new().chain_update(A_point_as_bytes).chain_update(B_point_as_bytes).chain_update(signature_point_as_bytes).finalize();
        let c_check = <<<E as EngineBLS>::PublicKeyGroup as Group>::ScalarField>::from_be_bytes_mod_order(&*resulting_scalar);

        c_check == signature_proof.1.0

    }
}
