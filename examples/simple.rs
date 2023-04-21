use w3f_bls::{Keypair, Message, ZBLS};

fn main() {
    let mut keypair = Keypair::<ZBLS>::generate(::rand::thread_rng());
    let message = Message::new(b"Some context", b"Some message");
    let sig = keypair.sign(&message);
    assert!(sig.verify(&message, &keypair.public));
}
