# bls [![Crates.io](https://img.shields.io/crates/v/w3f-bls.svg)](https://crates.io/crates/w3f-bls) #

Boneh-Lynn-Shacham (BLS) signatures have slow signing, very slow verification, require slow and much less secure pairing friendly curves, and tend towards dangerous malleability.  Yet, BLS permits a diverse array of signature aggregation options far beyond any other known signature scheme, which makes BLS a preferred scheme for voting in consensus algorithms and for threshold signatures. 

In this crate, we take a largely unified approach to aggregation techniques and verifier optimisations for BLS signature:  We support the [BLS12-381](https://z.cash/blog/new-snark-curve.html) and [BLS12-377](https://eprint.iacr.org/2018/962.pdf) (Barreto-Lynn-Scott) curves via Arkworks traits, but abstract the pairing so that developers can choose their preferred orientation for BLS signatures. We provide aggregation techniques based on messages being distinct, on proofs-of-possession, and on delinearization, although we do not provide all known optimisations for delinearization.

We provide implementation of generation and verification proof-of-possession based on Schnorr Signature which is faster than using BLS Signature itself for this task.

We cannot claim these abstractions provide miss-use resistance, but they at least structure the problem, provide some guidlines, and maximize the relevance of warnings present in the documentation.

## Documentation

You first bring the `bls` crate into your project just as you normally would.

```rust
use bls_like::{Keypair,ZBLS,Message,Signed};

let mut keypair = Keypair::<ZBLS>::generate(::rand::thread_rng());
let message = Message::new(b"Some context",b"Some message");
let sig = keypair.sign(message);
assert!( sig.verify(message,&keypair.public) );
```

In this example, `sig` is a `Signature<ZBLS>` which only contains signature. One can use `Keypair::signed_message` method which returns a `SignedMessage` struct that contains the message hash, the signer's public key, and of course the signature, but one should usually detach these constituents for wire formats.

Aggregated and blind signatures are almost the only reasons anyone would consider using BLS signatures, so we focus on aggregation here.  We assume for brevity that `sigs` is an array of `SignedMessage`s, as one might construct like 

As a rule, aggregation that requires distinct messages still requires one miller loop step per message, so aggregate signatures have rather slow verification times.  You can nevertheless achieve quite small signature sizes like

```rust
use bls_like::{Keypair,ZBLS,Message,Signed, distinct::DistinctMessages};
  
let mut keypairs = [Keypair::<ZBLS>::generate(::rand::thread_rng()), Keypair::<ZBLS>::generate(::rand::thread_rng())];
let msgs = ["The ships", "hung in the sky", "in much the same way", "that bricks don’t."].iter().map(|m| Message::new(b"Some context", m.as_bytes())).collect::<Vec<_>>();
let sigs = msgs.iter().zip(keypairs.iter_mut()).map(|(m,k)| k.signed_message(*m)).collect::<Vec<_>>();

let mut dms = sigs.iter().try_fold(
    DistinctMessages::<ZBLS>::new(),
    |dm,sig| dm.add(sig)
).unwrap();
let signature = <&DistinctMessages::<ZBLS> as Signed>::signature(&&dms);

let publickeys = keypairs.iter().map(|k|k.public).collect::<Vec<_>>();
let mut dms = msgs.iter().zip(publickeys).try_fold(
    DistinctMessages::<ZBLS>::new(), 
    |dm,(message,publickey)| dm.add_message_n_publickey(*message,publickey)
).unwrap();
dms.add_signature(&signature);
assert!(dms.verify())
```
Anyone who receives the already aggregated signature along with a list of messages and public keys might reconstruct the signature as shown in the above example.

We recommend distinct message aggregation like this primarily for verifying proofs-of-possession, meaning checking the self certificates for numerous keys.

Assuming you already have proofs-of-possession, then you'll want to do aggregation with `BitPoPSignedMessage` or some variant tuned to your use case.  We recommend more care when using `SignatureAggregatorAssumingPoP` because it provides no mechanism for checking a proof-of-possession table.

The library offers method for generating and verifying proof of positions based on [Schnorr Signature](https://en.wikipedia.org/wiki/Schnorr_signature) which is significantly faster to verify than when using BLS signature itself as proof of position. The following example demonstrate how to generate and verify proof of positions and then using `SignatureAggregatorAssumingPoP` to batch and verify multiple BLS signatures.

```rust
use bls_like::{Keypair,ZBLS,Message,Signed, pop::SignatureAggregatorAssumingPoP, pop::{ProofOfPossessionGenerator, ProofOfPossessionVerifier}};
use sha2::Sha512;

let mut keypairs = [Keypair::<ZBLS>::generate(::rand::thread_rng()), Keypair::<ZBLS>::generate(::rand::thread_rng())];
let msgs = ["The ships", "hung in the sky", "in much the same way", "that bricks don’t."].iter().map(|m| Message::new(b"Some context", m.as_bytes())).collect::<Vec<_>>();
let sigs = msgs.iter().zip(keypairs.iter_mut()).map(|(m,k)| k.sign(*m)).collect::<Vec<_>>();

let challenge_message = Message::new(b"ctx",b"sign this message, if you really have the secret key");
let publickeys_with_pop = keypairs.iter().map(|k|(k.public,<dyn ProofOfPossessionGenerator<ZBLS, Sha512>>::generate_pok(&k.secret, challenge_message))).collect::<Vec<_>>();

//first make sure public keys have valid pop
let publickeys = publickeys_with_pop.iter().map(|(publickey, pop) | {assert!(<dyn ProofOfPossessionVerifier<ZBLS, Sha512>>::verify_pok(publickey, challenge_message, *pop)); publickey}).collect::<Vec<_>>();

let mut batch_poped = msgs.iter().zip(publickeys).zip(sigs).fold(
    SignatureAggregatorAssumingPoP::<ZBLS>::new(),
    |mut bpop,((message, publickey),sig)| { bpop.add_message_n_publickey(message, &publickey); bpop.add_signature(&sig); bpop }
);
assert!(batch_poped.verify())
```

If you lack proofs-of-possesion, then delinearized approaches are provided in the `delinear` module, but such schemes might require a more customised approach.

### Efficient Aggregatable BLS Signatures with Chaum-Pedersen Proofs

The scheme introduced in [`our recent paper`](https://eprint.iacr.org/2022/1611) is implemented in [`chaum_pederson_signature.rs`](src/chaum_pederson_signature.rs) using `ChaumPedersonSigner` and `ChaumPedersonVerifier` traits and in [`pop.rs`](src/pop.rs) using `add_auxiliary_public_key` and `verify_using_aggregated_auxiliary_public_keys` functions. See benchmark tests for more how to use this scheme.

### Hash to Curve

In order to sign a message, the library needs to hash the message as a point on the signature curve. While `BLSEngine` trait is agnostic about `MapToSignatureCurve` method, our implementation of BLS12-381 (`ZBLS`) and BLS12-377(`BLS377`) specifically uses Wahby and Boneh hash to curve method described in Section of 6.6.3 of https://datatracker.ietf.org/doc/draft-irtf-cfrg-hash-to-curve/ .

## Security Warnings

This library does not make any guarantees about constant-time operations, memory access patterns, or resistance to side-channel attacks.

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

