#![feature(test)]

extern crate test;

const NO_OF_MULTI_SIG_SIGNERS: usize = 100;
use crate::chaum_pedersen_signature::ChaumPedersenSigner;
use crate::chaum_pedersen_signature::ChaumPedersenVerifier;
use crate::pop_aggregator::SignatureAggregatorAssumingPoP;
use crate::Keypair;
use crate::Message;
use crate::Signature as BLSSignature;
use crate::Signed;
use crate::{CurveExtraConfig, TinyBLS377, TinyBLS381, UsualBLS};
use crate::{EngineBLS, PublicKey};
use ark_ec::twisted_edwards;
use ark_ec::{CurveConfig, CurveGroup};
use ark_ed_by_bls12_381;
use ark_sw_by_bls12_381;
use core::marker::PhantomData;
use sha2::Sha256;
use test::{black_box, Bencher};

use ark_ec::AdditiveGroup;
use ark_ec::PrimeGroup;
use ark_ff::UniformRand;
use rand::thread_rng;

use crate::double_nugget::DoubleNuggetBLS;
use crate::double_nugget_glv::DoubleNuggetBLSGLV;
use crate::double_nugget_glv::NuggetDoublePublicKeyGLV;
use crate::nugget::{NuggetBLS, NuggetSignedMessage};
use crate::experimental::triple_nugget::NuggetTriplePublicKey;
use crate::experimental::triple_nugget::TripleNuggetBLS;
use crate::dual_scalar_mul::NonGLVCurve;
use crate::serialize::SerializableToBytes;
use crate::NuggetDoublePublicKey;
use crate::PublicKeyInSignatureGroup;

// SerializableToBytes for ark_sw_by_bls12_381::SWProjective is implemented in triple_nugget tests

// NonGLVCurve for ark_sw_by_bls12_381::SWProjective is implemented in dual_scalar_mul tests

// #[bench]
// fn only_generate_key_pairs(b: &mut Bencher) {
//     b.iter(|| {

//         let mut keypairs = generate_many_keypairs(NO_OF_MULTI_SIG_SIGNERS);
//     });
// }

// #[bench]
// fn test_many_tiny_aggregate_and_verify_in_g2(b: &mut Bencher) {
//     let message = Message::new(b"ctx",b"test message");
//     let mut keypairs = generate_many_keypairs(NO_OF_MULTI_SIG_SIGNERS);
// let mut pub_keys_in_sig_grp : Vec<PublicKeyInSignatureGroup<TinyBLS377>> = keypairs.iter().map(|k| k.into_public_key_in_signature_group()).collect();

// let mut aggregated_public_key = PublicKey::<TinyBLS377>(<TinyBLS377 as EngineBLS>::PublicKeyGroup::zero());
// let mut aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();

//     for k in &mut keypairs {
//     aggregator.aggregate(&k.signed_message(message));
//     aggregated_public_key.0 += k.public.0;
//     }

//     b.iter(|| {
//     let mut verifier_aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();
//     let mut verifier_aggregated_public_key = PublicKey::<TinyBLS377>(<TinyBLS377 as EngineBLS>::PublicKeyGroup::zero());

//     verifier_aggregator.add_signature(&aggregator.signature);

//     for k in &mut keypairs {
// 	verifier_aggregated_public_key.0 += k.public.0;
//         }

//     verifier_aggregator.add_message_n_publickey(&message, &verifier_aggregated_public_key);

//         assert!(verifier_aggregator.verify());
//     });
// }

// #[bench]
// fn test_many_tiny_aggregate_only_no_verify(b: &mut Bencher) {
//     let mut keypairs = generate_many_keypairs(NO_OF_MULTI_SIG_SIGNERS);
// 	let mut pub_keys_in_sig_grp : Vec<PublicKeyInSignatureGroup<TinyBLS377>> = keypairs.iter().map(|k| k.into_public_key_in_signature_group()).collect();
//     let message = Message::new(b"ctx",b"test message");

//     b.iter(|| {
//         let mut aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();
// 	    let mut aggregated_public_key = PublicKey::<TinyBLS377>(<TinyBLS377 as EngineBLS>::PublicKeyGroup::zero());

//         for k in &mut keypairs {
//             aggregator.aggregate(&k.signed_message(message));
// 		aggregated_public_key.0 += k.public.0;

//         }
//     });
// }

// #[bench]
// fn test_many_tiny_aggregate_and_verify_in_g1(b: &mut Bencher) {
//     let message = Message::new(b"ctx",b"test message");
//     let mut keypairs = generate_many_keypairs(NO_OF_MULTI_SIG_SIGNERS);
//     let mut pub_keys_in_sig_grp : Vec<PublicKeyInSignatureGroup<TinyBLS377>> = keypairs.iter().map(|k| k.into_public_key_in_signature_group()).collect();

//     let mut aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();
// let mut aggregated_public_key = PublicKey::<TinyBLS377>(<TinyBLS377 as EngineBLS>::PublicKeyGroup::zero());

//     for k in &mut keypairs {
//     aggregator.aggregate(&k.signed_message(message));
//     aggregated_public_key.0 += k.public.0;
//     }

//     b.iter(|| {
//     let mut verifier_aggregator = SignatureAggregatorAssumingPoP::<TinyBLS377>::new();

//     verifier_aggregator.add_signature(&aggregator.signature);
//     verifier_aggregator.add_message_n_publickey(&message, &aggregated_public_key);

//         for k in &pub_keys_in_sig_grp {
// 	verifier_aggregator.add_auxiliary_public_key(k);
//     }

//         assert!(verifier_aggregator.verify_using_aggregated_auxiliary_public_keys());

//     });

// }

//#[bench]
// fn test_bls_verify_many_signatures_simple(b: &mut Bencher) {
//     let good = Message::new(b"ctx",b"test message");

//     let mut keypair = Keypair::<TinyBLS377>::generate(thread_rng());
//     let message = Message::new(b"ctx",b"test message");

//     let sig = keypair.signed_message(&message);

// b.iter(||
//     for i in 1..NO_OF_MULTI_SIG_SIGNERS {
//         sig.verify();
//     });
// }

//#[bench]
// fn test_bls_verify_many_signatures_chaum_pedersen_in_signature_group(b: &mut Bencher) {
//     let mut keypair = Keypair::<TinyBLS381>::generate(thread_rng());
//     let message = Message::new(b"ctx", b"test message");

//     let sig = <Keypair<TinyBLS381> as NuggetBLS<
//         TinyBLS381,
//         <TinyBLS381 as EngineBLS>::SignatureGroup,
//     >>::sign(&mut keypair, &message);
//     let double_nugget_public = keypair.into_nugget_double_public_key();

//     b.iter(|| {
//         for i in 1..NO_OF_MULTI_SIG_SIGNERS {
//             assert!(
//                 <NuggetDoublePublicKey<TinyBLS381> as ChaumPedersenVerifier<
//                     TinyBLS381,
//                     <TinyBLS381 as EngineBLS>::SignatureGroup,
//                     Sha256,
//                 >>::verify_cp_signature(&double_nugget_public, &message, &sig)
//             );
//         }
//     });
// }

//#[bench]
// fn test_bls_verify_many_signatures_chaum_pedersen_in_edwards_sister_group(b: &mut Bencher) {
//     let mut keypair = Keypair::<TinyBLS381>::generate(thread_rng());
//     let message = Message::new(b"ctx", b"test message");

//     let sig = <Keypair<TinyBLS381> as NuggetBLS<
//         TinyBLS381,
//         ark_ed_by_bls12_381::EdwardsProjective,
//     >>::sign(&mut keypair, &message);
//     let triple_nugget_public_key: NuggetTriplePublicKey<_, ark_ed_by_bls12_381::EdwardsProjective> =
//         keypair.into_nugget_triple_public_key();

//     b.iter(|| {
//         for i in 1..NO_OF_MULTI_SIG_SIGNERS {
//             assert!(<NuggetTriplePublicKey<
//                 TinyBLS381,
//                 ark_ed_by_bls12_381::EdwardsProjective,
//             > as ChaumPedersenVerifier<
//                 TinyBLS381,
//                 ark_ed_by_bls12_381::EdwardsProjective,
//                 Sha256,
//             >>::verify_cp_signature(
//                 &triple_nugget_public_key, &message, &sig
//             ));
//         }
//     });
// }

// #[bench]
// fn test_scalar_mul_in_signature_group(b: &mut Bencher) {
//     let mut gen = <<TinyBLS381 as EngineBLS>::SignatureGroup as PrimeGroup>::generator();
//     b.iter(|| {
//         let mut random_scalar = TinyBLS381::generate(&mut thread_rng());

//         for _i in 1..NO_OF_MULTI_SIG_SIGNERS {
//             gen *= random_scalar;
//         }
//         println!("result = {gen}")
//     });
// }

// #[bench]
// fn test_scalar_mul_in_signature_group_no_glv_no_mul_by_a(b: &mut Bencher) {
//     let mut gen = <ark_bls12_381::G1Projective as PrimeGroup>::generator();

//     b.iter(|| {
//         let mut random_scalar = <ark_bls12_381::G1Projective as PrimeGroup>::ScalarField::rand(&mut thread_rng());

//         for _i in 1..NO_OF_MULTI_SIG_SIGNERS {
//              gen *= random_scalar;
//         }
//         println!("result = {gen}")
//     });
// }

// #[bench]
// fn test_scalar_mul_in_weirestarss_sister_group(b: &mut Bencher) {

//     let mut gen = <ark_sw_by_bls12_381::SWProjective as PrimeGroup>::generator();
//     b.iter(|| {

//         let mut random_scalar = <ark_sw_by_bls12_381::SWProjective as PrimeGroup>::ScalarField::rand(&mut thread_rng());

//         for _i in 1..NO_OF_MULTI_SIG_SIGNERS {
//              gen *= random_scalar;
//         }
//         println!("result = {gen}")
//     });
// }

// #[bench]
// fn test_add_in_signature_group_no_glv_no_mul_by_a(b: &mut Bencher) {
//     let mut gen = <ark_bls12_381::G1Projective as PrimeGroup>::generator();

//     let mut random_point = loop {
//         let mut r1 = <ark_bls12_381::g1::Config as CurveConfig>::BaseField::rand(&mut thread_rng());
//         let mut random_point = ark_bls12_381::G1Affine::get_point_from_x_unchecked(r1, false);
//         if random_point != None {
//             break random_point.unwrap();
//         }

//     };
//     b.iter(|| {
//         for _i in 1..NO_OF_MULTI_SIG_SIGNERS {
//              gen += random_point;
//         }
//         println!("result = {gen}")
//     });
// }

// #[bench]
// fn test_add_in_weirestarss_sister_group(b: &mut Bencher) {

//     let mut gen = <ark_sw_by_bls12_381::SWProjective as PrimeGroup>::generator();
//     let mut random_point = loop {
//         let mut r1 = <ark_sw_by_bls12_381::SWConfig as CurveConfig>::BaseField::rand(&mut thread_rng());
//         let mut random_point = ark_sw_by_bls12_381::SWAffine::get_point_from_x_unchecked(r1, false);
//         if random_point != None {
//             break random_point.unwrap();
//         }

//     };

//     b.iter(|| {

//         for _i in 1..NO_OF_MULTI_SIG_SIGNERS {
//              gen += random_point;
//         }
//         println!("result = {gen}")
//     });
// }

// #[bench]
// fn test_double_in_signature_group_no_glv_no_mul_by_a(b: &mut Bencher) {
//     let mut gen = <ark_bls12_381::G1Projective as PrimeGroup>::generator();

//     b.iter(|| {
//         let mut random_scalar = <ark_bls12_381::G1Projective as PrimeGroup>::ScalarField::rand(&mut thread_rng());

//         for _i in 1..NO_OF_MULTI_SIG_SIGNERS {
//              gen.double_in_place();
//         }
//         println!("result = {gen}")
//     });
// }

// #[bench]
// fn test_double_in_weirestarss_sister_group(b: &mut Bencher) {

//     let mut gen = <ark_sw_by_bls12_381::SWProjective as PrimeGroup>::generator();
//     b.iter(|| {

//         for _i in 1..NO_OF_MULTI_SIG_SIGNERS {
//              gen.double_in_place();
//         }
//         println!("result = {gen}")
//     });
// }

// #[bench]
// fn test_base_field_mul_in_signature_group(b: &mut Bencher) {

//     b.iter(|| {
//         let mut r1 = <<TinyBLS381 as EngineBLS>::SignatureGroup as CurveGroup>::BaseField::rand(&mut thread_rng());
//         let mut r2 = <<TinyBLS381 as EngineBLS>::SignatureGroup as CurveGroup>::BaseField::rand(&mut thread_rng());

//         for i in 1..NO_OF_MULTI_SIG_SIGNERS {
//             r1 *= r2;
//         }
//         println!("result = {r1}")
//     });
// }

// #[bench]
// fn test_base_field_mul_in_weirestarss_sister_group(b: &mut Bencher) {
//     b.iter(|| {
//         let mut r1 = <ark_sw_by_bls12_381::SWConfig as CurveConfig>::BaseField::rand(&mut thread_rng());
//         let mut r2 = <ark_sw_by_bls12_381::SWConfig as CurveConfig>::BaseField::rand(&mut thread_rng());

//         for i in 1..NO_OF_MULTI_SIG_SIGNERS {
//             r1 *= r2;
//         }
//         println!("result = {r1}")
//     });

// }

// #[bench]
// fn test_verify_cp_signature_naive(b: &mut Bencher) {
//         type EB = TinyBLS<Bls12_381, ark_bls12_381::Config>;

//         let mut keypair = Keypair::<EB>::generate(thread_rng());
//         let message = Message::new(b"ctx", b"test message");
//         let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
//             &mut keypair,
//             &message,
//         );

//         let signed_message = DoubleSignedMessage {
//             message: message,
//             publickey: keypair.into_nugget_double_public_key(),
//             signature: good_sig0,
//             _phantom: PhantomData,
//         };

//         assert!(
//             signed_message.verify(),
//             "valid double signed message should verify"
//         );
// }

#[bench]
fn test_bls_verify_many_signatures_chaum_pedersen_in_weierstrass_sister_group_straus(
    b: &mut Bencher,
) {
    let mut keypair = Keypair::<TinyBLS381>::generate(thread_rng());
    let message = Message::new(b"ctx", b"test message");

    let sig =
        <Keypair<TinyBLS381> as NuggetBLS<TinyBLS381, ark_sw_by_bls12_381::SWProjective>>::sign(
            &mut keypair,
            &message,
        );

    let triple_nugget_public_key: NuggetTriplePublicKey<_, ark_sw_by_bls12_381::SWProjective> =
        keypair.into_nugget_triple_public_key();

    b.iter(|| {
        for i in 0..NO_OF_MULTI_SIG_SIGNERS {
            let i = <NuggetTriplePublicKey<
                TinyBLS381,
                ark_sw_by_bls12_381::SWProjective,
            > as ChaumPedersenVerifier<
                TinyBLS381,
                ark_sw_by_bls12_381::SWProjective,
                Sha256,
            >>::verify_cp_signature(
                &triple_nugget_public_key, &message, &sig
            );
            assert!(i)
        }
    });
}

#[bench]
fn test_bls_verify_many_signatures_chaum_pedersen_in_weierstrass_sister_group_naive(
    b: &mut Bencher,
) {
    let mut keypair = Keypair::<TinyBLS381>::generate(thread_rng());
    let message = Message::new(b"ctx", b"test message");

    let sig =
        <Keypair<TinyBLS381> as NuggetBLS<TinyBLS381, ark_sw_by_bls12_381::SWProjective>>::sign(
            &mut keypair,
            &message,
        );

    let triple_nugget_public_key: NuggetTriplePublicKey<_, ark_sw_by_bls12_381::SWProjective> =
        keypair.into_nugget_triple_public_key();

    b.iter(|| {
        for i in 0..NO_OF_MULTI_SIG_SIGNERS {
            let i = <NuggetTriplePublicKey<
                TinyBLS381,
                ark_sw_by_bls12_381::SWProjective,
            > as ChaumPedersenVerifier<
                TinyBLS381,
                ark_sw_by_bls12_381::SWProjective,
                Sha256,
            >>::verify_cp_signature_naive(
                &triple_nugget_public_key, &message, &sig
            );
            assert!(i)
        }
    });
}

#[bench]
fn test_verify_cp_signature_naive(b: &mut Bencher) {
    type EB = TinyBLS381;

    let mut keypair = Keypair::<EB>::generate(thread_rng());
    let message = Message::new(b"ctx", b"test message");
    let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
        &mut keypair,
        &message,
    );

    let publickey: NuggetDoublePublicKey<EB> =
        DoubleNuggetBLS::<EB>::into_nugget_double_public_key(&keypair);

    //we chaum pederesen verification which is faster
    b.iter(|| {
        for i in 0..NO_OF_MULTI_SIG_SIGNERS {

        let i = ChaumPedersenVerifier::<EB, <EB as EngineBLS>::SignatureGroup, Sha256>::verify_cp_signature_naive(
            &publickey,
            &message,
            &good_sig0,
        );
            assert!(i)
        }
     })
}

#[bench]
fn test_verify_cp_signature_strauss_shamir_without_glv(b: &mut Bencher) {
    type EB = TinyBLS381;

    let mut keypair = Keypair::<EB>::generate(thread_rng());
    let message = Message::new(b"ctx", b"test message");
    let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
        &mut keypair,
        &message,
    );

    let publickey: NuggetDoublePublicKey<EB> =
        DoubleNuggetBLS::<EB>::into_nugget_double_public_key(&keypair);

    //we chaum pederesen verification which is faster
    b.iter(|| {
        for i in 0..NO_OF_MULTI_SIG_SIGNERS {

        let i = ChaumPedersenVerifier::<EB, <EB as EngineBLS>::SignatureGroup, Sha256>::verify_cp_signature(
            &publickey,
            &message,
            &good_sig0,
        );
            assert!(i)
        }
     })
}

#[bench]
fn test_verify_cp_signature_ark_msm(b: &mut Bencher) {
    type EB = TinyBLS381;

    let mut keypair = Keypair::<EB>::generate(thread_rng());
    let message = Message::new(b"ctx", b"test message");
    let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
        &mut keypair,
        &message,
    );

    let publickey: NuggetDoublePublicKey<EB> =
        DoubleNuggetBLS::<EB>::into_nugget_double_public_key(&keypair);

    //we chaum pederesen verification which is faster
    b.iter(|| {
        for i in 0..NO_OF_MULTI_SIG_SIGNERS {
            let i = ChaumPedersenVerifier::<EB, <EB as EngineBLS>::SignatureGroup, Sha256>::verify_cp_signature_with_msm_optimization(
                &publickey,
                &message,
                &good_sig0,
            );
            assert!(i)
        }
     })
}

#[bench]
fn test_verify_cp_signature_strauss_shamir_with_glv(b: &mut Bencher) {
    type EB = TinyBLS381;

    let mut keypair = Keypair::<EB>::generate(thread_rng());
    let message = Message::new(b"ctx", b"test message");
    let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
        &mut keypair,
        &message,
    );

    let publickey: NuggetDoublePublicKeyGLV<EB, ark_bls12_381::g1::Config> =
        DoubleNuggetBLSGLV::<EB, ark_bls12_381::g1::Config>::into_nugget_double_public_key(
            &keypair,
        );

    //we chaum pederesen verification which is faster
    b.iter(|| {
        for i in 0..NO_OF_MULTI_SIG_SIGNERS {
            let i = ChaumPedersenVerifier::<EB, <EB as EngineBLS>::SignatureGroup, Sha256>::verify_cp_signature(
                &publickey,
                &message,
                &good_sig0,
            );
            assert!(i);
        }
     })
}

#[bench]
fn test_verify_signature_with_pairing(b: &mut Bencher) {
    type EB = TinyBLS381;

    let mut keypair = Keypair::<EB>::generate(thread_rng());
    let message = Message::new(b"ctx", b"test message");
    let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
        &mut keypair,
        &message,
    );

    let publickey: NuggetDoublePublicKeyGLV<EB, ark_bls12_381::g1::Config> =
        DoubleNuggetBLSGLV::<EB, ark_bls12_381::g1::Config>::into_nugget_double_public_key(
            &keypair,
        );

    //we chaum pederesen verification which is faster
    b.iter(|| {
        for i in 0..NO_OF_MULTI_SIG_SIGNERS {
            let i = keypair.public.verify(&message, &BLSSignature(good_sig0.0));
            assert!(i);
        }
    })
}

//#[bench]
// fn test_pairing(b: &mut Bencher) {
//     let mut keypair1 = Keypair::<TinyBLS377>::generate(thread_rng());

// let point_1 = keypair1.into_public_key_in_signature_group().0;
// let point_2 = keypair1.public.0;

// b.iter(||
// for i in 0..NO_OF_MULTI_SIG_SIGNERS {
//         TinyBLS377::pairing(point_2, point_1);
//     });

// }

// //#[bench]
// fn test_scalar_multiplication(b: &mut Bencher) {
//     let mut keypair1 = Keypair::<TinyBLS377>::generate(thread_rng());

// let point_1 = keypair1.into_public_key_in_signature_group().0;
// let point_2 = keypair1.public.0;
// let scalar = keypair1.secret.into_vartime().0;

// b.iter(||
//        for i in 0..NO_OF_MULTI_SIG_SIGNERS {
// 	   point_1 * scalar;
//            });

// }

// #[bench]
// fn test_verify_cp_signature_glv_precomputed(b: &mut Bencher) {
//     type EB = TinyBLS381;

//     let mut keypair = Keypair::<EB>::generate(thread_rng());
//     let message = Message::new(b"ctx", b"test message");
//     let good_sig0 = <Keypair<_> as NuggetBLS<_, <EB as EngineBLS>::SignatureGroup>>::sign(
//         &mut keypair,
//         &message,
//     );

//     let publickey: NuggetDoublePublicKeyGLV<EB, ark_bls12_381::g1::Config> =
//         keypair.into_nugget_double_public_key();

//     // Verify with GLV precomputed 256-element table
//     b.iter(|| {
//         let i = ChaumPedersenVerifier::<EB, <EB as EngineBLS>::SignatureGroup, Sha256>::verify_cp_signature(
//             &publickey,
//             &message,
//             &good_sig0,
//         );
//         assert!(i)
//     })
// }
