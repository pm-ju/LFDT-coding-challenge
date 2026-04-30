#![allow(clippy::unwrap_used, clippy::expect_used)]

use generic_ec::curves::{Ed25519, Secp256k1, Secp384r1};
use generic_ec::{Curve, Point, Scalar, SecretScalar};
use rand::rngs::OsRng;

use crate::encrypt::encrypt_with_ephemeral;
use crate::{decrypt, decrypt_from_bytes, encrypt, encrypt_to_bytes, Ciphertext, Error};

fn keypair<E: Curve>(sk_val: u32) -> (SecretScalar<E>, Point<E>) {
    let sk = SecretScalar::<E>::new(&mut Scalar::from(sk_val));
    let pk = Point::<E>::generator() * &sk;
    (sk, pk)
}

fn challenge_keypair<E: Curve>() -> (SecretScalar<E>, Point<E>) {
    keypair::<E>(65537)
}

fn verify_vector<E: Curve>(ct_hex: &str, msg_hex: &str) {
    let (sk, _) = challenge_keypair::<E>();
    let ct_bytes = hex::decode(ct_hex).unwrap();
    let msg = hex::decode(msg_hex).unwrap();
    assert_eq!(decrypt_from_bytes::<E>(&sk, &ct_bytes).unwrap(), msg);
}

// Challenge test vectors — Section 2.1, private scalar = 65537 (base 10).

#[test]
fn ed25519_zeros() {
    verify_vector::<Ed25519>(
        "83789da3b47511d971be426996e29773dbf1fd0b5d4117dc3f6197ac3b390b16\
         021c4d4dcacd69fa6ddfbd70272254a8c1d6caa1553718b4b592f518ca856030",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn ed25519_ones() {
    verify_vector::<Ed25519>(
        "63dddd19ca1aae622af6419925c1ccb6aa009255f08fc8f36ebc96aeffb0e575\
         cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64\
         cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64\
         cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64\
         cc8408cbb3762fb4bbfdfb36f62cbc4e9dfaaab0882d62acc16f7d77e366af64",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
}

#[test]
fn ed25519_text() {
    verify_vector::<Ed25519>(
        "b453eb48c662ee52064508cf2c0cae99a36e1eaca32141c9a9fa15d3f0851b7c\
         6c7bd0aeb14d7e7ee098eac3e03360d3b35b13432fced2ef3b83f313208bcfde\
         433e94b4b704377ee69cead8ea343fd3b413185e3ececee16e9ceb15a7908a98\
         067495fdb24b782dac9da5c0eb246c9fb15c00593e",
        "4a652073756973206c61206d65722c20632765737420706f757271756f69206a\
         6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c\
         206a6520766f757320646f6e6e65206c6120766965",
    );
}

#[test]
fn secp256k1_zeros() {
    verify_vector::<Secp256k1>(
        "028ff73c6a81376adeb0a5b9d3e0a89de67ef1215174c1b53a953bc51a5849ad\
         4940c21b932a166cb2b913778a30f500b4f1c09d48c2549560c9f5513a6cf395\
         f1",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn secp256k1_ones() {
    verify_vector::<Secp256k1>(
        "022361daf6095c336b21f3ae6a9cb3a4389071e65f3dddc910783fd2805f80d0\
         660ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b\
         f60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b\
         f60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b\
         f60ca42649522059373a5677b2391fe1c2dd718724bb984bb0b926e32c26123b\
         f6",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
}

#[test]
fn secp256k1_text() {
    verify_vector::<Secp256k1>(
        "0209f092f4d63ca4efa0e639fb6225039a406cff3123e37b8b3bb5271cd75879\
         5f5a44b3beca08af02c430eec8b4f83785314f463c9ad9eeb96eb978ce14e661\
         a27501f7a4cc41e602c234eed3beff688536074d218bd9f2b73ba660c893fd24\
         e4304bf6edc90ea9518835a1cbbfef3bc9334855268b",
        "4a652073756973206c61206d65722c20632765737420706f757271756f69206a\
         6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c\
         206a6520766f757320646f6e6e65206c6120766965",
    );
}

#[test]
fn secp384r1_zeros() {
    verify_vector::<Secp384r1>(
        "03e448a1a9041bda41d16e521223572ed634169df6cd56ce5ae7f42b3914497a\
         fb8156b91c3f5baa12b4d81b5f44f2eb402399e501ed395e834c44d5c85008ef\
         0a8b281240c5d409e4d1b85a586e493332",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
}

#[test]
fn secp384r1_ones() {
    verify_vector::<Secp384r1>(
        "0289b66ed7a9f3a649057afee3700e5ea217e059b88f05e76054991f133ec2fa\
         5abb536caf174cc3258bf387f3e72e496c018163905de06e3a718c353cc3932c\
         d63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932c\
         d63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932c\
         d63e456eea56a0548bba4fe135f73faa9e018163905de06e3a718c353cc3932c\
         d63e456eea56a0548bba4fe135f73faa9e",
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\
         ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    );
}

#[test]
fn secp384r1_text() {
    verify_vector::<Secp384r1>(
        "035371df7afefe2df5d492d62754bf6aa28aa269b1ea58936235f6c4a22e7a0a\
         3e79b4895fe83593a0cbe39b4010d96c63d39a10133ef7f68aabfc63253f4537\
         337539a69d1792df589046a3fcc51d6780fcdf540938bebf8aadf8633e354268\
         337271ad800692c356c559bbfa420622c6b99555403df1f0d9e7f92c2634523b\
         7f773eb58706",
        "4a652073756973206c61206d65722c20632765737420706f757271756f69206a\
         6520646973203a206a6520766f757320646f6e6e65206c61206d6973e872652c\
         206a6520766f757320646f6e6e65206c6120766965",
    );
}

// Round-trip property: decrypt(encrypt(m)) == m for arbitrary messages.

fn assert_round_trip<E: Curve>(msg: &[u8]) {
    let (sk, pk) = challenge_keypair::<E>();
    let ct = encrypt::<E>(&pk, msg, &mut OsRng).unwrap();
    assert_eq!(decrypt::<E>(&sk, &ct).unwrap(), msg);
}

fn assert_round_trip_bytes<E: Curve>(msg: &[u8]) {
    let (sk, pk) = challenge_keypair::<E>();
    let wire = encrypt_to_bytes::<E>(&pk, msg, &mut OsRng).unwrap();
    assert_eq!(decrypt_from_bytes::<E>(&sk, &wire).unwrap(), msg);
}

macro_rules! round_trip_suite {
    ($curve:ty, $name:ident) => {
        mod $name {
            use super::*;

            #[test]
            fn one_byte() {
                assert_round_trip::<$curve>(&[0x42]);
            }

            #[test]
            fn sub_hash_block() {
                assert_round_trip::<$curve>(&[0xAB; 31]);
            }

            #[test]
            fn exact_hash_block() {
                assert_round_trip::<$curve>(&[0xCD; 32]);
            }

            #[test]
            fn over_hash_block() {
                assert_round_trip::<$curve>(&[0xEF; 33]);
            }

            #[test]
            fn multi_block() {
                assert_round_trip::<$curve>(&[0x77; 1024]);
            }

            #[test]
            fn large_message() {
                assert_round_trip::<$curve>(&vec![0xDE; 8192]);
            }

            #[test]
            fn all_byte_values() {
                let msg: Vec<u8> = (0..=255).cycle().take(512).collect();
                assert_round_trip::<$curve>(&msg);
            }

            #[test]
            fn wire_format_round_trip() {
                assert_round_trip_bytes::<$curve>(b"lockness round-trip");
            }
        }
    };
}

round_trip_suite!(Ed25519, ed25519_rt);
round_trip_suite!(Secp256k1, secp256k1_rt);
round_trip_suite!(Secp384r1, secp384r1_rt);

// Deterministic encryption: same ephemeral ⇒ same ciphertext.

#[test]
fn fixed_ephemeral_is_deterministic() {
    let (sk, pk) = challenge_keypair::<Secp256k1>();
    let eph = SecretScalar::<Secp256k1>::new(&mut Scalar::from(12345_u32));
    let msg = b"deterministic";

    let a = encrypt_with_ephemeral::<Secp256k1>(&pk, msg, &eph).unwrap();
    let b = encrypt_with_ephemeral::<Secp256k1>(&pk, msg, &eph).unwrap();
    assert_eq!(a.to_bytes(), b.to_bytes());
    assert_eq!(decrypt::<Secp256k1>(&sk, &a).unwrap(), msg);
}

// Different ephemeral ⇒ different ciphertext for the same plaintext.

#[test]
fn distinct_ephemerals_differ() {
    let (_, pk) = challenge_keypair::<Secp256k1>();
    let msg = b"non-deterministic check";

    let e1 = SecretScalar::<Secp256k1>::new(&mut Scalar::from(111_u32));
    let e2 = SecretScalar::<Secp256k1>::new(&mut Scalar::from(222_u32));

    let c1 = encrypt_with_ephemeral::<Secp256k1>(&pk, msg, &e1).unwrap();
    let c2 = encrypt_with_ephemeral::<Secp256k1>(&pk, msg, &e2).unwrap();
    assert_ne!(c1.to_bytes(), c2.to_bytes());
}

// Error paths.

#[test]
fn rejects_empty_plaintext() {
    let (_, pk) = challenge_keypair::<Secp256k1>();
    assert!(matches!(
        encrypt::<Secp256k1>(&pk, &[], &mut OsRng),
        Err(Error::EmptyInput)
    ));
}

#[test]
fn rejects_truncated_ciphertext() {
    let (sk, pk) = challenge_keypair::<Secp256k1>();
    let wire = encrypt_to_bytes::<Secp256k1>(&pk, b"x", &mut OsRng).unwrap();

    let point_only = &wire[..Point::<Secp256k1>::serialized_len(true)];
    assert!(matches!(
        decrypt_from_bytes::<Secp256k1>(&sk, point_only),
        Err(Error::InvalidCiphertext)
    ));
}

#[test]
fn rejects_too_short_blob() {
    let (sk, _) = challenge_keypair::<Secp256k1>();
    assert!(matches!(
        decrypt_from_bytes::<Secp256k1>(&sk, &[0u8; 4]),
        Err(Error::InvalidCiphertext)
    ));
}

#[test]
fn corrupted_point_does_not_recover_original() {
    let (sk, pk) = challenge_keypair::<Secp256k1>();
    let mut wire = encrypt_to_bytes::<Secp256k1>(&pk, b"test", &mut OsRng).unwrap();
    wire[1] ^= 0xFF;

    match decrypt_from_bytes::<Secp256k1>(&sk, &wire) {
        Err(_) => {}                       // point decode failed — fine
        Ok(pt) => assert_ne!(pt, b"test"), // decoded a different point — wrong plaintext
    }
}

#[test]
fn wrong_key_gives_garbage() {
    let (_, pk) = challenge_keypair::<Secp256k1>();
    let ct = encrypt::<Secp256k1>(&pk, b"classified", &mut OsRng).unwrap();

    let (wrong_sk, _) = keypair::<Secp256k1>(99999);
    assert_ne!(decrypt::<Secp256k1>(&wrong_sk, &ct).unwrap(), b"classified");
}

// Ciphertext serialization invariants.

#[test]
fn ciphertext_wire_round_trip() {
    let (_, pk) = challenge_keypair::<Secp256k1>();
    let ct = encrypt::<Secp256k1>(&pk, b"serde", &mut OsRng).unwrap();
    let wire = ct.to_bytes();
    let ct2 = Ciphertext::<Secp256k1>::from_bytes(&wire).unwrap();

    assert_eq!(ct, ct2);
    assert_eq!(ct.encoded_len(), wire.len());
}

#[test]
fn ciphertext_len_matches() {
    for msg_len in [1, 31, 32, 33, 64, 128, 255, 1024] {
        let expected = Point::<Secp256k1>::serialized_len(true) + msg_len;
        assert_eq!(
            crate::encrypt::ciphertext_len::<Secp256k1>(msg_len),
            expected
        );
    }
}
