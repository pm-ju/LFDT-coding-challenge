Here is the demo video provided for testing demo of this challenge:

# Working formula:

[Google drive of PDF of coding challenge]: https://drive.google.com/file/d/1JeBaZkQf2ZpKciUbwQqd4Bz9clNS1Mdp/view?usp=sharing

## Usage

```rust,ignore
use generic_ec::curves::Secp256k1;
use generic_ec::{Point, SecretScalar};
use rand::rngs::OsRng;
use lockness_challenge::{encrypt, decrypt};

let sk = SecretScalar::<Secp256k1>::random(&mut OsRng);
let pk = Point::generator() * &sk;

let ct = encrypt(&pk, b"hello", &mut OsRng).unwrap();
assert_eq!(decrypt(&sk, &ct).unwrap(), b"hello");
```

# How to build and use

```text
cargo test          
cargo clippy        
cargo fmt -- --check
```
[lockness]: https://github.com/LFDT-Lockness
[generic-ec]: https://docs.rs/generic-ec/0.5.0/generic_ec/
