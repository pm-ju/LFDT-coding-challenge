# lockness challenge submission

here is my implementation of the cryptosystem.

formula/challenge pdf: https://drive.google.com/file/d/1JeBaZkQf2ZpKciUbwQqd4Bz9clNS1Mdp/view?usp=sharing

### how to test

```text
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo run --example demo
```

### quick usage

```rust,ignore
use lockness_challenge::{encrypt, decrypt};
use generic_ec::curves::Secp256k1;
use generic_ec::{Point, SecretScalar};
use rand::rngs::OsRng;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sk = SecretScalar::<Secp256k1>::random(&mut OsRng);
    let pk = Point::generator() * &sk;

    let ct = encrypt(&pk, b"hello", &mut OsRng)?;
    let msg = decrypt(&sk, &ct)?;

    assert_eq!(msg, b"hello");

    Ok(())
}
```
