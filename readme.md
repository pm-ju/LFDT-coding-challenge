# lockness-challenge

A Rust library crate implementing the ElGamal-like XOR stream cipher
described in the [LFDT Lockness mentorship coding challenge][lockness].
Built on top of [`generic-ec`][generic-ec] for curve-agnostic elliptic-curve
arithmetic.

> **Warning:** this cryptosystem is intentionally insecure — it is a pedagogical
> exercise, not a real encryption scheme.

## Scheme

```text
Encrypt(pk, M):
    eph ← Zq
    R   = G · eph
    S   = pk · eph
    K   = Expand(SHA-256(encode(S)), len(M))
    C   = M ⊕ K
    return encode(R) ‖ C
```

Decryption recovers S = R · sk and derives the same keystream.

`Expand(B, L)` repeats `B` until it reaches `L` bytes, truncating the
last copy as needed.

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

## Building & testing

```text
cargo test          # 45+ tests, including all 9 challenge vectors
cargo clippy        # zero warnings
cargo fmt -- --check
```

## Design decisions

- **Generic over `E: Curve`**, tested against ed25519, secp256k1, and secp384r1.
- **No panics** — `unwrap` / `expect` / `panic!` are denied by clippy lints
  in library code. All fallible operations return `Result<_, Error>`.
- **`#![forbid(unsafe_code)]`** — no unsafe blocks anywhere.
- **`Ciphertext` encapsulation** — fields are `pub(crate)`; access through
  `ephemeral()` / `body()` / `to_bytes()` / `from_bytes()`.
- **`zeroize`** on intermediate key material (SHA-256 hash used for keystream
  derivation).
- **Deterministic test path** — `encrypt_with_ephemeral` (crate-internal) lets
  tests pin the randomness without exposing a footgun in the public API.

## Layout

```text
src/
  lib.rs          crate root, public re-exports
  error.rs        Error enum
  ciphertext.rs   Ciphertext<E> + wire format
  expand.rs       Expand(B, L) helper
  encrypt.rs      encrypt, encrypt_to_bytes, keystream derivation
  decrypt.rs      decrypt, decrypt_from_bytes
  tests.rs        challenge vectors, round-trips, edge cases
```

[lockness]: https://github.com/LFDT-Lockness
[generic-ec]: https://docs.rs/generic-ec/0.5.0/generic_ec/