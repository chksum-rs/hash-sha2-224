# chksum-hash-sha2-224

[![crates.io](https://img.shields.io/crates/v/chksum-hash-sha2-224?style=flat-square&logo=rust "crates.io")](https://crates.io/crates/chksum-hash-sha2-224)
[![Build](https://img.shields.io/github/actions/workflow/status/chksum-rs/hash-sha2-224/rust.yml?branch=master&style=flat-square&logo=github "Build")](https://github.com/chksum-rs/hash-sha2-224/actions/workflows/rust.yml)
[![docs.rs](https://img.shields.io/docsrs/chksum-hash-sha2-224?style=flat-square&logo=docsdotrs "docs.rs")](https://docs.rs/chksum-hash-sha2-224/)
[![MSRV](https://img.shields.io/badge/MSRV-1.63.0-informational?style=flat-square "MSRV")](https://github.com/chksum-rs/hash-sha2-224/blob/master/Cargo.toml)
[![deps.rs](https://deps.rs/crate/chksum-hash-sha2-224/0.0.1/status.svg?style=flat-square "deps.rs")](https://deps.rs/crate/chksum-hash-sha2-224/0.0.1)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg?style=flat-square "unsafe forbidden")](https://github.com/rust-secure-code/safety-dance)
[![LICENSE](https://img.shields.io/github/license/chksum-rs/hash-sha2-224?style=flat-square "LICENSE")](https://github.com/chksum-rs/hash-sha2-224/blob/master/LICENSE)

An implementation of SHA-2 224 hash algorithm for batch and stream computation.

## Setup

To use this crate, add the following entry to your `Cargo.toml` file in the `dependencies` section:

```toml
[dependencies]
chksum-hash-sha2-224 = "0.0.1"
```

Alternatively, you can use the [`cargo add`](https://doc.rust-lang.org/cargo/commands/cargo-add.html) subcommand:

```shell
cargo add chksum-hash-sha2-224
```

## Usage

Use the `hash` function for batch digest calculation.

```rust
use chksum_hash_sha2_224 as sha2_224;

let digest = sha2_224::hash(b"example data");
assert_eq!(
    digest.to_hex_lowercase(),
    "90382cbfda2656313ad61fd74b32ddfa4bcc118f660bd4fba9228ced"
);
```

Use the `default` function to create a hash instance for stream digest calculation.

```rust
use chksum_hash_sha2_224 as sha2_224;

let digest = sha2_224::default()
    .update("example")
    .update(b"data")
    .update([0, 1, 2, 3])
    .digest();
assert_eq!(
    digest.to_hex_lowercase(),
    "6325c53dd1a5d4772c0821dc28a9e4eef02b0803dc18b33522928242"
);
```

For more usage examples, refer to the documentation available at [docs.rs](https://docs.rs/chksum-hash-sha2-224/).

## License

This crate is licensed under the MIT License.
