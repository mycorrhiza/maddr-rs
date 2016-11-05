# maddr [![travis-badge][]][travis] [![cargo-badge][]][cargo] ![license-badge][]

A Rust implementation of the [multiaddr][] format as used in [IPFS][].

## Developing

This project uses [clippy][] and denies warnings in CI builds. To ensure your
changes will be accepted please check them with `cargo clippy` (available via
`cargo install clippy` on nightly rust) before submitting a pull request (along
with `cargo test` as usual).

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you shall be dual licensed as above, without any
additional terms or conditions.

[travis-badge]: https://img.shields.io/travis/mycorrhiza/maddr-rs/master.svg?style=flat-square
[travis]: https://travis-ci.org/mycorrhiza/maddr-rs
[cargo-badge]: https://img.shields.io/crates/v/maddr.svg?style=flat-square
[cargo]: https://crates.io/crates/maddr
[license-badge]: https://img.shields.io/badge/license-MIT/Apache--2.0-lightgray.svg?style=flat-square

[multiaddr]: https://github.com/multiformats/multiaddr
[ipfs]: https://ipfs.io
[clippy]: https://github.com/Manishearth/rust-clippy
