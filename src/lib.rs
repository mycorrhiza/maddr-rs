#![recursion_limit = "1024"]

#![allow(unknown_lints)] // for clippy
#![warn(fat_ptr_transmutes)]
#![warn(missing_copy_implementations)]
#![warn(missing_debug_implementations)]
#![warn(missing_docs)]
#![warn(trivial_casts)]
#![warn(trivial_numeric_casts)]
#![warn(unused_import_braces)]
#![warn(unused_results)]
#![warn(variant_size_differences)]

//! An implementation of the [multiaddr][] format as used in [IPFS][].
//!
//! [multiaddr]: https://github.com/multiformats/multiaddr
//! [ipfs]: https://ipfs.io

#[macro_use]
extern crate error_chain;
extern crate mhash;
extern crate varmint;

mod multiaddr;
mod segment;

mod display;
mod parse;
mod read;
mod write;

pub use multiaddr::MultiAddr;
pub use segment::Segment;

pub use read::ReadMultiAddr;
pub use write::WriteMultiAddr;
