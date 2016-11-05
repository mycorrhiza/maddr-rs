#![recursion_limit = "1024"]

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
