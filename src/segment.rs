use std::net::{ Ipv4Addr, Ipv6Addr };

use mhash::MultiHash;

#[derive(PartialEq, Eq, Clone)]
/// The possible multiaddr segments.
pub enum Segment {
    /// Datagram Congestion Control Protocol, a transport layer protocol.
    /// The argument is the port number.
    Dccp(u16),

    /// Hypertext Transfer Protocol, an application layer protocol.
    Http,

    /// Hypertext Transfer Protocol layered on top of Transport Layer Security,
    /// an application layer protocol.
    Https,

    /// Internet Protocol version 4, an internet layer protocol.
    /// The argument is the IPv4 address.
    IP4(Ipv4Addr),

    /// Internet Protocol version 6, an internet layer protocol.
    /// The argument is the IPv6 address.
    IP6(Ipv6Addr),

    /// The InterPlanetary File System, an application layer protocol.
    /// The argument is the public hash of an IPFS node.
    Ipfs(MultiHash<Vec<u8>>),

    /// Stream Control Transmission Protocol, a transport layer protocol.
    /// The argument is the port number.
    Sctp(u16),

    /// Transmission Control Protocol, a transport layer protocol.
    /// The argument is the port number.
    Tcp(u16),

    /// User Datagram Protocol, a transport layer protocol.
    /// The argument is the port number.
    Udp(u16),

    /// UDP-based Data Transfer Protocol, an application layer protocol.
    Udt,

    /// Micro Transport Protocol, an application? layer protocol.
    Utp,
}

impl Segment {
    /// The code used in the binary representation of this segment.
    pub fn code(&self) -> u64 {
        match *self {
            Segment::Dccp(_) => 33,
            Segment::Http => 480,
            Segment::Https => 443,
            Segment::IP4(_) => 4,
            Segment::IP6(_) => 41,
            Segment::Ipfs(_) => 421,
            Segment::Sctp(_) => 132,
            Segment::Tcp(_) => 6,
            Segment::Udp(_) => 17,
            Segment::Udt => 301,
            Segment::Utp => 302,
        }
    }

    /// The name used in the string representation of this segment.
    pub fn name(&self) -> &'static str {
        match *self {
            Segment::Dccp(_) => "dccp",
            Segment::Http => "http",
            Segment::Https => "https",
            Segment::IP4(_) => "ip4",
            Segment::IP6(_) => "ip6",
            Segment::Ipfs(_) => "ipfs",
            Segment::Sctp(_) => "sctp",
            Segment::Tcp(_) => "tcp",
            Segment::Udp(_) => "udp",
            Segment::Udt => "udt",
            Segment::Utp => "utp",
        }
    }
}
