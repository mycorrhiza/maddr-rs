use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use mhash::MultiHash;

#[allow(variant_size_differences)]
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
    Ipfs(MultiHash),

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

impl From<IpAddr> for Segment {
    fn from(ip: IpAddr) -> Segment {
        match ip {
            IpAddr::V4(ip) => ip.into(),
            IpAddr::V6(ip) => ip.into(),
        }
    }
}

impl From<Ipv4Addr> for Segment {
    fn from(ip: Ipv4Addr) -> Segment {
        Segment::IP4(ip)
    }
}

impl From<Ipv6Addr> for Segment {
    fn from(ip: Ipv6Addr) -> Segment {
        Segment::IP6(ip)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use Segment;

    #[test]
    fn from_ip4() {
        assert_eq!(
            Segment::IP4(Ipv4Addr::new(1, 2, 3, 4)),
            Ipv4Addr::new(1, 2, 3, 4).into());
    }

    #[test]
    fn from_ip6() {
        assert_eq!(
            Segment::IP6(Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0x11, 0x11)),
            Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0x11, 0x11).into());
    }

    #[test]
    fn from_ip_ip4() {
        assert_eq!(
            Segment::IP4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)).into());
    }

    #[test]
    fn from_ip_ip6() {
        assert_eq!(
            Segment::IP6(Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0x11, 0x11)),
            IpAddr::V6(Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0x11, 0x11)).into());
    }
}
