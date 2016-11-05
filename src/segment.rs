use std::net::{ Ipv4Addr, Ipv6Addr };

use mhash::MultiHash;

#[derive(PartialEq, Eq, Clone)]
pub enum Segment {
    Dccp(u16),
    Http,
    Https,
    IP4(Ipv4Addr),
    IP6(Ipv6Addr),
    Ipfs(MultiHash<Vec<u8>>),
    Sctp(u16),
    Tcp(u16),
    Udp(u16),
    Udt,
    Utp,
}

impl Segment {
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
