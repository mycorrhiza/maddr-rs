use std::str::FromStr;
use std::num::ParseIntError;
use std::net::AddrParseError;
use std::borrow::Cow;
use std::io;

use supra_base58::FromBase58;
use supra_multihash::ReadMultiHash;

use { Segment, MultiAddr };

#[derive(Debug)]
pub enum ParseSegmentError {
    Str(Cow<'static, str>),
    Num(ParseIntError),
    Addr(AddrParseError),
    Io(io::Error),
}

impl From<&'static str> for ParseSegmentError {
    fn from(s: &'static str) -> ParseSegmentError {
        ParseSegmentError::Str(s.into())
    }
}

impl From<String> for ParseSegmentError {
    fn from(s: String) -> ParseSegmentError {
        ParseSegmentError::Str(s.into())
    }
}

impl From<ParseIntError> for ParseSegmentError {
    fn from(err: ParseIntError) -> ParseSegmentError {
        ParseSegmentError::Num(err)
    }
}

impl From<()> for ParseSegmentError {
    fn from(_: ()) -> ParseSegmentError {
        ParseSegmentError::Str("unknown".into())
    }
}

impl From<AddrParseError> for ParseSegmentError {
    fn from(err: AddrParseError) -> ParseSegmentError {
        ParseSegmentError::Addr(err)
    }
}

impl From<io::Error> for ParseSegmentError {
    fn from(err: io::Error) -> ParseSegmentError {
        ParseSegmentError::Io(err)
    }
}

fn segment_from_strs<'a, S: Iterator<Item=&'a str>>(strs: &mut S) -> Result<Option<Segment>, ParseSegmentError> {
    let missing_data = ParseSegmentError::Str(Cow::Borrowed("missing segment data"));
    if let Some(s) = strs.next() {
        match s {
            "ip4" => Ok(Some(Segment::IP4(try!(try!(strs.next().ok_or(missing_data)).parse())))),
            "ip6" => Ok(Some(Segment::IP6(try!(try!(strs.next().ok_or(missing_data)).parse())))),
            "udp" => Ok(Some(Segment::Udp(try!(try!(strs.next().ok_or(missing_data)).parse())))),
            "dccp" => Ok(Some(Segment::Dccp(try!(try!(strs.next().ok_or(missing_data)).parse())))),
            "sctp" => Ok(Some(Segment::Sctp(try!(try!(strs.next().ok_or(missing_data)).parse())))),
            "tcp" => Ok(Some(Segment::Tcp(try!(try!(strs.next().ok_or(missing_data)).parse())))),
            "ipfs" => {
                let bytes = try!(try!(strs.next().ok_or(missing_data)).from_base58());
                let multihash = try!((&bytes[..]).read_multihash());
                Ok(Some(Segment::Ipfs(multihash)))
            }
            "udt" => Ok(Some(Segment::Udt)),
            "utp" => Ok(Some(Segment::Utp)),
            "http" => Ok(Some(Segment::Http)),
            "https" => Ok(Some(Segment::Https)),
            _ => Err(format!("unrecognised segment type {}", s).into()),
        }
    } else {
        Ok(None)
    }
}

impl FromStr for MultiAddr {
    type Err = ParseSegmentError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if &s[0..1] != "/" {
            return Err("didn't start with /".into());
        }
        let mut strs = s[1..].split('/');
        let mut segments = vec![];
        while let Some(segment) = try!(segment_from_strs(&mut strs)) {
            segments.push(segment);
        }
        Ok(MultiAddr::new(segments))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{ Ipv4Addr, Ipv6Addr };
    use supra_multihash as mh;
    use supra_multihash::MultiHash;
    use { MultiAddr, Segment };

    #[test]
    fn ip4() {
        assert_eq!(
            MultiAddr::new(vec![Segment::IP4(Ipv4Addr::new(1, 2, 3, 4))]),
            "/ip4/1.2.3.4".parse().unwrap());
    }

    #[test]
    fn ip6() {
        assert_eq!(
            MultiAddr::new(vec![Segment::IP6(Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0x11, 0x11))]),
            "/ip6/2a02:6b8::11:11".parse().unwrap());
    }

    #[test]
    fn ipfs() {
        let digest = mh::Digest::Sha2_256([
            213, 46, 187, 137, 216, 91, 2, 162,
            132, 148, 130, 3, 166, 47, 242, 131,
            137, 197, 124, 159, 66, 190, 236, 78,
            194, 13, 183, 106, 104, 145, 28, 11,
        ]);
        assert_eq!(
            MultiAddr::new(vec![Segment::Ipfs(MultiHash::new(32, digest))]),
            "/ipfs/QmcgpsyWgH8Y8ajJz1Cu72KnS5uo2Aa2LpzU7kinSupNKC".parse().unwrap());
    }
}
