use std::io;
use std::net::{ Ipv4Addr, Ipv6Addr };

use varint::ReadVarInt;
use multihash::ReadMultiHash;

use { MultiAddr, Segment };
use Segment::*;

trait ReadHelper {
    fn read_u8(&mut self) -> io::Result<u8>;
    fn read_u16_be(&mut self) -> io::Result<u16>;
    fn read_ipv4addr(&mut self) -> io::Result<Ipv4Addr>;
    fn read_ipv6addr(&mut self) -> io::Result<Ipv6Addr>;
    fn check_empty(&mut self) -> io::Result<()>;
    fn read_segment(&mut self, code: u64) -> io::Result<Segment>;
    fn try_read_segment(&mut self) -> io::Result<Option<Segment>>;
}

impl<R: io::Read> ReadHelper for R {
    fn read_u8(&mut self) -> io::Result<u8> {
        let mut buffer = [0];
        try!(self.read_exact(&mut buffer));
        Ok(buffer[0])
    }

    fn read_u16_be(&mut self) -> io::Result<u16> {
        let mut buffer = [0; 2];
        try!(self.read_exact(&mut buffer));
        Ok(((buffer[0] as u16) << 8) + (buffer[1] as u16))
    }

    fn read_ipv4addr(&mut self) -> io::Result<Ipv4Addr> {
        let mut buffer = [0; 4];
        try!(self.read_exact(&mut buffer));
        Ok(Ipv4Addr::from(buffer))
    }

    fn read_ipv6addr(&mut self) -> io::Result<Ipv6Addr> {
        let mut buffer = [0; 16];
        try!(self.read_exact(&mut buffer));
        Ok(Ipv6Addr::from(buffer))
    }

    fn check_empty(&mut self) -> io::Result<()> {
        let mut buffer = [0];
        if try!(self.read(&mut buffer)) == 0 {
            Ok(())
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "Unexpected extra bytes"))
        }
    }

    fn read_segment(&mut self, code: u64) -> io::Result<Segment> {
        Ok(match code {
            4 => IP4(try!(self.read_ipv4addr())),
            6 => Tcp(try!(self.read_u16_be())),
            17 => Udp(try!(self.read_u16_be())),
            33 => Dccp(try!(self.read_u16_be())),
            41 => IP6(try!(self.read_ipv6addr())),
            132 => Sctp(try!(self.read_u16_be())),
            301 => Udt,
            302 => Utp,
            421 => {
                let length = try!(self.read_u64_varint());
                let mut hash_bytes = io::Read::take(self, length);
                let multihash = try!(hash_bytes.read_multihash());
                try!(hash_bytes.check_empty());
                Ipfs(multihash)
            }
            443 => Https,
            480 => Http,
            _ => {
                return Err(io::Error::new(io::ErrorKind::Other, "Invalid code"))
            }
        })
    }

    fn try_read_segment(&mut self) -> io::Result<Option<Segment>> {
        if let Some(code) = try!(self.try_read_u64_varint()) {
            Ok(Some(try!(self.read_segment(code))))
        } else {
            Ok(None)
        }
    }
}

pub trait ReadMultiAddr {
    fn read_multiaddr(&mut self) -> io::Result<MultiAddr>;
}

impl<R: io::Read> ReadMultiAddr for R {
    fn read_multiaddr(&mut self) -> io::Result<MultiAddr> {
        // multiaddr lacks any header telling us how far to read, assume the
        // io::Read used has been correctly sized externally to only return the
        // expected bytes for the multiaddr and keep reading till EOF is
        // reached when attempting to read a segment code (any other EOF is
        // treated as an error).
        let mut segments = Vec::new();
        loop {
            if let Some(segment) = try!(self.try_read_segment()) {
                segments.push(segment);
            } else {
                break;
            }
        }
        try!(self.check_empty());
        Ok(MultiAddr::new(segments))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{ Ipv4Addr, Ipv6Addr };
    use { Segment, MultiAddr, ReadMultiAddr };
    use multihash::MultiHash;

    #[test]
    fn ip4() {
        let mut buffer: &[u8] = &[4, 1, 2, 3, 4];
        assert_eq!(
            buffer.read_multiaddr().unwrap(),
            MultiAddr::new(vec![Segment::IP4(Ipv4Addr::new(1, 2, 3, 4))]));
    }

    #[test]
    fn ip6() {
        let mut buffer: &[u8] = &[
            41,
            0x2a, 0x02, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x11,
        ];
        let ip = Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0x11, 0x11);
        assert_eq!(
            buffer.read_multiaddr().unwrap(),
            MultiAddr::new(vec![Segment::IP6(ip)]));
    }

    #[test]
    fn ipfs() {
        let multihash = MultiHash::Sha2_256([
            213, 46, 187, 137, 216, 91, 2, 162,
            132, 148, 130, 3, 166, 47, 242, 131,
            137, 197, 124, 159, 66, 190, 236, 78,
            194, 13, 183, 106, 104, 145, 28, 11,
        ], 32);

        let mut buffer: &[u8] = &[
            0b10100101, 0b00000011, 34,
            0x12, 32,
            213, 46, 187, 137, 216, 91, 2, 162,
            132, 148, 130, 3, 166, 47, 242, 131,
            137, 197, 124, 159, 66, 190, 236, 78,
            194, 13, 183, 106, 104, 145, 28, 11
        ];
        assert_eq!(
            buffer.read_multiaddr().unwrap(),
            MultiAddr::new(vec![Segment::Ipfs(multihash)]));
    }
}
