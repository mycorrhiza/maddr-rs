use std::io;
use std::net::{ Ipv4Addr, Ipv6Addr };

use varint::WriteVarInt;
use multihash::WriteMultiHash;

use { MultiAddr, Segment };
use Segment::*;

trait WriteHelper {
    fn write_u8(&mut self, val: u8) -> io::Result<()>;
    fn write_u16_be(&mut self, val: u16) -> io::Result<()>;
    fn write_ipv4addr(&mut self, addr: &Ipv4Addr) -> io::Result<()>;
    fn write_ipv6addr(&mut self, addr: &Ipv6Addr) -> io::Result<()>;
    fn write_segment(&mut self, segment: &Segment) -> io::Result<()>;
}

impl<W: io::Write> WriteHelper for W {
    fn write_u8(&mut self, val: u8) -> io::Result<()> {
        try!(self.write_all(&[val]));
        Ok(())
    }

    fn write_u16_be(&mut self, val: u16) -> io::Result<()> {
        try!(self.write_all(&[((val >> 8) & 0xFF) as u8, (val & 0xFF) as u8]));
        Ok(())
    }

    fn write_ipv4addr(&mut self, addr: &Ipv4Addr) -> io::Result<()> {
        try!(self.write_all(&addr.octets()));
        Ok(())
    }

    fn write_ipv6addr(&mut self, addr: &Ipv6Addr) -> io::Result<()> {
        // TODO: waiting on https://github.com/rust-lang/rust/issues/32313
        // try!(self.write_all(&addr.octets()));
        let segments = addr.segments();
        try!(self.write_u16_be(segments[0]));
        try!(self.write_u16_be(segments[1]));
        try!(self.write_u16_be(segments[2]));
        try!(self.write_u16_be(segments[3]));
        try!(self.write_u16_be(segments[4]));
        try!(self.write_u16_be(segments[5]));
        try!(self.write_u16_be(segments[6]));
        try!(self.write_u16_be(segments[7]));
        Ok(())
    }

    fn write_segment(&mut self, segment: &Segment) -> io::Result<()> {
        try!(self.write_u64_varint(segment.code()));
        match *segment {
            IP4(ref addr) =>
                try!(self.write_ipv4addr(addr)),
            IP6(ref addr) =>
                try!(self.write_ipv6addr(addr)),
            Udp(port) | Dccp(port) | Sctp(port) | Tcp(port) =>
                try!(self.write_u16_be(port)),
            Ipfs(ref multihash) => {
                try!(self.write_u64_varint(multihash.output_len() as u64));
                try!(self.write_multihash(multihash));
            }
            Udt | Utp | Http | Https => {
            }
        }
        Ok(())
    }
}

pub trait WriteMultiAddr {
    fn write_multiaddr(&mut self, multiaddr: &MultiAddr) -> io::Result<()>;
}

impl<W: io::Write> WriteMultiAddr for W {
    fn write_multiaddr(&mut self, multiaddr: &MultiAddr) -> io::Result<()> {
        for segment in multiaddr.segments() {
            try!(self.write_segment(segment));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::net::{ Ipv4Addr, Ipv6Addr };
    use { Segment, MultiAddr, WriteMultiAddr };
    use multihash::MultiHash;

    #[test]
    fn ip4() {
        let mut buffer = Vec::with_capacity(5);
        buffer.write_multiaddr(&MultiAddr::new(vec![Segment::IP4(Ipv4Addr::new(1, 2, 3, 4))])).unwrap();
        assert_eq!(buffer, vec![4, 1, 2, 3, 4]);
    }

    #[test]
    fn ip6() {
        let mut buffer = Vec::with_capacity(17);
        let addr = Ipv6Addr::new(0x2a02, 0x6b8, 0, 0, 0, 0, 0x11, 0x11);
        buffer.write_multiaddr(&MultiAddr::new(vec![Segment::IP6(addr)])).unwrap();
        assert_eq!(buffer, vec![
            41,
            0x2a, 0x02, 0x06, 0xb8, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x11,
        ]);
    }

    #[test]
    fn ipfs() {
        let multihash = MultiHash::Sha2_256([
            213, 46, 187, 137, 216, 91, 2, 162,
            132, 148, 130, 3, 166, 47, 242, 131,
            137, 197, 124, 159, 66, 190, 236, 78,
            194, 13, 183, 106, 104, 145, 28, 11,
        ], 32);
        let segment = Segment::Ipfs(multihash);

        let mut buffer = Vec::with_capacity(37);
        buffer.write_multiaddr(&MultiAddr::new(vec![segment])).unwrap();
        assert_eq!(buffer, vec![
            0b10100101, 0b00000011, 34,
            0x12, 32,
            213, 46, 187, 137, 216, 91, 2, 162,
            132, 148, 130, 3, 166, 47, 242, 131,
            137, 197, 124, 159, 66, 190, 236, 78,
            194, 13, 183, 106, 104, 145, 28, 11
        ]);
    }
}
