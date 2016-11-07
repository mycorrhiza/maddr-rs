use std::io;
use std::net::{ Ipv4Addr, Ipv6Addr };

use varmint::WriteVarInt;
use mhash::WriteMultiHash;

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
        try!(self.write_all(&addr.octets()));
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
                try!(self.write_usize_varint(multihash.output_len()));
                try!(self.write_multihash(multihash));
            }
            Udt | Utp | Http | Https => {
            }
        }
        Ok(())
    }
}

/// A trait to allow writing a `MultiAddr` to an object.
///
/// This is primarily intended to provide support for the `io::Write` trait,
/// allowing writing a `MultiAddr` to a stream.
pub trait WriteMultiAddr {
    /// Write a `MultiAddr` to this object.
    ///
    /// # Errors
    ///
    /// Any errors encountered when writing to the underlying `io::Write`
    /// stream will be propagated out, if that happens an undefined number of
    /// bytes will already have been written to the stream.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use std::net::Ipv4Addr;
    /// use maddr::{ MultiAddr, Segment, WriteMultiAddr };
    ///
    /// let mut buffer = vec![];
    /// buffer.write_multiaddr(&MultiAddr::new(vec![
    ///         Segment::IP4(Ipv4Addr::new(1, 2, 3, 4))
    ///     ]))
    ///     .unwrap();
    /// assert_eq!(vec![4, 1, 2, 3, 4], buffer);
    /// ```
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

    use mhash::{ MultiHash, MultiHashVariant };

    use { Segment, MultiAddr, WriteMultiAddr };

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
        let multihash = MultiHash::new(MultiHashVariant::Sha2_256, &[
            213, 46, 187, 137, 216, 91, 2, 162,
            132, 148, 130, 3, 166, 47, 242, 131,
            137, 197, 124, 159, 66, 190, 236, 78,
            194, 13, 183, 106, 104, 145, 28, 11,
        ]).unwrap();
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
