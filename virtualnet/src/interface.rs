//! This module contains structs & functions that are used by user's code in the course.
//! It's almost entirely copied from smoltcp with a small number of changes, and it's not
//! actually compiled in the target virtual network module - this part of code is here only
//! for testing purposes. In production, it's a part of the front-end code base.

#![allow(unused)]

use std::convert::TryInto;
use std::io::ErrorKind;
use std::net::Ipv4Addr;

type Result<T> = std::io::Result<T>;

pub type Ipv4Packet = Packet<[u8; 20]>;

pub mod checksum {
    use super::*;

    fn propagate_carries(word: u32) -> u16 {
        let sum = (word >> 16) + (word & 0xffff);
        ((sum >> 16) as u16) + (sum as u16)
    }

    /// Compute an RFC 1071 compliant checksum (without the final complement).
    pub fn data(mut data: &[u8]) -> u16 {
        let mut accum = 0;

        // For each 32-byte chunk...
        const CHUNK_SIZE: usize = 32;
        while data.len() >= CHUNK_SIZE {
            let mut d = &data[..CHUNK_SIZE];
            // ... take by 2 bytes and sum them.
            while d.len() >= 2 {
                accum += NetworkEndian::read_u16(d) as u32;
                d = &d[2..];
            }

            data = &data[CHUNK_SIZE..];
        }

        // Sum the rest that does not fit the last 32-byte chunk,
        // taking by 2 bytes.
        while data.len() >= 2 {
            accum += NetworkEndian::read_u16(data) as u32;
            data = &data[2..];
        }

        // Add the last remaining odd byte, if any.
        if let Some(&value) = data.first() {
            accum += (value as u32) << 8;
        }

        propagate_carries(accum)
    }

    /// Combine several RFC 1071 compliant checksums.
    pub fn combine(checksums: &[u16]) -> u16 {
        let mut accum: u32 = 0;
        for &word in checksums {
            accum += word as u32;
        }
        propagate_carries(accum)
    }

    /// Compute an IP pseudo header checksum.
    pub fn pseudo_header(
        src_addr: &Ipv4Addr,
        dst_addr: &Ipv4Addr,
        protocol: Protocol,
        length: u32,
    ) -> u16 {
        let mut proto_len = [0u8; 4];
        proto_len[1] = protocol.into();
        NetworkEndian::write_u16(&mut proto_len[2..4], length as u16);

        combine(&[
            data(&src_addr.octets()),
            data(&dst_addr.octets()),
            data(&proto_len[..]),
        ])
    }
}

pub enum Protocol {
    HopByHop,
    Icmp,
    Igmp,
    Tcp,
    Udp,
    Unknown(u8),
}

impl From<u8> for Protocol {
    fn from(value: u8) -> Self {
        match value {
            0x00 => Protocol::HopByHop,
            0x01 => Protocol::Icmp,
            0x02 => Protocol::Igmp,
            0x06 => Protocol::Tcp,
            0x11 => Protocol::Udp,
            other => Protocol::Unknown(other),
        }
    }
}

impl From<Protocol> for u8 {
    fn from(value: Protocol) -> Self {
        match value {
            Protocol::HopByHop => 0x00,
            Protocol::Icmp => 0x01,
            Protocol::Igmp => 0x02,
            Protocol::Tcp => 0x06,
            Protocol::Udp => 0x11,
            Protocol::Unknown(other) => other,
        }
    }
}

struct NetworkEndian {}

impl NetworkEndian {
    fn read_u16(input: &[u8]) -> u16 {
        let (int_bytes, rest) = input.split_at(std::mem::size_of::<u16>());
        u16::from_be_bytes(int_bytes.try_into().unwrap())
    }

    fn read_u32(input: &[u8]) -> u32 {
        let (int_bytes, rest) = input.split_at(std::mem::size_of::<u32>());
        u32::from_be_bytes(int_bytes.try_into().unwrap())
    }

    fn write_u16(input: &mut [u8], value: u16) {
        let bytes = value.to_be_bytes();
        let (int_bytes, rest) = input.split_at_mut(std::mem::size_of::<u16>());
        int_bytes.copy_from_slice(&bytes);
    }

    fn write_u32(input: &mut [u8], value: u32) {
        let bytes = value.to_be_bytes();
        let (int_bytes, rest) = input.split_at_mut(std::mem::size_of::<u32>());
        int_bytes.copy_from_slice(&bytes);
    }
}

/// A read/write wrapper around an Internet Protocol version 4 packet buffer.
#[derive(Debug, PartialEq, Clone)]
pub struct Packet<T: AsRef<[u8]>> {
    buffer: T,
}

mod field {
    pub type Field = ::core::ops::Range<usize>;

    pub const VER_IHL: usize = 0;
    pub const DSCP_ECN: usize = 1;
    pub const LENGTH: Field = 2..4;
    pub const IDENT: Field = 4..6;
    pub const FLG_OFF: Field = 6..8;
    pub const TTL: usize = 8;
    pub const PROTOCOL: usize = 9;
    pub const CHECKSUM: Field = 10..12;
    pub const SRC_ADDR: Field = 12..16;
    pub const DST_ADDR: Field = 16..20;
}

impl<T: AsRef<[u8]>> Packet<T> {
    /// Imbue a raw octet buffer with IPv4 packet structure.
    pub fn new_unchecked(buffer: T) -> Packet<T> {
        Packet { buffer }
    }

    /// Shorthand for a combination of [new_unchecked] and [check_len].
    ///
    /// [new_unchecked]: #method.new_unchecked
    /// [check_len]: #method.check_len
    pub fn new_checked(buffer: T) -> Result<Packet<T>> {
        let packet = Self::new_unchecked(buffer);
        packet.check_len()?;
        Ok(packet)
    }

    /// Ensure that no accessor method will panic if called.
    pub fn check_len(&self) -> Result<()> {
        let len = self.buffer.as_ref().len();
        if len < field::DST_ADDR.end {
            Err(std::io::Error::new(ErrorKind::Other, "Truncated"))
        } else if len < self.header_len() as usize {
            Err(std::io::Error::new(ErrorKind::Other, "Truncated"))
        } else if self.header_len() as u16 > self.total_len() {
            Err(std::io::Error::new(ErrorKind::Other, "Malformed"))
        } else if len < self.total_len() as usize {
            Err(std::io::Error::new(ErrorKind::Other, "Truncated"))
        } else {
            Ok(())
        }
    }

    /// Consume the packet, returning the underlying buffer.
    pub fn into_inner(self) -> T {
        self.buffer
    }

    /// Return the version field.
    #[inline]
    pub fn version(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::VER_IHL] >> 4
    }

    /// Return the header length, in octets.
    #[inline]
    pub fn header_len(&self) -> u8 {
        let data = self.buffer.as_ref();
        (data[field::VER_IHL] & 0x0f) * 4
    }

    /// Return the Differential Services Code Point field.
    pub fn dscp(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSCP_ECN] >> 2
    }

    /// Return the Explicit Congestion Notification field.
    pub fn ecn(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::DSCP_ECN] & 0x03
    }

    /// Return the total length field.
    #[inline]
    pub fn total_len(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::LENGTH])
    }

    /// Return the fragment identification field.
    #[inline]
    pub fn ident(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::IDENT])
    }

    /// Return the "don't fragment" flag.
    #[inline]
    pub fn dont_frag(&self) -> bool {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) & 0x4000 != 0
    }

    /// Return the "more fragments" flag.
    #[inline]
    pub fn more_frags(&self) -> bool {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) & 0x2000 != 0
    }

    /// Return the fragment offset, in octets.
    #[inline]
    pub fn frag_offset(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::FLG_OFF]) << 3
    }

    /// Return the time to live field.
    #[inline]
    pub fn hop_limit(&self) -> u8 {
        let data = self.buffer.as_ref();
        data[field::TTL]
    }

    /// Return the protocol field.
    #[inline]
    pub fn protocol(&self) -> Protocol {
        let data = self.buffer.as_ref();
        Protocol::from(data[field::PROTOCOL])
    }

    /// Return the header checksum field.
    #[inline]
    pub fn checksum(&self) -> u16 {
        let data = self.buffer.as_ref();
        NetworkEndian::read_u16(&data[field::CHECKSUM])
    }

    /// Return the source address field.
    #[inline]
    pub fn src_addr(&self) -> Ipv4Addr {
        let data = self.buffer.as_ref();
        Ipv4Addr::from(NetworkEndian::read_u32(&data[field::SRC_ADDR]))
    }

    /// Return the destination address field.
    #[inline]
    pub fn dst_addr(&self) -> Ipv4Addr {
        let data = self.buffer.as_ref();
        Ipv4Addr::from(NetworkEndian::read_u32(&data[field::DST_ADDR]))
    }

    /// Validate the header checksum.
    ///
    /// # Fuzzing
    /// This function always returns `true` when fuzzing.
    pub fn verify_checksum(&self) -> bool {
        if cfg!(fuzzing) {
            return true;
        }

        let data = self.buffer.as_ref();
        checksum::data(&data[..self.header_len() as usize]) == !0
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
    /// Return a pointer to the payload.
    #[inline]
    pub fn payload(&self) -> &'a [u8] {
        let range = self.header_len() as usize..self.total_len() as usize;
        let data = self.buffer.as_ref();
        &data[range]
    }
}

impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
    /// Set the version field.
    #[inline]
    pub fn set_version(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER_IHL] = (data[field::VER_IHL] & !0xf0) | (value << 4);
    }

    /// Set the header length, in octets.
    #[inline]
    pub fn set_header_len(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::VER_IHL] = (data[field::VER_IHL] & !0x0f) | ((value / 4) & 0x0f);
    }

    /// Set the Differential Services Code Point field.
    pub fn set_dscp(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0xfc) | (value << 2)
    }

    /// Set the Explicit Congestion Notification field.
    pub fn set_ecn(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::DSCP_ECN] = (data[field::DSCP_ECN] & !0x03) | (value & 0x03)
    }

    /// Set the total length field.
    #[inline]
    pub fn set_total_len(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::LENGTH], value)
    }

    /// Set the fragment identification field.
    #[inline]
    pub fn set_ident(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::IDENT], value)
    }

    /// Clear the entire flags field.
    #[inline]
    pub fn clear_flags(&mut self) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = raw & !0xe000;
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the "don't fragment" flag.
    #[inline]
    pub fn set_dont_frag(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x4000 } else { raw & !0x4000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the "more fragments" flag.
    #[inline]
    pub fn set_more_frags(&mut self, value: bool) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = if value { raw | 0x2000 } else { raw & !0x2000 };
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the fragment offset, in octets.
    #[inline]
    pub fn set_frag_offset(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        let raw = NetworkEndian::read_u16(&data[field::FLG_OFF]);
        let raw = (raw & 0xe000) | (value >> 3);
        NetworkEndian::write_u16(&mut data[field::FLG_OFF], raw);
    }

    /// Set the time to live field.
    #[inline]
    pub fn set_hop_limit(&mut self, value: u8) {
        let data = self.buffer.as_mut();
        data[field::TTL] = value
    }

    /// Set the protocol field.
    #[inline]
    pub fn set_protocol(&mut self, value: Protocol) {
        let data = self.buffer.as_mut();
        data[field::PROTOCOL] = value.into()
    }

    /// Set the header checksum field.
    #[inline]
    pub fn set_checksum(&mut self, value: u16) {
        let data = self.buffer.as_mut();
        NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
    }

    /// Set the source address field.
    #[inline]
    pub fn set_src_addr(&mut self, value: Ipv4Addr) {
        let data = self.buffer.as_mut();
        data[field::SRC_ADDR].copy_from_slice(&value.octets())
    }

    /// Set the destination address field.
    #[inline]
    pub fn set_dst_addr(&mut self, value: Ipv4Addr) {
        let data = self.buffer.as_mut();
        data[field::DST_ADDR].copy_from_slice(&value.octets())
    }

    /// Compute and fill in the header checksum.
    pub fn fill_checksum(&mut self) {
        self.set_checksum(0);
        let checksum = {
            let data = self.buffer.as_ref();
            !checksum::data(&data[..self.header_len() as usize])
        };
        self.set_checksum(checksum)
    }

    /// Return a mutable pointer to the payload.
    #[inline]
    pub fn payload_mut(&mut self) -> &mut [u8] {
        let range = self.header_len() as usize..self.total_len() as usize;
        let data = self.buffer.as_mut();
        &mut data[range]
    }
}

impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
    fn as_ref(&self) -> &[u8] {
        self.buffer.as_ref()
    }
}

mod udp {
    use super::{NetworkEndian, Protocol as IpProtocol};
    use std::io::ErrorKind;
    use std::net::Ipv4Addr;

    type Result<T> = std::io::Result<T>;

    #[derive(Debug, PartialEq, Clone)]
    pub struct Packet<T: AsRef<[u8]>> {
        buffer: T,
    }

    mod field {
        #![allow(non_snake_case)]

        pub type Field = ::core::ops::Range<usize>;

        pub const SRC_PORT: Field = 0..2;
        pub const DST_PORT: Field = 2..4;
        pub const LENGTH: Field = 4..6;
        pub const CHECKSUM: Field = 6..8;

        pub fn PAYLOAD(length: u16) -> Field {
            CHECKSUM.end..(length as usize)
        }
    }

    impl<T: AsRef<[u8]>> Packet<T> {
        pub fn new_unchecked(buffer: T) -> Packet<T> {
            Packet { buffer }
        }

        pub fn new_checked(buffer: T) -> Result<Packet<T>> {
            let packet = Self::new_unchecked(buffer);
            packet.check_len()?;
            Ok(packet)
        }

        pub fn check_len(&self) -> Result<()> {
            let buffer_len = self.buffer.as_ref().len();
            if buffer_len < field::CHECKSUM.end {
                Err(std::io::Error::new(ErrorKind::Other, "Truncated"))
            } else {
                let field_len = self.len() as usize;
                if buffer_len < field_len {
                    Err(std::io::Error::new(ErrorKind::Other, "Truncated"))
                } else if field_len < field::CHECKSUM.end {
                    Err(std::io::Error::new(ErrorKind::Other, "Malformed"))
                } else {
                    Ok(())
                }
            }
        }

        pub fn into_inner(self) -> T {
            self.buffer
        }

        #[inline]
        pub fn src_port(&self) -> u16 {
            let data = self.buffer.as_ref();
            NetworkEndian::read_u16(&data[field::SRC_PORT])
        }

        #[inline]
        pub fn dst_port(&self) -> u16 {
            let data = self.buffer.as_ref();
            NetworkEndian::read_u16(&data[field::DST_PORT])
        }

        #[inline]
        pub fn len(&self) -> u16 {
            let data = self.buffer.as_ref();
            NetworkEndian::read_u16(&data[field::LENGTH])
        }

        #[inline]
        pub fn checksum(&self) -> u16 {
            let data = self.buffer.as_ref();
            NetworkEndian::read_u16(&data[field::CHECKSUM])
        }

        pub fn verify_checksum(&self, src_addr: &Ipv4Addr, dst_addr: &Ipv4Addr) -> bool {
            let data = self.buffer.as_ref();
            super::checksum::combine(&[
                super::checksum::pseudo_header(
                    src_addr,
                    dst_addr,
                    IpProtocol::Udp,
                    self.len() as u32,
                ),
                super::checksum::data(&data[..self.len() as usize]),
            ]) == !0
        }
    }

    impl<'a, T: AsRef<[u8]> + ?Sized> Packet<&'a T> {
        #[inline]
        pub fn payload(&self) -> &'a [u8] {
            let length = self.len();
            let data = self.buffer.as_ref();
            &data[field::PAYLOAD(length)]
        }
    }

    impl<T: AsRef<[u8]> + AsMut<[u8]>> Packet<T> {
        #[inline]
        pub fn set_src_port(&mut self, value: u16) {
            let data = self.buffer.as_mut();
            NetworkEndian::write_u16(&mut data[field::SRC_PORT], value)
        }

        #[inline]
        pub fn set_dst_port(&mut self, value: u16) {
            let data = self.buffer.as_mut();
            NetworkEndian::write_u16(&mut data[field::DST_PORT], value)
        }

        #[inline]
        pub fn set_len(&mut self, value: u16) {
            let data = self.buffer.as_mut();
            NetworkEndian::write_u16(&mut data[field::LENGTH], value)
        }

        #[inline]
        pub fn set_checksum(&mut self, value: u16) {
            let data = self.buffer.as_mut();
            NetworkEndian::write_u16(&mut data[field::CHECKSUM], value)
        }

        pub fn fill_checksum(&mut self, src_addr: &Ipv4Addr, dst_addr: &Ipv4Addr) {
            self.set_checksum(0);
            let checksum = {
                let data = self.buffer.as_ref();
                !super::checksum::combine(&[
                    super::checksum::pseudo_header(
                        src_addr,
                        dst_addr,
                        IpProtocol::Udp,
                        self.len() as u32,
                    ),
                    super::checksum::data(&data[..self.len() as usize]),
                ])
            };
            self.set_checksum(if checksum == 0 { 0xffff } else { checksum })
        }

        #[inline]
        pub fn payload_mut(&mut self) -> &mut [u8] {
            let length = self.len();
            let data = self.buffer.as_mut();
            &mut data[field::PAYLOAD(length)]
        }
    }

    impl<T: AsRef<[u8]>> AsRef<[u8]> for Packet<T> {
        fn as_ref(&self) -> &[u8] {
            self.buffer.as_ref()
        }
    }
}

mod test {
    use super::*;

    #[test]
    fn create_udp_header() {
        type UdpDatagram = super::udp::Packet<[u8; 8]>;
        type Ipv4Packet = super::Packet<[u8; 28]>;

        let our_own_address = Ipv4Addr::new(10, 0, 0, 1);
        let dns_server_address = Ipv4Addr::new(1, 2, 3, 4);

        let udp_header_data = [0u8; 8];
        let mut udp_packet = UdpDatagram::new_unchecked(udp_header_data);

        udp_packet.set_src_port(1000);
        udp_packet.set_dst_port(53);
        udp_packet.set_len(0);

        let mut ip_data = [0u8; 20 + 8];
        let mut ip_packet = Ipv4Packet::new_unchecked(ip_data);

        ip_packet.set_src_addr(our_own_address);
        ip_packet.set_dst_addr(dns_server_address);

        udp_packet.fill_checksum(&our_own_address, &dns_server_address);

        ip_packet.set_header_len(20);
        ip_packet.set_total_len(28);

        ip_packet
            .payload_mut()
            .copy_from_slice(&udp_packet.into_inner());

        ip_packet.fill_checksum();

        assert_ne!(ip_packet.into_inner(), [0u8; 28]);
    }

    #[test]
    fn create_header() {
        let mut header_data = [0u8; 20];
        let mut ip_packet = Ipv4Packet::new_unchecked(header_data);

        let our_own_address = Ipv4Addr::new(10, 0, 0, 1);

        ip_packet.set_src_addr(our_own_address);

        let dns_server_address = Ipv4Addr::new(1, 2, 3, 4);
        ip_packet.set_dst_addr(dns_server_address);

        ip_packet.set_protocol(Protocol::Udp);

        ip_packet.set_version(4);
        ip_packet.set_header_len(20);
        ip_packet.set_total_len(20);

        ip_packet.fill_checksum();

        assert_ne!(ip_packet.into_inner(), [0; 20]);
    }
}
