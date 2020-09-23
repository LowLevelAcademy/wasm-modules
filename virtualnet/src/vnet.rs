//! This module implements the virtual network functions used from JavaScript API.

use smoltcp::iface::{EthernetInterface, EthernetInterfaceBuilder, NeighborCache};
use smoltcp::phy::Loopback;
use smoltcp::socket::{SocketHandle, SocketSet, UdpPacketMetadata, UdpSocket, UdpSocketBuffer};
use smoltcp::time::Duration;
use smoltcp::wire::*;

use std::collections::hash_map::DefaultHasher;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::{cell::RefCell, slice};

use crate::middleware::WasmMiddleware;

/// Test: has the reader sent a DNS request for Alice's IP address?
const TEST_ASKED_ALICE_IP: u8 = 1;
/// Test: has the reader contacted 'Alice'?
const TEST_CONTACTED_ALICE: u8 = 2;

extern "C" {
    /// Prints out a message to JS console.
    fn print_log(s: *const u8, s_len: usize);

    /// Function that is triggered each time a test condition is met.
    fn test_completed(num: u8);
}

fn log(s: &str) {
    use std::ffi::CString;

    let len = s.len();
    let c_str = CString::new(s).unwrap();
    unsafe {
        print_log(c_str.as_ptr() as *const _, len);
    }
}

/// This struct holds the entire state of the virtual network, including sockets, interfaces, etc.
pub struct NetworkState<'a> {
    /// Ethernet interface for the virtual network with the WebAssembly middleware.
    iface: EthernetInterface<'static, 'a, 'a, WasmMiddleware<Loopback>>,
    clock: mock::Clock,
    /// Socket set that holds all sockets used in the virtual network.
    socket_set: SocketSet<'a, 'a, 'a>,
    /// Socket for the name server.
    dns_socket: SocketHandle,
    /// If this server runs in a 'mock' DNS mode, it will not return 'real' IP addresses
    /// used in the virtual network, but rather a hash converted into a mock IP address.
    is_mock_dns: bool,
    /// Socket for the 'Alice' server.
    alice_socket: Option<SocketHandle>,
    /// Socket for the easter egg server. ;)
    easter_socket: Option<SocketHandle>,
}

// There's only one thread in the wasm runtime, so we use thread_locals for global state storage.
thread_local! {
    pub static NETWORK: RefCell<Option<NetworkState<'static>>> = RefCell::new(None);
}

mod mock {
    use core::cell::Cell;
    use smoltcp::time::{Duration, Instant};

    pub struct Clock(Cell<Instant>);

    impl Clock {
        pub fn new() -> Clock {
            Clock(Cell::new(Instant::from_millis(0)))
        }

        pub fn advance(&self, duration: Duration) {
            self.0.set(self.0.get() + duration)
        }

        pub fn elapsed(&self) -> Instant {
            self.0.get()
        }
    }
}

/// Setup a UDP socket for the domain name service.
fn setup_dns_socket(socket_set: &mut SocketSet) -> SocketHandle {
    let mut socket = {
        let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 4], vec![0; 1024]);
        let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 4], vec![0; 1024]);
        UdpSocket::new(udp_rx_buffer, udp_tx_buffer)
    };

    socket
        .bind(IpEndpoint::new(IpAddress::v4(1, 2, 3, 4), 53))
        .unwrap();

    socket_set.add(socket)
}

/// Setup UDP sockets for Alice & the easter egg server.
fn setup_alice_socket(socket_set: &mut SocketSet) -> (Option<SocketHandle>, Option<SocketHandle>) {
    // Alice
    let mut socket = {
        let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 4], vec![0; 1024]);
        let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 4], vec![0; 1024]);
        UdpSocket::new(udp_rx_buffer, udp_tx_buffer)
    };
    socket
        .bind(IpEndpoint::new(IpAddress::v4(10, 0, 0, 42), 1000))
        .unwrap();

    let alice_socket = socket_set.add(socket);

    // Easter egg
    let mut socket = {
        let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 4], vec![0; 1024]);
        let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 4], vec![0; 1024]);
        UdpSocket::new(udp_rx_buffer, udp_tx_buffer)
    };
    socket
        .bind(IpEndpoint::new(IpAddress::v4(10, 0, 0, 99), 1000))
        .unwrap();

    let easter_egg_socket = socket_set.add(socket);

    return (Some(alice_socket), Some(easter_egg_socket));
}

/// Handle DNS requests.
fn poll_dns(network: &mut NetworkState) {
    let mut dns_sock = network.socket_set.get::<UdpSocket>(network.dns_socket);

    match dns_sock.recv() {
        Ok((data, sender_endpoint)) => {
            // Decode a DNS request.
            log(&format!("{:?}, {:?}", data, sender_endpoint));

            if network.is_mock_dns {
                // Hash the request and return it as a faux IP address.
                let mut hasher = DefaultHasher::new();
                data.hash(&mut hasher);

                let res = hasher.finish().to_be_bytes();
                log(&format!("DNS response: {:?}", &res[0..4]));

                dns_sock.send_slice(&res[0..4], sender_endpoint).unwrap(); // fixme: properly report errors
            } else {
                let response = match &data.to_ascii_lowercase()[..] {
                    b"alice" => {
                        unsafe { test_completed(TEST_ASKED_ALICE_IP) };
                        [10, 0, 0, 42]
                    }
                    b"lobste.rs"
                    | b"google.com"
                    | b"duckduckgo.com"
                    | b"rust-lang.org"
                    | b"users.rust-lang.org"
                    | b"news.ycombinator.com"
                    | b"youtube.com"
                    | b"youtu.be"
                    | b"reddit.com" => [10, 0, 0, 99],
                    _ => [0, 0, 0, 0],
                };
                log(&format!("DNS response: {:?}", &response[0..4]));

                dns_sock.send_slice(&response, sender_endpoint).unwrap(); // fixme: properly report errors
            }
        }
        Err(smoltcp::Error::Exhausted) => {
            // Buffer is empty, ignore
            return;
        }
        Err(e) => {
            // TODO: properly report this error
            log(&format!("{:?}", e));
            return;
        }
    }
}

/// Handle requests to Alice's server.
fn poll_alice(network: &mut NetworkState) {
    let mut sock = network
        .socket_set
        .get::<UdpSocket>(network.alice_socket.as_ref().cloned().unwrap());

    match sock.recv() {
        Ok((_, sender_endpoint)) => {
            unsafe { test_completed(TEST_CONTACTED_ALICE) };

            sock.send_slice(b"Hello from Alice!", sender_endpoint)
                .unwrap(); // fixme: properly report errors
        }
        Err(smoltcp::Error::Exhausted) => {
            // buffer is empty, ignore
            return;
        }
        Err(e) => {
            // todo: properly report this error
            log(&format!("{:?}", e));
            return;
        }
    }
}

fn poll_easter(network: &mut NetworkState) {
    let mut sock = network
        .socket_set
        .get::<UdpSocket>(network.easter_socket.as_ref().cloned().unwrap());

    match sock.recv() {
        Ok((_, sender_endpoint)) => {
            sock.send_slice(
                b"301 Moved Permanently\nLocation: https://youtu.be/dQw4w9WgXcQ\n",
                sender_endpoint,
            )
            .unwrap(); // FIXME: properly report errors
        }
        Err(smoltcp::Error::Exhausted) => {
            // Buffer is empty, ignore
            return;
        }
        Err(e) => {
            // TODO: properly report this error
            log(&format!("{:?}", e));
            return;
        }
    }
}

fn poll_services(network: &mut NetworkState) {
    poll_dns(network);

    if !network.is_mock_dns {
        poll_alice(network);
        poll_easter(network);
    }
}

/// Initialise the virtual network, setup sockets, etc.
/// If `mock_dns` is true, only a 'fake' name server will be initialised.
/// The fake name server will return IP addresses that don't exist in the virtual network.
#[no_mangle]
pub fn setup_network(mock_dns: bool) {
    let clock = mock::Clock::new();

    let loopback = Loopback::new();
    let device = WasmMiddleware::new(loopback);

    // let neighbor_cache = unsafe { NeighborCache::new(&mut NEIGHBOR_CACHE[..]) };
    let neighbor_cache = NeighborCache::new(BTreeMap::new());

    let iface = EthernetInterfaceBuilder::new(device)
        .ethernet_addr(EthernetAddress::default())
        .neighbor_cache(neighbor_cache)
        .ip_addrs([
            IpCidr::new(IpAddress::v4(1, 2, 3, 4), 8),   // DNS
            IpCidr::new(IpAddress::v4(10, 0, 0, 1), 8),  // User's IP
            IpCidr::new(IpAddress::v4(10, 0, 0, 42), 8), // Alice
            IpCidr::new(IpAddress::v4(10, 0, 0, 99), 8), // Hidden service
        ])
        .finalize();

    let mut socket_set = SocketSet::new(vec![]);

    let dns_socket = setup_dns_socket(&mut socket_set);

    let (alice_socket, easter_socket) = if mock_dns {
        (None, None)
    } else {
        setup_alice_socket(&mut socket_set)
    };

    let network = NetworkState {
        iface,
        clock,
        socket_set,
        dns_socket,
        alice_socket,
        easter_socket,
        is_mock_dns: mock_dns,
    };

    NETWORK.with(|net| {
        *net.borrow_mut() = Some(network);
    });
}

/// Polls all sockets in the virtual network and handles events.
#[no_mangle]
pub unsafe fn poll_network() {
    NETWORK.with(|net| {
        let net2 = &mut *net.borrow_mut(); // TODO: gracefully report error if None
        let mut network = net2.as_mut().unwrap();

        let mut processed = true;

        while processed {
            processed = match network
                .iface
                .poll(&mut network.socket_set, network.clock.elapsed())
            {
                Ok(processed) => processed,
                Err(_e) => {
                    log(&format!("err: {:?}", _e));
                    true
                }
            };

            match network
                .iface
                .poll_delay(&network.socket_set, network.clock.elapsed())
            {
                Some(Duration { millis: 0 }) => {}
                Some(delay) => network.clock.advance(delay),
                None => network.clock.advance(Duration::from_millis(1)),
            }

            if processed {
                poll_services(&mut network);
            }
        }
    });
}

/// Creates a new UDP socket on the virtual network and returns a handle.
#[no_mangle]
pub unsafe fn udp_bind(ip: u32, port: u16) -> usize {
    let mut socket = {
        let udp_rx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 4], vec![0; 1024]);
        let udp_tx_buffer = UdpSocketBuffer::new(vec![UdpPacketMetadata::EMPTY; 4], vec![0; 1024]);

        UdpSocket::new(udp_rx_buffer, udp_tx_buffer)
    };

    socket
        .bind(IpEndpoint::new(
            IpAddress::Ipv4(Ipv4Address(ip.to_be_bytes())),
            port,
        ))
        .unwrap();

    NETWORK.with(|net| {
        let net2 = &mut *net.borrow_mut();
        let network = net2.as_mut().unwrap(); // TODO: gracefully report error if None

        network.socket_set.add(socket).inner()
    })
}

/// Sends data to a provided destination address.
///
/// ## Arguments
/// - `sock`: the source socket.
/// - `buf`: pointer to the source data buffer.
/// - `buf_len`: size of the source data buffer.
/// - `dst_ip`: destination IP address.
/// - `dst_port`: destination port number.
#[no_mangle]
pub unsafe fn udp_send_to(sock: usize, buf: *const u8, buf_len: u16, dst_ip: u32, dst_port: u16) {
    NETWORK.with(|net| {
        let net2 = &mut *net.borrow_mut();
        let network = net2.as_mut().unwrap(); // TODO: gracefully report error if None

        let mut socket = network
            .socket_set
            .get::<UdpSocket>(SocketHandle::from(sock));

        let endpoint =
            IpEndpoint::new(IpAddress::Ipv4(Ipv4Address(dst_ip.to_be_bytes())), dst_port);
        let buf_slice = slice::from_raw_parts(buf, buf_len as usize);
        log(&format!("({:?}) {:?} -> {:?}", sock, buf_slice, endpoint));

        let res = socket.send_slice(buf_slice, endpoint);

        log(&format!("{:?}", res));
    })
}

/// Polls a given socket for new packets.
/// Returns a number of bytes received.
///
/// ## Arguments
/// - `sock`: the source socket.
/// - `buf`: pointer to the destination data buffer that needs to be pre-allocated.
/// - `buf_len`: size of the destination data buffer.
/// - `src_ip`: pointer to a memory region that will hold the sender's IP.
/// - `src_port`: pointer to a memory region that will hold the sender's port number.
#[no_mangle]
pub unsafe fn udp_recv_from(
    sock: usize,
    buf: *mut u8,
    buf_len: u16,
    src_ip: *mut u32,
    src_port: *mut u16,
) -> u16 {
    NETWORK.with(|net| {
        let net2 = &mut *net.borrow_mut();
        let network = net2.as_mut().unwrap(); // TODO: gracefully report error if None

        log(&format!("sock num: {:?}", sock));

        let mut socket = network
            .socket_set
            .get::<UdpSocket>(SocketHandle::from(sock));

        let mut dst_buf = slice::from_raw_parts_mut(buf, buf_len as usize);

        let (size, sender) = match socket.recv_slice(&mut dst_buf) {
            Ok(res) => res,
            Err(smoltcp::Error::Exhausted) => {
                // the buffer is empty
                return 0;
            }
            Err(e) => {
                // TODO: proper error reporting
                log(&format!("recv error: {:?}", e));
                return 0;
            }
        };

        log(&format!("udp_recv_from: {:?}, {:?}", size, sender));

        if let IpAddress::Ipv4(ipv4) = sender.addr {
            *src_ip = u32::from_be_bytes(ipv4.0);
        }
        *src_port = sender.port;

        size as u16
    })
}

/// Removes the given socket from the virtual network.
#[no_mangle]
pub fn udp_unbind(sock: usize) {
    NETWORK.with(|net| {
        let net2 = &mut *net.borrow_mut();
        let network = net2.as_mut().unwrap(); // TODO: gracefully report error if None

        let _ = network.socket_set.remove(SocketHandle::from(sock));
    });
}
