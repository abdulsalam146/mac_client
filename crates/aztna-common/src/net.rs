//! Socket helpers shared by data-plane components.

/// Connected-UDP trap: ICMP port-unreachable from a vanished peer makes
/// every following recv/recv_from fail with WSAECONNRESET (10054),
/// leaving the socket deaf [W4.7 lesson]. No-op off Windows.
/// W8.1: moved here from client dns.rs so the gateway UDP relay gets
/// the same protection (client now delegates to this copy).
#[cfg(windows)]
pub fn udp_no_connreset(sock: &std::net::UdpSocket) {
    use std::os::windows::io::AsRawSocket;
    use windows::Win32::Networking::WinSock::{WSAIoctl, SIO_UDP_CONNRESET, SOCKET};
    let enable: u32 = 0; // FALSE: do not report resets
    let mut returned: u32 = 0;
    let r = unsafe {
        WSAIoctl(
            SOCKET(sock.as_raw_socket() as usize),
            SIO_UDP_CONNRESET,
            Some(&enable as *const u32 as *const core::ffi::c_void),
            std::mem::size_of::<u32>() as u32,
            None,
            0,
            &mut returned,
            None,
            None,
        )
    };
    if r != 0 {
        eprintln!("[net] SIO_UDP_CONNRESET ioctl failed (resets may stall reads)");
    }
}

#[cfg(not(windows))]
pub fn udp_no_connreset(_sock: &std::net::UdpSocket) {}
