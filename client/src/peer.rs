//! W13 step 3 [per-user tunnel isolation]: TCP/UDP peer attribution via
//! the kernel owner tables — the mechanism that lets a forwarder refuse
//! connections from any local principal other than the tunnel-owning
//! user. The kernel tables name the TRUE owning process (a standard
//! user cannot forge them); attribution is VALIDATION-FIRST: the
//! `glmdev peer-probe` harness measured match rate / latency / races on
//! this exact code BEFORE the forwarder depends on it (plan v0.5 review
//! round 2 — proven, not assumed).
//!
//! Fail-closed rule: an unresolvable peer (row gone — e.g. fast-close
//! before lookup) resolves to Err, and the forwarder refuses.
//!
//! W29: two platform implementations of the same contract —
//!   windows: GetExtendedTcpTable/UdpTable + process token (SID string)
//!   linux:   /proc/net/{tcp,tcp6,udp,udp6} + /proc/<pid>/fd inode scan,
//!            `sid` carries the decimal uid (peer_allowed compares uid
//!            strings with the same exact-equality semantics as SIDs).
//! Unix note: cross-user attribution needs permission to read the other
//! user's /proc/<pid>/fd (root or same-uid); anything unreadable is Err —
//! fail closed, same contract as the Windows table lookup.
//! W30: macOS (darwin_imp) joins the contract via libproc (step 2);
//! until then it fails closed — Err refuses the peer, never a bypass.

use std::net::SocketAddr;

/// The attributed peer: owning PID, its user SID (string form; decimal
/// uid on unix), and its terminal-services session id (0 on unix — no
/// TS session concept).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerOwner {
    pub pid: u32,
    pub sid: String,
    pub session: u32,
}

#[cfg(target_os = "macos")]
use darwin_imp as imp;
#[cfg(target_os = "linux")]
use linux_imp as imp;
#[cfg(windows)]
use windows_imp as imp;

/// This process's own identity — the comparison baseline.
pub fn self_owner() -> Result<PeerOwner, anyhow::Error> {
    imp::self_owner()
}

/// Attribute the process at the other end of an ACCEPTED connection:
/// `peer` is the remote address as seen on our accepted socket, which is
/// the peer's LOCAL tuple in the kernel table. Rows are a point-in-time
/// snapshot — a peer that closed between accept and lookup yields
/// Err (fail closed upstream).
pub fn tcp_owner(peer: SocketAddr) -> Result<PeerOwner, anyhow::Error> {
    imp::tcp_owner(peer)
}

/// Attribute the sender of a datagram just received by `local`: the
/// sender's local tuple is (their addr, their source port) — the caller
/// supplies the sender address as observed on recv_from.
pub fn udp_owner(sender: SocketAddr) -> Result<PeerOwner, anyhow::Error> {
    imp::udp_owner(sender)
}

/// Pure decision (unit-pinned): may a peer with this SID use the
/// tunnel context owned by `owning_sid`? Exact string equality — same
/// user, any elevation (elevated tokens keep the SID; on unix the uid
/// string is elevation-invariant the same way).
pub fn peer_allowed(owning_sid: &str, peer_sid: &str) -> bool {
    !peer_sid.is_empty() && peer_sid == owning_sid
}

// ---------------------------------------------------------------------
// Windows: Win32 owner tables (unchanged W13 code, moved under cfg)
// ---------------------------------------------------------------------

#[cfg(windows)]
mod windows_imp {
    use super::{PeerOwner, SocketAddr};
    use anyhow::{anyhow, Result};

    pub fn self_owner() -> Result<PeerOwner> {
        unsafe {
            let h = windows::Win32::System::Threading::GetCurrentProcess();
            token_owner(h)
        }
    }

    pub fn tcp_owner(peer: SocketAddr) -> Result<PeerOwner> {
        unsafe {
            let (af, want) = match peer {
                SocketAddr::V4(a) => (
                    windows::Win32::Networking::WinSock::AF_INET.0 as u32,
                    RowAddr::V4(u32::from(*a.ip()).to_be()),
                ),
                SocketAddr::V6(a) => (
                    windows::Win32::Networking::WinSock::AF_INET6.0 as u32,
                    RowAddr::V6(a.ip().octets()),
                ),
            };
            let want_port = peer.port();
            let mut size = 0u32;
            let rc = windows::Win32::NetworkManagement::IpHelper::GetExtendedTcpTable(
                None,
                &mut size,
                false,
                af,
                windows::Win32::NetworkManagement::IpHelper::TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if rc != 122 && rc != 0 {
                return Err(anyhow!("GetExtendedTcpTable size query failed: {rc}"));
            }
            let mut buf = vec![0u8; size as usize];
            let rc = windows::Win32::NetworkManagement::IpHelper::GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                af,
                windows::Win32::NetworkManagement::IpHelper::TCP_TABLE_OWNER_PID_ALL,
                0,
            );
            if rc != 0 {
                return Err(anyhow!("GetExtendedTcpTable failed: {rc}"));
            }
            // walk rows: [u32 numEntries][row...] — match on the peer's LOCAL
            // tuple (their local addr+port IS our remote view of them)
            let n = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
            let mut off = 4usize;
            for _ in 0..n {
                let pid = match &want {
                    RowAddr::V4(w4) => {
                        // MIB_TCPROW_OWNER_PID: state u32, localAddr u32,
                        // localPort u32, remoteAddr u32, remotePort u32, pid u32
                        if off + 24 > buf.len() {
                            break;
                        }
                        let la = u32::from_ne_bytes(buf[off + 4..off + 8].try_into().unwrap());
                        let lp = net_port(&buf[off + 8..off + 12]);
                        let hit = la == *w4 && lp == want_port;
                        let pid = u32::from_ne_bytes(buf[off + 20..off + 24].try_into().unwrap());
                        off += 24;
                        if hit {
                            pid
                        } else {
                            continue;
                        }
                    }
                    RowAddr::V6(w6) => {
                        // MIB_TCP6ROW_OWNER_PID: local[16], scope u32, localPort
                        // u32, remote[16], scope u32, remotePort u32, state u32,
                        // pid u32
                        if off + 56 > buf.len() {
                            break;
                        }
                        let la = &buf[off..off + 16];
                        let lp = net_port(&buf[off + 20..off + 24]);
                        let hit = la == w6.as_slice() && lp == want_port;
                        let pid = u32::from_ne_bytes(buf[off + 52..off + 56].try_into().unwrap());
                        off += 56;
                        if hit {
                            pid
                        } else {
                            continue;
                        }
                    }
                };
                return process_owner(pid);
            }
            Err(anyhow!("no owner row for {peer} (closed before lookup?)"))
        }
    }

    pub fn udp_owner(sender: SocketAddr) -> Result<PeerOwner> {
        unsafe {
            let (af, want) = match sender {
                SocketAddr::V4(a) => (
                    windows::Win32::Networking::WinSock::AF_INET.0 as u32,
                    RowAddr::V4(u32::from(*a.ip()).to_be()),
                ),
                SocketAddr::V6(a) => (
                    windows::Win32::Networking::WinSock::AF_INET6.0 as u32,
                    RowAddr::V6(a.ip().octets()),
                ),
            };
            let want_port = sender.port();
            let mut size = 0u32;
            let rc = windows::Win32::NetworkManagement::IpHelper::GetExtendedUdpTable(
                None,
                &mut size,
                false,
                af,
                windows::Win32::NetworkManagement::IpHelper::UDP_TABLE_OWNER_PID,
                0,
            );
            if rc != 122 && rc != 0 {
                return Err(anyhow!("GetExtendedUdpTable size query failed: {rc}"));
            }
            let mut buf = vec![0u8; size as usize];
            let rc = windows::Win32::NetworkManagement::IpHelper::GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                af,
                windows::Win32::NetworkManagement::IpHelper::UDP_TABLE_OWNER_PID,
                0,
            );
            if rc != 0 {
                return Err(anyhow!("GetExtendedUdpTable failed: {rc}"));
            }
            let n = u32::from_ne_bytes(buf[0..4].try_into().unwrap()) as usize;
            let mut off = 4usize;
            for _ in 0..n {
                let pid = match &want {
                    RowAddr::V4(w4) => {
                        // MIB_UDPROW_OWNER_PID: localAddr u32, localPort u32, pid
                        if off + 12 > buf.len() {
                            break;
                        }
                        let la = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap());
                        let lp = net_port(&buf[off + 4..off + 8]);
                        let hit = la == *w4 && lp == want_port;
                        let pid = u32::from_ne_bytes(buf[off + 8..off + 12].try_into().unwrap());
                        off += 12;
                        if hit {
                            pid
                        } else {
                            continue;
                        }
                    }
                    RowAddr::V6(w6) => {
                        // MIB_UDP6ROW_OWNER_PID: local[16], scope u32, localPort
                        // u32, pid u32
                        if off + 28 > buf.len() {
                            break;
                        }
                        let la = &buf[off..off + 16];
                        let lp = net_port(&buf[off + 20..off + 24]);
                        let hit = la == w6.as_slice() && lp == want_port;
                        let pid = u32::from_ne_bytes(buf[off + 24..off + 28].try_into().unwrap());
                        off += 28;
                        if hit {
                            pid
                        } else {
                            continue;
                        }
                    }
                };
                return process_owner(pid);
            }
            Err(anyhow!("no udp owner row for {sender}"))
        }
    }

    enum RowAddr {
        V4(u32),
        V6([u8; 16]),
    }

    /// Row ports are in NETWORK byte order inside a u32 slot.
    fn net_port(b: &[u8]) -> u16 {
        u16::from_be(u16::from_ne_bytes([b[0], b[1]]))
    }

    fn process_owner(pid: u32) -> Result<PeerOwner> {
        use windows::Win32::Foundation::CloseHandle;
        use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
        unsafe {
            let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
                .map_err(|e| anyhow!("OpenProcess({pid}): {e}"))?;
            let owner = token_owner(h);
            let _ = CloseHandle(h);
            owner
        }
    }

    unsafe fn token_owner(h: windows::Win32::Foundation::HANDLE) -> Result<PeerOwner> {
        use windows::core::PWSTR;
        use windows::Win32::Foundation::{CloseHandle, HANDLE};
        use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
        use windows::Win32::Security::{
            GetTokenInformation, TokenSessionId, TokenUser, TOKEN_QUERY,
        };
        use windows::Win32::System::Threading::OpenProcessToken;
        let mut tok = HANDLE::default();
        OpenProcessToken(h, TOKEN_QUERY, &mut tok).map_err(|e| anyhow!("OpenProcessToken: {e}"))?;
        // TokenUser → SID string
        let mut need = 0u32;
        let _ = GetTokenInformation(tok, TokenUser, None, 0, &mut need);
        let mut buf = vec![0u8; need as usize];
        GetTokenInformation(
            tok,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut _),
            need,
            &mut need,
        )
        .map_err(|e| anyhow!("GetTokenInformation(TokenUser): {e}"))?;
        // TOKEN_USER { User: SID_AND_ATTRIBUTES { Sid: PSID, Attributes } }
        let sid_ptr = *buf.as_ptr().cast::<*const std::ffi::c_void>();
        if sid_ptr.is_null() {
            let _ = CloseHandle(tok);
            return Err(anyhow!("token has no user SID"));
        }
        let psid = windows::Win32::Security::PSID(sid_ptr as *mut _);
        let mut sid_str = PWSTR::null();
        ConvertSidToStringSidW(psid, &mut sid_str)
            .map_err(|e| anyhow!("ConvertSidToStringSidW: {e}"))?;
        let sid = sid_str.to_string().unwrap_or_default();
        windows::Win32::Foundation::LocalFree(windows::Win32::Foundation::HLOCAL(
            sid_str.as_ptr().cast(),
        ));
        // TokenSessionId → u32
        let mut session = 0u32;
        let mut need2 = 0u32;
        let _ = GetTokenInformation(tok, TokenSessionId, None, 0, &mut need2);
        let mut sbuf = vec![0u8; need2 as usize];
        if GetTokenInformation(
            tok,
            TokenSessionId,
            Some(sbuf.as_mut_ptr() as *mut _),
            need2,
            &mut need2,
        )
        .is_ok()
        {
            session = u32::from_ne_bytes(sbuf[0..4].try_into().unwrap_or_default());
        }
        let _ = CloseHandle(tok);
        Ok(PeerOwner {
            pid: windows::Win32::System::Threading::GetProcessId(h),
            sid,
            session,
        })
    }
}

// ---------------------------------------------------------------------
// Linux: /proc owner tables (W29 step 1; W30 step 1 re-gated from
// cfg(unix) to Linux-only — the tables are procfs)
// ---------------------------------------------------------------------

#[cfg(target_os = "linux")]
mod linux_imp {
    use super::{PeerOwner, SocketAddr};
    use anyhow::{anyhow, Result};
    use std::path::Path;

    pub fn self_owner() -> Result<PeerOwner> {
        owner_of_pid(Path::new("/proc"), std::process::id())
    }

    pub fn tcp_owner(peer: SocketAddr) -> Result<PeerOwner> {
        let table = match peer {
            SocketAddr::V4(_) => "/proc/net/tcp",
            SocketAddr::V6(_) => "/proc/net/tcp6",
        };
        bounded_scan(std::time::Duration::from_secs(2), move || {
            let content =
                std::fs::read_to_string(table).map_err(|e| anyhow!("read {table}: {e}"))?;
            tcp_owner_in(Path::new("/proc"), &content, peer)
        })
    }

    pub fn udp_owner(sender: SocketAddr) -> Result<PeerOwner> {
        let table = match sender {
            SocketAddr::V4(_) => "/proc/net/udp",
            SocketAddr::V6(_) => "/proc/net/udp6",
        };
        bounded_scan(std::time::Duration::from_secs(2), move || {
            let content =
                std::fs::read_to_string(table).map_err(|e| anyhow!("read {table}: {e}"))?;
            udp_owner_in(Path::new("/proc"), &content, sender)
        })
    }

    /// Run the scan on a short-lived worker with a hard join deadline. A
    /// /proc entry that blocks indefinitely (observed on WSL: relay/9P
    /// artifacts under mirrored networking) would otherwise wedge the
    /// CALLER — the isolation gate runs on forwarder accept paths. Convert
    /// a stuck scan into Err (fail closed, caller refuses the peer). The
    /// orphaned worker, if any, is one thread per call and dies with its
    /// syscall; it cannot accumulate unboundedly because every caller
    /// proceeds at the deadline.
    fn bounded_scan(
        budget: std::time::Duration,
        f: impl FnOnce() -> Result<PeerOwner> + Send + 'static,
    ) -> Result<PeerOwner> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        match rx.recv_timeout(budget) {
            Ok(r) => r,
            Err(_) => Err(anyhow!(
                "peer attribution scan exceeded {budget:?} - fail closed"
            )),
        }
    }

    /// Pure lookup over parsed table content + a /proc-shaped root — the
    /// test seam (fixtures build a fake tree). Match on the peer's LOCAL
    /// tuple (their local addr+port IS our remote view of them); prefer
    /// ESTABLISHED rows, skip inode-0 rows (TIME_WAIT etc. have no owner).
    pub(super) fn tcp_owner_in(root: &Path, content: &str, peer: SocketAddr) -> Result<PeerOwner> {
        let rows = parse_table(content);
        // pass 1: ESTABLISHED (st == "01"); pass 2: any row with an inode
        for want_est in [true, false] {
            for row in rows.iter() {
                if row.local == peer && row.inode != 0 && (row.state == "01") == want_est {
                    let pid = find_pid_by_inode(root, row.inode).ok_or_else(|| {
                        anyhow!(
                            "inode {} unattributable for {peer} (fd unreadable?)",
                            row.inode
                        )
                    })?;
                    return owner_of_pid(root, pid);
                }
            }
        }
        Err(anyhow!("no owner row for {peer} (closed before lookup?)"))
    }

    pub(super) fn udp_owner_in(
        root: &Path,
        content: &str,
        sender: SocketAddr,
    ) -> Result<PeerOwner> {
        for row in parse_table(content).iter() {
            if row.local == sender && row.inode != 0 {
                let pid = find_pid_by_inode(root, row.inode)
                    .ok_or_else(|| anyhow!("inode {} unattributable for {sender}", row.inode))?;
                return owner_of_pid(root, pid);
            }
        }
        Err(anyhow!("no udp owner row for {sender}"))
    }

    /// One row of /proc/net/{tcp,tcp6,udp,udp6} — only the fields the
    /// lookup needs.
    #[derive(Debug)]
    struct Row {
        local: SocketAddr,
        state: String,
        inode: u32,
    }

    /// Parse a /proc net table. Layout (whitespace-split):
    /// sl local_address rem_address st tx:rx tr:tm->when retrnsmt uid
    /// timeout inode — the header line's first field is literally "sl"
    /// (data rows start "0:", "1:", … so a suffix check would eat them);
    /// malformed lines are skipped (defensive, kernel format is stable).
    fn parse_table(content: &str) -> Vec<Row> {
        let mut out = Vec::new();
        for line in content.lines() {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 || f[0] == "sl" {
                continue; // header or short line
            }
            let Some(local) = parse_hex_sock(f[1]) else {
                continue;
            };
            let Ok(inode) = f[9].parse::<u32>() else {
                continue;
            };
            out.push(Row {
                local,
                state: f[3].to_string(),
                inode,
            });
        }
        out
    }

    /// "0100007F:1F90" → 127.0.0.1:8080. v4 = 8 hex chars, v6 = 32; the
    /// kernel prints each 32-bit group with its bytes swapped for
    /// little-endian hosts (the only targets we ship), the port is plain
    /// big-endian hex.
    pub(super) fn parse_hex_sock(s: &str) -> Option<SocketAddr> {
        let (addr, port) = s.split_once(':')?;
        let port = u16::from_str_radix(port, 16).ok()?;
        let sock = match addr.len() {
            8 => {
                let v = u32::from_str_radix(addr, 16).ok()?;
                SocketAddr::from((
                    std::net::Ipv4Addr::new(
                        v as u8,
                        (v >> 8) as u8,
                        (v >> 16) as u8,
                        (v >> 24) as u8,
                    ),
                    port,
                ))
            }
            32 => {
                let mut octets = [0u8; 16];
                for (i, g) in addr.as_bytes().chunks(8).enumerate() {
                    let g = std::str::from_utf8(g).ok()?;
                    let v = u32::from_str_radix(g, 16).ok()?;
                    octets[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
                }
                SocketAddr::from((std::net::Ipv6Addr::from(octets), port))
            }
            _ => return None,
        };
        Some(sock)
    }

    /// Scan a /proc-shaped root for the pid owning socket inode N
    /// (`/proc/<pid>/fd/*` → "socket:[N]"). Unreadable pid dirs (other
    /// user, insufficient permission) are skipped — None means
    /// unattributable, the caller fails closed.
    fn find_pid_by_inode(root: &Path, inode: u32) -> Option<u32> {
        let want = format!("socket:[{inode}]");
        let entries = std::fs::read_dir(root).ok()?;
        for e in entries.flatten() {
            let name = e.file_name();
            let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            let fd_dir = e.path().join("fd");
            let Ok(fds) = std::fs::read_dir(&fd_dir) else {
                continue;
            };
            for fd in fds.flatten() {
                if let Ok(target) = std::fs::read_link(fd.path()) {
                    if target.to_string_lossy() == want {
                        return Some(pid);
                    }
                }
            }
        }
        None
    }

    /// PeerOwner from /proc/<pid>/status ("Uid:" line, first field = real
    /// uid; the SID slot carries the decimal uid string).
    fn owner_of_pid(root: &Path, pid: u32) -> Result<PeerOwner> {
        let status = std::fs::read_to_string(root.join(pid.to_string()).join("status"))
            .map_err(|e| anyhow!("read status of pid {pid}: {e}"))?;
        let uid = status
            .lines()
            .find_map(|l| l.strip_prefix("Uid:"))
            .and_then(|rest| rest.split_whitespace().next())
            .ok_or_else(|| anyhow!("pid {pid} has no Uid line"))?;
        Ok(PeerOwner {
            pid,
            sid: uid.to_string(),
            session: 0,
        })
    }
}

// ---------------------------------------------------------------------
// macOS (W30 step 2): libproc attribution — proc_listallpids +
// PROC_PIDLISTFDS + PROC_PIDFDSOCKETINFO, matching the peer's LOCAL
// tuple (their local addr+port IS our remote view of them); uid via
// PROC_PIDT_SHORTBSDINFO. Same contract as the other tiers: Err =
// unattributable = the forwarder refuses (fail closed). Cross-user
// attribution needs permission to read the other user's process
// (root or same-uid) — an unreadable owner is a no-match -> Err,
// same scope statement as non-root Linux.
//
// Binding decision (plan §3.6): an extern block over the stable
// Darwin ABI (proc_listallpids / proc_pidinfo / proc_pid_fdinfo +
// the xnu proc_info.h structs, layouts mirrored verbatim from
// xnu-11215.1.10 bsd/sys/proc_info.h) — no third-party crate.
// ---------------------------------------------------------------------

#[cfg(target_os = "macos")]
mod darwin_imp {
    use super::{PeerOwner, SocketAddr};
    use anyhow::{anyhow, Result};
    use std::net::{Ipv4Addr, Ipv6Addr};

    // ---- libproc FFI (libSystem) --------------------------------------
    use std::os::raw::{c_int, c_void};

    // libproc.dylib: proc_pid_fdinfo is NOT in libSystem proper (the
    // CI linker proved it) — the explicit link is required.
    #[link(name = "proc")]
    extern "C" {
        fn proc_listallpids(buffer: *mut c_void, buffersize: c_int) -> c_int;
        fn proc_pidinfo(
            pid: c_int,
            flavor: c_int,
            arg: u64,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
        fn proc_pidfdinfo(
            pid: c_int,
            fd: c_int,
            flavor: c_int,
            buffer: *mut c_void,
            buffersize: c_int,
        ) -> c_int;
    }

    // proc_info.h flavors (FD-info enum: VNODEINFO=1, VNODEPATHINFO=2,
    // SOCKETINFO=3 per the SDK). Runs 34792440297/34792652864 returned
    // rb=0 for BOTH flavor 2 and 3 — the dump's flavor sweep maps the
    // live behavior; the enum note stays until the sweep explains it.
    const PROC_PIDLISTFDS: c_int = 1;
    const PROC_PIDFDSOCKETINFO: c_int = 3;
    const PROC_PIDT_SHORTBSDINFO: c_int = 13;
    // fd types (proc_fdinfo.proc_fdtype)
    const PROX_FDTYPE_SOCKET: u32 = 2;
    // socket_info.soi_kind
    const SOCKINFO_IN: i32 = 1; // UDP + generic INET sockets
    const SOCKINFO_TCP: i32 = 2;
    // in_sockinfo.insi_vflag
    const INI_IPV4: u8 = 0x1;
    const INI_IPV6: u8 = 0x2;
    // netinet/tcp_fsm.h (two-pass PREFERENCE only — never correctness)
    const TCPS_ESTABLISHED: i32 = 4;

    // ---- xnu proc_info.h structs, mirrored verbatim -------------------

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ProcFdInfo {
        proc_fd: i32,
        proc_fdtype: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct VinfoStat {
        vst_dev: u32,
        vst_mode: u16,
        vst_nlink: u16,
        vst_ino: u64,
        vst_uid: u32,
        vst_gid: u32,
        vst_atime: i64,
        vst_atimensec: i64,
        vst_mtime: i64,
        vst_mtimensec: i64,
        vst_ctime: i64,
        vst_ctimensec: i64,
        vst_birthtime: i64,
        vst_birthtimensec: i64,
        vst_size: i64,
        vst_blocks: i64,
        vst_blksize: i32,
        vst_flags: u32,
        vst_gen: u32,
        vst_rdev: u32,
        vst_qspare: [i64; 2],
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct SockBufInfo {
        sbi_cc: u32,
        sbi_hiwat: u32,
        sbi_mbcnt: u32,
        sbi_mbmax: u32,
        sbi_lowat: u32,
        sbi_flags: i16,
        sbi_timeo: i16,
    }

    /// struct in4in6_addr { u32 pad[3]; struct in_addr; } — 16 bytes so
    /// it overlays an in6_addr where used as a union variant
    /// (netinet/in.h). The v4 address sits at offset 12.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct In4In6Addr {
        pad: [u32; 3],
        addr4: [u8; 4],
    }

    impl In4In6Addr {
        unsafe fn v4(&self) -> Ipv4Addr {
            Ipv4Addr::from(self.addr4)
        }
        /// overlay read of the full 16 bytes (the C union side)
        unsafe fn v6(&self) -> Ipv6Addr {
            let raw: [u8; 16] = std::ptr::read(self as *const Self as *const [u8; 16]);
            Ipv6Addr::from(raw)
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct InSockInfo {
        insi_fport: i32,
        insi_lport: i32,
        insi_gencnt: u64,
        insi_flags: u32,
        insi_flow: u32,
        insi_vflag: u8,
        insi_ip_ttl: u8,
        rfu_1: u32,
        insi_faddr: In4In6Addr,
        insi_laddr: In4In6Addr,
        insi_v4_tos: u8,
        insi_v6_hlim: u8,
        insi_v6_cksum: i32,
        insi_v6_ifindex: u16,
        insi_v6_hops: i16,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct TcpSockInfo {
        tcpsi_ini: InSockInfo,
        tcpsi_state: i32,
        tcpsi_timer: [i32; 4],
        tcpsi_mss: i32,
        tcpsi_flags: u32,
        rfu_1: u32,
        tcpsi_tp: u64,
    }

    /// socket_info.soi_proto union. CI-proven sizing (run 34793010578
    /// sweep: kernel sizeof(socket_fdinfo) = 792 → union = 792 - 24
    /// (proc_fileinfo) - 216 (pre-union fields) = 552; the big variants
    /// are pri_un/pri_kern_ctl with SOCK_MAXADDRLEN/char[96] arrays).
    /// Oversizing is safe; UNDERsizing makes proc_pidfdinfo return 0
    /// without copying (the rb=0-everywhere failure mode) — the buffer
    /// must be >= the kernel's 792-byte struct.
    #[repr(C)]
    union SocketProto {
        pri_in: InSockInfo,
        pri_tcp: TcpSockInfo,
        _oversize: [u8; 560],
    }

    #[repr(C)]
    struct SocketInfo {
        soi_stat: VinfoStat,
        soi_so: u64,
        soi_pcb: u64,
        soi_type: i32,
        soi_protocol: i32,
        soi_family: i32,
        soi_options: i16,
        soi_linger: i16,
        soi_state: i16,
        soi_qlen: i16,
        soi_incqlen: i16,
        soi_qlimit: i16,
        soi_timeo: i16,
        soi_error: u16,
        soi_oobmark: u32,
        soi_rcv: SockBufInfo,
        soi_snd: SockBufInfo,
        soi_kind: i32,
        rfu_1: u32,
        soi_proto: SocketProto,
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ProcFileInfo {
        fi_openflags: u32,
        fi_status: u32,
        fi_offset: i64,
        fi_type: i32,
        fi_guardflags: u32,
    }

    #[repr(C)]
    struct SocketFdInfo {
        pfi: ProcFileInfo,
        psi: SocketInfo,
    }

    /// PROC_PIDT_SHORTBSDINFO payload (uid at pbsi_uid).
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct ProcBsdShortInfo {
        pbsi_pid: u32,
        pbsi_ppid: u32,
        pbsi_pgid: u32,
        pbsi_status: u32,
        pbsi_comm: [u8; 16], // MAXCOMLEN
        pbsi_flags: u32,
        pbsi_uid: u32,
        pbsi_gid: u32,
        pbsi_ruid: u32,
        pbsi_rgid: u32,
        pbsi_svuid: u32,
        pbsi_svgid: u32,
        pbsi_rfu: u32,
    }

    // ---- the attribution contract -------------------------------------

    pub fn self_owner() -> Result<PeerOwner> {
        let pid = std::process::id() as c_int;
        let uid = uid_of_pid(pid)?;
        Ok(PeerOwner {
            pid: pid as u32,
            sid: uid.to_string(),
            session: 0,
        })
    }

    pub fn tcp_owner(peer: SocketAddr) -> Result<PeerOwner> {
        bounded_scan(std::time::Duration::from_secs(2), move || {
            scan_for_owner(peer, SockKind::Tcp)
        })
    }

    pub fn udp_owner(sender: SocketAddr) -> Result<PeerOwner> {
        bounded_scan(std::time::Duration::from_secs(2), move || {
            scan_for_owner(sender, SockKind::Udp)
        })
    }

    #[derive(Debug)]
    enum SockKind {
        Tcp,
        Udp,
    }

    /// Same worker-isolation pattern as the Linux tier: a stuck libproc
    /// call converts to Err (fail closed) instead of wedging the
    /// forwarder's accept path; at most one orphaned worker per call.
    fn bounded_scan(
        budget: std::time::Duration,
        f: impl FnOnce() -> Result<PeerOwner> + Send + 'static,
    ) -> Result<PeerOwner> {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = tx.send(f());
        });
        match rx.recv_timeout(budget) {
            Ok(r) => r,
            Err(_) => Err(anyhow!(
                "peer attribution scan exceeded {budget:?} - fail closed"
            )),
        }
    }

    /// Full-table scan: every pid -> every socket fd -> local-tuple
    /// match. Two passes (TCP-established preferred, then any) — the
    /// Linux ESTABLISHED-first discipline.
    fn scan_for_owner(peer: SocketAddr, kind: SockKind) -> Result<PeerOwner> {
        for want_established in [true, false] {
            if let Some(pid) = scan_once(&peer, &kind, want_established) {
                let uid = uid_of_pid(pid)?;
                return Ok(PeerOwner {
                    pid: pid as u32,
                    sid: uid.to_string(),
                    session: 0,
                });
            }
        }
        Err(anyhow!(
            "no owning socket found for {peer:?} ({kind:?}) - unattributable, fail closed"
        ))
    }

    fn scan_once(peer: &SocketAddr, kind: &SockKind, want_established: bool) -> Option<c_int> {
        let mut pids = vec![0 as c_int; 4096];
        let n = unsafe {
            proc_listallpids(
                pids.as_mut_ptr() as *mut c_void,
                (pids.len() * std::mem::size_of::<c_int>()) as c_int,
            )
        };
        if n <= 0 {
            return None;
        }
        let pids = &pids[..n as usize];

        let mut fds: Vec<ProcFdInfo> = vec![unsafe { std::mem::zeroed() }; 1024];
        let mut sfd: SocketFdInfo = unsafe { std::mem::zeroed() };

        for &pid in pids {
            if pid <= 0 {
                continue;
            }
            // an unreadable process (other user, non-root) returns <= 0:
            // skipped — if it held the peer socket the overall scan
            // finds no match -> Err (fail closed, documented scope)
            let nb = unsafe {
                proc_pidinfo(
                    pid,
                    PROC_PIDLISTFDS,
                    0,
                    fds.as_mut_ptr() as *mut c_void,
                    (fds.len() * std::mem::size_of::<ProcFdInfo>()) as c_int,
                )
            };
            if nb <= 0 {
                continue;
            }
            let fd_count = (nb as usize) / std::mem::size_of::<ProcFdInfo>();
            for fi in &fds[..fd_count] {
                if fi.proc_fdtype != PROX_FDTYPE_SOCKET {
                    continue;
                }
                let rb = unsafe {
                    proc_pidfdinfo(
                        pid,
                        fi.proc_fd,
                        PROC_PIDFDSOCKETINFO,
                        &mut sfd as *mut SocketFdInfo as *mut c_void,
                        std::mem::size_of::<SocketFdInfo>() as c_int,
                    )
                };
                if rb <= 0 {
                    continue;
                }
                if unsafe { socket_matches(&sfd.psi, peer, kind, want_established) } {
                    return Some(pid);
                }
            }
        }
        None
    }

    /// The peer's LOCAL tuple = (insi_laddr, insi_lport); ports are
    /// in_port_t (network byte order) stored in an int field.
    unsafe fn socket_matches(
        psi: &SocketInfo,
        peer: &SocketAddr,
        kind: &SockKind,
        want_established: bool,
    ) -> bool {
        let ini: &InSockInfo = match (psi.soi_kind, kind) {
            (SOCKINFO_TCP, SockKind::Tcp) => {
                let state = psi.soi_proto.pri_tcp.tcpsi_state;
                if (state == TCPS_ESTABLISHED) != want_established {
                    return false;
                }
                &psi.soi_proto.pri_tcp.tcpsi_ini
            }
            (SOCKINFO_IN, SockKind::Udp) => {
                // pass 1 (established-preferred) is TCP-only
                if want_established {
                    return false;
                }
                &psi.soi_proto.pri_in
            }
            // kind mismatches can never be the peer
            _ => return false,
        };
        let lport = u16::from_be((ini.insi_lport & 0xFFFF) as u16);
        if lport != peer.port() {
            return false;
        }
        match peer {
            SocketAddr::V4(v4) => ini.insi_vflag & INI_IPV4 != 0 && ini.insi_laddr.v4() == *v4.ip(),
            SocketAddr::V6(v6) => ini.insi_vflag & INI_IPV6 != 0 && ini.insi_laddr.v6() == *v6.ip(),
        }
    }

    fn uid_of_pid(pid: c_int) -> Result<u32> {
        let mut info = ProcBsdShortInfo::default();
        let r = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDT_SHORTBSDINFO,
                0,
                &mut info as *mut ProcBsdShortInfo as *mut c_void,
                std::mem::size_of::<ProcBsdShortInfo>() as c_int,
            )
        };
        if r <= 0 {
            return Err(anyhow!(
                "uid lookup failed for pid {pid} (unreadable process?) - fail closed"
            ));
        }
        Ok(info.pbsi_uid)
    }

    /// Diagnostics ONLY (CI-driven debugging, run 34774193404): dump the
    /// raw libproc view — per-socket kind/vflag/lport plus struct-layout
    /// facts — so a failing attribution test surfaces WHY in the log.
    pub(crate) fn debug_dump_sockets() {
        eprintln!(
            "DUMP layout: sizeof(SocketFdInfo)={} sizeof(SocketInfo)={} sizeof(VinfoStat)={} sizeof(InSockInfo)={} sizeof(TcpSockInfo)={} off(soi_kind)={} off(soi_proto)={}",
            std::mem::size_of::<SocketFdInfo>(),
            std::mem::size_of::<SocketInfo>(),
            std::mem::size_of::<VinfoStat>(),
            std::mem::size_of::<InSockInfo>(),
            std::mem::size_of::<TcpSockInfo>(),
            std::mem::offset_of!(SocketInfo, soi_kind),
            std::mem::offset_of!(SocketInfo, soi_proto),
        );
        let mut pids = vec![0 as c_int; 4096];
        let n = unsafe {
            proc_listallpids(
                pids.as_mut_ptr() as *mut c_void,
                (pids.len() * std::mem::size_of::<c_int>()) as c_int,
            )
        };
        eprintln!("DUMP proc_listallpids rc={n} self={}", std::process::id());
        if n <= 0 {
            return;
        }
        let mut fds: Vec<ProcFdInfo> = vec![unsafe { std::mem::zeroed() }; 1024];
        let mut sfd: SocketFdInfo = unsafe { std::mem::zeroed() };
        let mut shown = 0;
        for &pid in &pids[..n as usize] {
            if pid <= 0 || shown > 60 {
                continue;
            }
            let nb = unsafe {
                proc_pidinfo(
                    pid,
                    PROC_PIDLISTFDS,
                    0,
                    fds.as_mut_ptr() as *mut c_void,
                    (fds.len() * std::mem::size_of::<ProcFdInfo>()) as c_int,
                )
            };
            if nb <= 0 {
                continue;
            }
            for fi in &fds[..(nb as usize) / std::mem::size_of::<ProcFdInfo>()] {
                if fi.proc_fdtype != PROX_FDTYPE_SOCKET {
                    continue;
                }
                let rb = unsafe {
                    proc_pidfdinfo(
                        pid,
                        fi.proc_fd,
                        PROC_PIDFDSOCKETINFO,
                        &mut sfd as *mut SocketFdInfo as *mut c_void,
                        std::mem::size_of::<SocketFdInfo>() as c_int,
                    )
                };
                let psi = &sfd.psi;
                unsafe {
                    let ini: &InSockInfo = if psi.soi_kind == SOCKINFO_TCP {
                        &psi.soi_proto.pri_tcp.tcpsi_ini
                    } else if psi.soi_kind == SOCKINFO_IN {
                        &psi.soi_proto.pri_in
                    } else {
                        eprintln!(
                            "DUMP pid={pid} fd={} rb={rb} kind={} (non-INET)",
                            fi.proc_fd, psi.soi_kind
                        );
                        shown += 1;
                        continue;
                    };
                    let state = if psi.soi_kind == SOCKINFO_TCP {
                        psi.soi_proto.pri_tcp.tcpsi_state
                    } else {
                        -1
                    };
                    eprintln!(
                        "DUMP pid={pid} fd={} rb={rb} kind={} proto={} fam={} state={} vflag={:#04x} lport_raw={} lport_host={} laddr_v4={:?}",
                        fi.proc_fd,
                        psi.soi_kind,
                        psi.soi_protocol,
                        psi.soi_family,
                        state,
                        ini.insi_vflag,
                        ini.insi_lport,
                        u16::from_be((ini.insi_lport & 0xFFFF) as u16),
                        ini.insi_laddr.v4()
                    );
                }
                shown += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_allowed_is_exact_uid_equality() {
        // unix: uid strings; windows: SIDs — same exact-equality rule
        assert!(peer_allowed("1000", "1000"));
        assert!(!peer_allowed("1000", "1001"));
        assert!(!peer_allowed("1000", "")); // empty never matches
    }

    // W30 step 2: the libproc tier, exercised against REAL sockets the
    // test itself creates (the runner is macOS; cross-user EPERM→Err is
    // the step-5 lane's second-user test, not a unit test).
    #[cfg(target_os = "macos")]
    mod darwin_libproc {
        use super::super::darwin_imp;

        #[test]
        fn self_owner_is_own_pid_and_uid() {
            let o = darwin_imp::self_owner().expect("self attribution");
            assert_eq!(o.pid, std::process::id());
            assert_eq!(o.sid, unsafe { libc::getuid() }.to_string());
            assert_eq!(o.session, 0);
        }

        #[test]
        fn tcp_round_trip_attributes_own_pid() {
            // the CONNECTING socket's local tuple is what tcp_owner sees
            // as the peer; both ends live in this process
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = l.local_addr().unwrap();
            let c = std::net::TcpStream::connect(addr).unwrap();
            let (_s, peer) = l.accept().unwrap();
            let o = match darwin_imp::tcp_owner(peer) {
                Ok(o) => o,
                Err(e) => {
                    darwin_imp::debug_dump_sockets();
                    panic!("tcp attribution: {e:#}");
                }
            };
            assert_eq!(o.pid, std::process::id());
            drop(c);
        }

        #[test]
        fn tcp_ipv6_round_trip_attributes_own_pid() {
            let l = std::net::TcpListener::bind("[::1]:0").unwrap();
            let addr = l.local_addr().unwrap();
            let _c = std::net::TcpStream::connect(addr).unwrap();
            let (_s, peer) = l.accept().unwrap();
            let o = match darwin_imp::tcp_owner(peer) {
                Ok(o) => o,
                Err(e) => {
                    darwin_imp::debug_dump_sockets();
                    panic!("tcp6 attribution: {e:#}");
                }
            };
            assert_eq!(o.pid, std::process::id());
        }

        #[test]
        fn udp_sender_attribution_own_pid() {
            let rx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let raddr = rx.local_addr().unwrap();
            let tx = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            tx.connect(raddr).unwrap();
            tx.send(b"aztna-attrib").unwrap();
            let mut buf = [0u8; 16];
            let (n, from) = rx.recv_from(&mut buf).unwrap();
            assert_eq!(&buf[..n], b"aztna-attrib");
            let o = match darwin_imp::udp_owner(from) {
                Ok(o) => o,
                Err(e) => {
                    darwin_imp::debug_dump_sockets();
                    panic!("udp attribution: {e:#}");
                }
            };
            assert_eq!(o.pid, std::process::id());
        }

        #[test]
        fn unattributable_fabricated_addr_fails_closed() {
            // a loopback tuple no socket holds: must Err, never Ok-garbage
            let fake = "127.0.0.1:1".parse().unwrap();
            assert!(darwin_imp::tcp_owner(fake).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    mod linux_tables {
        use super::super::linux_imp::{tcp_owner_in, udp_owner_in};
        use super::*;
        use std::os::unix::fs::symlink;

        fn fake_proc(rows: &[(u32, u32)]) -> std::path::PathBuf {
            // rows: (pid, inode) — <root>/<pid>/fd/3 -> socket:[inode],
            // plus a status file with a distinct uid per pid
            let root = std::env::temp_dir().join(format!(
                "aztna-peer-proc-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            for (pid, inode) in rows {
                let dir = root.join(pid.to_string()).join("fd");
                std::fs::create_dir_all(&dir).unwrap();
                symlink(format!("socket:[{inode}]"), dir.join("3")).unwrap();
                std::fs::write(
                    root.join(pid.to_string()).join("status"),
                    format!("Name:\tfake\nUid:\t{pid}\t0\t0\t0\n"),
                )
                .unwrap();
            }
            root
        }

        const TCP_TABLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n \
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111111 1 0000000000000000 100 0 0 10 0\n \
   1: 6C2B0A0A:C350 0100007F:8AE1 01 00000000:00000000 00:00000000 00000000     0        0 999999 1 0000000000000000 24 4 30 10 -1\n \
   2: 0100007F:C350 6C2B0A0A:8AE1 01 00000000:00000000 00:00000000 00000000     0        0 777777 1 0000000000000000 24 4 30 10 -1\n \
   3: 0100007F:C350 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0      0 1 0000000000000000 24 4 30 10 -1\n";

        #[test]
        fn addr_decode() {
            use super::super::linux_imp::parse_hex_sock as parse;
            assert_eq!(
                parse("0100007F:1F90").unwrap(),
                "127.0.0.1:8080".parse::<SocketAddr>().unwrap()
            );
            // ::1 — all-zero groups + final 01000000 (LE of 0x00000001)
            assert_eq!(
                parse("00000000000000000000000001000000:0016").unwrap(),
                "[::1]:22".parse::<SocketAddr>().unwrap()
            );
            assert!(parse("ZZZZ:1").is_none());
        }

        #[test]
        fn tcp_row_match_prefers_established_and_skips_inode0() {
            // rows 2 (inode 777777, ESTABLISHED) and 3 (inode 0, TIME_WAIT)
            // both carry local 127.0.0.1:50000 — the lookup must pick 777777
            let root = fake_proc(&[(4242, 999_999), (5252, 777_777)]);
            let peer = "127.0.0.1:50000".parse().unwrap();
            let o = tcp_owner_in(&root, TCP_TABLE, peer).unwrap();
            assert_eq!(o.pid, 5252);
            assert_eq!(o.sid, "5252");
            assert_eq!(o.session, 0);
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn tcp_row_v4_mapped_elsewhere_is_not_v6() {
            let root = fake_proc(&[(1, 999_999)]);
            // v4 peer vs a v6-shaped row with the same port: no match → Err
            let peer = "127.0.0.2:50000".parse().unwrap();
            assert!(tcp_owner_in(&root, TCP_TABLE, peer).is_err());
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn absent_row_fails_closed() {
            // exit-race shape: the peer's row is gone before lookup
            let root = fake_proc(&[(1, 999_999)]);
            let peer = "127.0.0.1:59999".parse().unwrap();
            assert!(tcp_owner_in(&root, TCP_TABLE, peer).is_err());
            let _ = std::fs::remove_dir_all(&root);
        }

        #[test]
        fn inode_without_pid_dir_fails_closed() {
            // row exists (ESTABLISHED, nonzero inode) but the fd scan can't
            // attribute it — the cross-user shape: unreadable → Err, never
            // a wrong-owner answer
            let root = fake_proc(&[]);
            let p2: SocketAddr = "127.0.0.1:50000".parse().unwrap();
            assert!(tcp_owner_in(&root, TCP_TABLE, p2).is_err());
            let _ = std::fs::remove_dir_all(&root);
        }

        const UDP_TABLE: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer\n \
   0: 0100007F:C351 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 555555 2 0000000000000000 0\n";

        #[test]
        fn udp_row_match() {
            let root = fake_proc(&[(7, 555_555)]);
            let sender: SocketAddr = "127.0.0.1:50001".parse().unwrap();
            let o = udp_owner_in(&root, UDP_TABLE, sender).unwrap();
            assert_eq!(o.pid, 7);
            let _ = std::fs::remove_dir_all(&root);
        }

        /// Live /proc: a real loopback TCP connection attributes to THIS
        /// process with THIS uid (the unix equivalent of the W13 probe).
        /// ss-probed 2026-09-12: WSL mirrored or not, the kernel table
        /// names the true owning process for these sockets.
        #[test]
        fn live_tcp_connection_attributes_to_self() {
            use std::io::Write;
            let srv = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let addr = srv.local_addr().unwrap();
            let mut c = std::net::TcpStream::connect(addr).unwrap();
            // never read here: the peer never sends — a blocking read with
            // no data and no timeout is the wedge this test once had
            c.set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            let local = c.local_addr().unwrap();
            let (_s, _r) = (srv.accept().unwrap(), ());
            let _ = c.write_all(b"x");
            let o = tcp_owner(local).unwrap();
            let me = self_owner().unwrap();
            assert_eq!(o.pid, std::process::id());
            assert_eq!(o.sid, me.sid, "same-user attribution");
            drop(c);
        }

        /// Live /proc: a bound+used UDP socket attributes to this process.
        #[test]
        fn live_udp_socket_attributes_to_self() {
            let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            a.send_to(b"ping", b.local_addr().unwrap()).unwrap();
            let o = udp_owner(a.local_addr().unwrap()).unwrap();
            assert_eq!(o.pid, std::process::id());
            assert_eq!(o.sid, self_owner().unwrap().sid);
        }
    }
}
