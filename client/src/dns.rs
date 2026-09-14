//! W4.1 [ADR-0016]: minimal split-horizon DNS responder.
//! A-only, NO recursion: known zone names answer with the mapped loopback IP,
//! known names with a non-A qtype get NOERROR/empty, everything else gets
//! NXDOMAIN — the private resolver never forwards upstream (no DNS leak).

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

pub const TYPE_A: u16 = 1;
pub const CLASS_IN: u16 = 1;
/// Short TTL: policy changes stop being served within seconds [W4.1 F4].
const ANSWER_TTL_SECS: u32 = 5;

pub struct Question {
    pub id: u16,
    pub rd: bool,
    /// QNAME with compression resolved, labels still length-prefixed and
    /// zero-terminated — echoed verbatim in the reply.
    pub raw_name: Vec<u8>,
    /// Lossy lowercase dotted form for the zone lookup.
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

/// Parse a DNS query packet (one question). Returns None on malformed input.
pub fn parse_query(pkt: &[u8]) -> Option<Question> {
    if pkt.len() < 12 {
        return None;
    }
    let id = be16(&pkt[0..2]);
    let flags = be16(&pkt[2..4]);
    if flags & 0x8000 != 0 {
        return None; // a response, not a query
    }
    let qdcount = be16(&pkt[4..6]);
    if qdcount < 1 {
        return None;
    }
    // QNAME: labels with optional compression pointers (loop-guarded)
    let mut raw_name: Vec<u8> = Vec::new();
    let mut name = String::new();
    let mut pos = 12usize;
    let mut jumps = 0usize;
    loop {
        match pkt.get(pos) {
            None => return None,
            Some(&0) => {
                raw_name.push(0);
                pos += 1;
                break;
            }
            Some(&l) if l & 0xC0 == 0xC0 => {
                // compression pointer
                if pkt.len() < pos + 2 || jumps >= 16 {
                    return None;
                }
                let target = ((l & 0x3F) as usize) << 8 | *pkt.get(pos + 1)? as usize;
                if target >= pos {
                    return None; // forward pointers = loops
                }
                pos = target;
                jumps += 1;
            }
            Some(&l) => {
                let l = l as usize;
                if l == 0 || pkt.len() < pos + 1 + l || raw_name.len() + l + 1 > 255 {
                    return None;
                }
                let label = &pkt[pos + 1..pos + 1 + l];
                raw_name.push(l as u8);
                raw_name.extend_from_slice(label);
                name.push_str(&String::from_utf8_lossy(label));
                name.push('.');
                pos += 1 + l;
            }
        }
    }
    if pkt.len() < pos + 4 {
        return None;
    }
    Some(Question {
        id,
        rd: flags & 0x0100 != 0,
        raw_name,
        name: name.trim_end_matches('.').to_ascii_lowercase(),
        qtype: be16(&pkt[pos..pos + 2]),
        qclass: be16(&pkt[pos + 2..pos + 4]),
    })
}

/// Build the reply: A answer / empty NOERROR / NXDOMAIN (see module docs).
pub fn build_reply(q: &Question, answer_ip: Option<&str>) -> Vec<u8> {
    let octets = answer_ip.and_then(|ip| {
        let o: Vec<u8> = ip.split('.').filter_map(|p| p.parse::<u8>().ok()).collect();
        (o.len() == 4).then_some(o)
    });
    let (rcode, ancount) = if q.qtype == TYPE_A && q.qclass == CLASS_IN {
        match octets.as_deref() {
            Some(_) => (0u16, 1u16),
            None => (3, 0), // unknown name (or bad map entry) -> NXDOMAIN
        }
    } else if octets.is_some() {
        (0, 0) // known name, non-A qtype -> NOERROR, zero answers
    } else {
        (3, 0)
    };
    let mut out = Vec::with_capacity(12 + q.raw_name.len() + 4 + 16);
    out.extend_from_slice(&q.id.to_be_bytes());
    let flags: u16 = 0x8000 // QR=1 (reply)
        | if q.rd { 0x0100 } else { 0 }
        | rcode;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT (echo the question)
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out.extend_from_slice(&q.raw_name);
    out.extend_from_slice(&q.qtype.to_be_bytes());
    out.extend_from_slice(&q.qclass.to_be_bytes());
    if ancount == 1 {
        out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // name pointer -> offset 12
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ANSWER_TTL_SECS.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
        out.extend_from_slice(octets.as_deref().unwrap_or(&[0; 4]));
    }
    out
}

/// Serve DNS forever on the bound socket. Malformed packets are dropped.
/// `zones`: lowercase fqdn -> loopback IP (shared with the zone manager).
pub async fn serve(
    sock: tokio::net::UdpSocket,
    zones: Arc<RwLock<HashMap<String, String>>>,
) -> anyhow::Result<()> {
    let mut buf = vec![0u8; 512];
    loop {
        let (n, peer) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(e) => {
                // Windows connected-UDP trap: ICMP port-unreachable from a
                // vanished client surfaces as WSAECONNRESET here — count it
                // (the deafness watchdog from the W4.7 lesson)
                let class = if e.kind() == std::io::ErrorKind::ConnectionReset {
                    "conn_reset"
                } else {
                    "other"
                };
                crate::metrics::dns_responder_errors()
                    .with_label_values(&[class])
                    .inc();
                eprintln!("[dns] recv error: {e}");
                continue;
            }
        };
        if let Some(q) = parse_query(&buf[..n]) {
            let ip = zones.read().await.get(&q.name).cloned();
            let result = if ip.is_some() {
                if q.qtype == TYPE_A && q.qclass == CLASS_IN {
                    "answered"
                } else {
                    "empty"
                }
            } else {
                "nxdomain"
            };
            crate::metrics::dns_queries_total()
                .with_label_values(&[result])
                .inc();
            let reply = build_reply(&q, ip.as_deref());
            if let Err(e) = sock.send_to(&reply, peer).await {
                eprintln!("[dns] send error to {peer}: {e}");
            }
        }
    }
}

/// Windows: disable WSAECONNRESET surfacing (SIO_UDP_CONNRESET). The classic
/// connected-UDP trap: ICMP port-unreachable from a vanished client makes
/// every following recv_from fail with 10054, leaving the responder deaf
/// [E2E W4.7 lesson]. No-op elsewhere.
pub use aztna_common::net::udp_no_connreset;

#[cfg(test)]
mod tests {
    use super::*;

    /// Hand-built query: id 0xBEEF, RD, one question erp.corp.com A IN.
    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&0xBEEFu16.to_be_bytes());
        p.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&[0; 6]);
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&CLASS_IN.to_be_bytes());
        p
    }

    fn rcode_of(p: &[u8]) -> u16 {
        be16(&p[2..4]) & 0x000F
    }
    fn ancount_of(p: &[u8]) -> u16 {
        be16(&p[6..8])
    }
    fn answer_ip(p: &[u8]) -> Option<String> {
        // skip header(12) + question (name ends at first 0 len byte)
        let mut i = 12;
        while p.get(i) != Some(&0) {
            i += 1 + *p.get(i)? as usize;
        }
        i += 1 + 4; // root + qtype + qclass
        if ancount_of(p) == 0 {
            return None;
        }
        let rr = &p[i..];
        let rdlen = be16(&rr[10..12]) as usize;
        let rdata = &rr[12..12 + rdlen];
        Some(
            rdata
                .iter()
                .map(|b| b.to_string())
                .collect::<Vec<_>>()
                .join("."),
        )
    }

    #[test]
    fn parse_and_answer_round_trip() {
        let q = parse_query(&query("erp.corp.com", TYPE_A)).expect("parse");
        assert_eq!(q.id, 0xBEEF);
        assert!(q.rd);
        assert_eq!(q.name, "erp.corp.com");
        assert_eq!(q.qtype, TYPE_A);
        assert_eq!(q.qclass, CLASS_IN);

        let r = build_reply(&q, Some("127.0.0.10"));
        assert_eq!(rcode_of(&r), 0);
        assert_eq!(ancount_of(&r), 1);
        assert_eq!(answer_ip(&r).as_deref(), Some("127.0.0.10"));

        // id echoed
        assert_eq!(be16(&r[0..2]), 0xBEEF);
    }

    #[test]
    fn unknown_name_nxdomain() {
        let q = parse_query(&query("unlisted.corp.com", TYPE_A)).unwrap();
        let r = build_reply(&q, None);
        assert_eq!(rcode_of(&r), 3, "NXDOMAIN for unknown names");
        assert_eq!(ancount_of(&r), 0);
    }

    #[test]
    fn known_name_non_a_is_empty_noerror() {
        let q = parse_query(&query("erp.corp.com", 28 /* AAAA */)).unwrap();
        let r = build_reply(&q, Some("127.0.0.10"));
        assert_eq!(rcode_of(&r), 0);
        assert_eq!(ancount_of(&r), 0, "no v6 addresses advertised");
    }

    #[test]
    fn malformed_packets_rejected() {
        assert!(parse_query(&[]).is_none());
        assert!(parse_query(&[0; 4]).is_none());
        // query flag (QR) set -> not a query
        let mut p = query("a.b", TYPE_A);
        p[2] |= 0x80;
        assert!(parse_query(&p).is_none());
        // truncated name (length runs past the packet)
        let mut p = query("erp.corp.com", TYPE_A);
        p.truncate(14);
        assert!(parse_query(&p).is_none());
    }

    /// End-to-end responder check over a real UDP socket: A answered from the
    /// shared zone map, unknown names NXDOMAIN.
    #[tokio::test]
    async fn responder_answers_from_zone_map() {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let zones: Arc<RwLock<HashMap<String, String>>> = Arc::new(Default::default());
        zones
            .write()
            .await
            .insert("erp.corp.com".into(), "127.0.0.10".into());
        let server = tokio::spawn(serve(sock, zones.clone()));

        let c = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        c.connect(addr).await.unwrap();
        let mut buf = [0u8; 512];
        c.send(&query("ERP.CORP.COM", TYPE_A)).await.unwrap(); // case-insensitive
        let (n, _) = c.recv_from(&mut buf).await.unwrap();
        let reply = &buf[..n];
        assert_eq!(rcode_of(reply), 0);
        assert_eq!(answer_ip(reply).as_deref(), Some("127.0.0.10"));

        c.send(&query("nope.corp.com", TYPE_A)).await.unwrap();
        let (n, _) = c.recv_from(&mut buf).await.unwrap();
        assert_eq!(rcode_of(&buf[..n]), 3, "unknown name must NXDOMAIN");

        server.abort();
    }
}
