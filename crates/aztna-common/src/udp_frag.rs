//! W14 [w14-carrier-mtls]: UDP-app datagram framing over QUIC DATAGRAM
//! frames — shared by gateway and client (single definition). Symmetric
//! in both directions; delivery is all-or-nothing per original datagram.

/// Max original app datagram (matches the raw relay's 65507 budget).
pub const UDP_QUIC_MAX_DGRAM: usize = 65_507;

/// Wire frame for a UDP-app datagram fragment riding a QUIC DATAGRAM:
/// session_id | dgram_id | frag_offset | total_len (all BE u32/u16/u16/u16)
/// | payload. Symmetric: gateway→client responses use the same layout.
/// Delivery is all-or-nothing per original datagram — a missing fragment
/// discards it (UDP semantics; no retransmit, never truncated).
pub const HDR: usize = 4 + 2 + 2 + 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<'a> {
    pub session_id: u32,
    pub dgram_id: u16,
    pub frag_offset: u16,
    pub total_len: u16,
    pub payload: &'a [u8],
}

pub fn encode(out: &mut Vec<u8>, f: &Frame) {
    out.extend_from_slice(&f.session_id.to_be_bytes());
    out.extend_from_slice(&f.dgram_id.to_be_bytes());
    out.extend_from_slice(&f.frag_offset.to_be_bytes());
    out.extend_from_slice(&f.total_len.to_be_bytes());
    out.extend_from_slice(f.payload);
}

/// None = malformed (shorter than the header). Validity of
/// offset/total bounds is checked by the caller (Reassembler).
pub fn decode(b: &[u8]) -> Option<Frame<'_>> {
    if b.len() < HDR {
        return None;
    }
    Some(Frame {
        session_id: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
        dgram_id: u16::from_be_bytes([b[4], b[5]]),
        frag_offset: u16::from_be_bytes([b[6], b[7]]),
        total_len: u16::from_be_bytes([b[8], b[9]]),
        payload: &b[HDR..],
    })
}

/// Split one app datagram into frames sized to the CURRENT runtime
/// maximum (dynamic per the plan — quinn's max_datagram_size varies
/// with PMTU). Returns None if the datagram exceeds the protocol
/// cap (caller refuses, counted) or max is absurdly small.
pub fn fragment(
    session_id: u32,
    dgram_id: u16,
    data: &[u8],
    max_frame: usize,
) -> Option<Vec<Vec<u8>>> {
    if data.len() > u16::MAX as usize || max_frame <= HDR + 1 {
        return None;
    }
    let chunk = max_frame - HDR;
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < data.len() {
        let end = (off + chunk).min(data.len());
        let mut f = Vec::with_capacity(HDR + end - off);
        encode(
            &mut f,
            &Frame {
                session_id,
                dgram_id,
                frag_offset: off as u16,
                total_len: data.len() as u16,
                payload: &data[off..end],
            },
        );
        out.push(f);
        off = end;
    }
    Some(out)
}

/// Bounded reassembly (the DoS surface). Slots cap concurrent partial
/// datagrams per session; bytes cap buffers; malformed (out-of-bounds
/// offset/total) frames are discarded, counted by the caller.
/// `now` drives the gap timeout — fragments of one datagram are sent
/// back-to-back, so the timer only catches loss.
pub struct Reassembler {
    slots: std::collections::HashMap<u16, Slot>,
    max_slots: usize,
    max_bytes: usize,
}

struct Slot {
    total: usize,
    got: std::collections::BTreeMap<usize, Vec<u8>>,
    bytes: usize,
    first_seen: std::time::Instant,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// complete datagram
    Complete(Vec<u8>),
    /// accepted, waiting for more fragments
    Partial,
    /// rejected: offset/total bounds violated, or total over cap
    Malformed,
    /// rejected: slot pressure — oldest partial evicted to make room
    /// (the new frame was still accepted)
    Evicted,
}

impl Reassembler {
    pub fn new(max_slots: usize, max_bytes: usize) -> Self {
        Self {
            slots: Default::default(),
            max_slots,
            max_bytes,
        }
    }

    /// Total buffered bytes across slots (for the per-connection cap).
    pub fn buffered(&self) -> usize {
        self.slots.values().map(|s| s.bytes).sum()
    }

    /// Live partial slots (test visibility + sweep introspection).
    pub fn slots_len(&self) -> usize {
        self.slots.len()
    }

    /// Age out slots whose gap window expired (called by the sweep).
    pub fn reap_older(&mut self, now: std::time::Instant, gap: std::time::Duration) -> usize {
        let dead: Vec<u16> = self
            .slots
            .iter()
            .filter(|(_, s)| now.duration_since(s.first_seen) > gap)
            .map(|(id, _)| *id)
            .collect();
        for id in &dead {
            self.slots.remove(id);
        }
        dead.len()
    }

    pub fn accept(&mut self, f: &Frame, now: std::time::Instant) -> Outcome {
        let total = f.total_len as usize;
        let off = f.frag_offset as usize;
        if total == 0 || total > UDP_QUIC_MAX_DGRAM || off + f.payload.len() > total {
            return Outcome::Malformed;
        }
        // slot pressure: a NEW dgram_id evicts the OLDEST partial
        if !self.slots.contains_key(&f.dgram_id) && self.slots.len() >= self.max_slots {
            if let Some(id) = self.oldest_id() {
                self.slots.remove(&id);
            }
        }
        let slot = self.slots.entry(f.dgram_id).or_insert_with(|| Slot {
            total,
            got: Default::default(),
            bytes: 0,
            first_seen: now,
        });
        // per-slot byte cap (against a hostile single giant dgram)
        if slot.bytes + f.payload.len() > self.max_bytes {
            self.slots.remove(&f.dgram_id);
            return Outcome::Malformed;
        }
        let mut evicted = false;
        if !slot.got.contains_key(&off) {
            // global pressure: drop the OLDEST OTHER partial, accept this
            let global_cap = self.max_bytes.saturating_mul(self.max_slots.max(1));
            if self.buffered() + f.payload.len() > global_cap {
                if let Some(id) = self.oldest_id() {
                    if id != f.dgram_id && self.slots.remove(&id).is_some() {
                        evicted = true;
                    }
                }
            }
            let slot = self.slots.get_mut(&f.dgram_id).expect("slot present");
            slot.got.insert(off, f.payload.to_vec());
            slot.bytes += f.payload.len();
        }
        // contiguous-complete check
        let (total, complete) = {
            let slot = self.slots.get(&f.dgram_id).expect("slot present");
            let mut want = 0usize;
            let mut complete = true;
            for (&o, chunk) in slot.got.range(..) {
                if o != want {
                    complete = false;
                    break;
                }
                want += chunk.len();
            }
            (slot.total, complete && want == slot.total)
        };
        if complete {
            let mut data = Vec::with_capacity(total);
            if let Some(slot) = self.slots.remove(&f.dgram_id) {
                for (_, chunk) in slot.got {
                    data.extend_from_slice(&chunk);
                }
            }
            if evicted {
                return Outcome::Evicted;
            }
            return Outcome::Complete(data);
        }
        if evicted {
            return Outcome::Evicted;
        }
        Outcome::Partial
    }

    fn oldest_id(&self) -> Option<u16> {
        self.slots
            .iter()
            .min_by_key(|(_, s)| s.first_seen)
            .map(|(id, _)| *id)
    }
}
