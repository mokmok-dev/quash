use bytes::Bytes;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::AtomicBool;
use tokio::sync::Notify;

/// Tracks an outbound byte stream so it can be replayed after a reconnect.
///
/// Every chunk pulled from the local side is tagged with its absolute offset
/// in the stream. Chunks stay buffered until the peer acknowledges applying
/// them, so a new QUIC connection can resend from the last applied offset
/// without losing or duplicating bytes.
#[derive(Default)]
pub struct SendQueue {
    next_offset: u64,
    acked: u64,
    sent: u64,
    chunks: VecDeque<(u64, Bytes)>,
}

impl SendQueue {
    /// Appends a chunk and returns its assigned offset.
    pub fn push(&mut self, payload: Bytes) -> u64 {
        let offset = self.next_offset;
        self.next_offset += payload.len() as u64;
        self.chunks.push_back((offset, payload));
        offset
    }

    /// Records that the peer applied everything below `offset`.
    pub fn ack(&mut self, offset: u64) {
        if offset <= self.acked {
            return;
        }
        self.acked = offset;
        while let Some((start, payload)) = self.chunks.front() {
            if start + payload.len() as u64 <= self.acked {
                self.chunks.pop_front();
            } else {
                break;
            }
        }
    }

    /// Starts a fresh link: everything unacknowledged becomes eligible again.
    pub const fn rewind(&mut self) {
        self.sent = self.acked;
    }

    /// Drops all state for a brand-new session (the old one expired).
    pub fn reset(&mut self) {
        self.next_offset = 0;
        self.acked = 0;
        self.sent = 0;
        self.chunks.clear();
    }

    /// Chunks to transmit now, advancing the send cursor. Bytes are cheap
    /// clones; the originals stay buffered until acknowledged.
    pub fn take_pending(&mut self) -> Vec<(u64, Bytes)> {
        let mut out = Vec::new();
        for (offset, payload) in &self.chunks {
            let end = offset + payload.len() as u64;
            if end <= self.sent {
                continue;
            }
            if *offset >= self.sent {
                out.push((*offset, payload.clone()));
            } else {
                // Partially sent before a reconnect: resend the remainder.
                let skip = usize::try_from(self.sent - *offset).unwrap_or(usize::MAX);
                out.push((*offset + skip as u64, payload.slice(skip..)));
            }
        }
        self.sent = self.next_offset;
        out
    }

    #[must_use]
    pub const fn is_drained(&self) -> bool {
        self.acked == self.next_offset
    }
}

/// Reassembles an inbound byte stream, tolerating duplicates and reordering
/// introduced by connection resumption.
#[derive(Default)]
pub struct Reassembler {
    applied: u64,
    pending: BTreeMap<u64, Bytes>,
}

impl Reassembler {
    /// Accepts a chunk. Returns the run of contiguous chunks that became
    /// applicable, in order. A duplicate yields an empty vec; an out-of-order
    /// chunk is buffered until the gap fills.
    pub fn accept(&mut self, offset: u64, payload: Bytes) -> Vec<Bytes> {
        if offset < self.applied {
            return Vec::new();
        }
        if offset > self.applied {
            self.pending.entry(offset).or_insert(payload);
            return Vec::new();
        }
        let mut out = vec![payload];
        self.applied += out[0].len() as u64;
        while let Some(next) = self.pending.remove(&self.applied) {
            self.applied += next.len() as u64;
            out.push(next);
        }
        out
    }

    #[must_use]
    pub const fn applied(&self) -> u64 {
        self.applied
    }

    /// Drops all state for a brand-new session (the old one expired).
    pub fn reset(&mut self) {
        self.applied = 0;
        self.pending.clear();
    }
}

/// State that outlives an individual QUIC connection so a session can resume
/// after a network handover or a suspended process. Shared by both ends.
pub struct SessionState {
    pub send: tokio::sync::Mutex<SendQueue>,
    pub recv: tokio::sync::Mutex<Reassembler>,
    /// Signalled when there is new uplink data or an acknowledgement moved the
    /// send cursor so the link should flush.
    pub send_ready: Notify,
    /// Set once the local side has no more bytes to send (stdin or TCP EOF).
    pub fin: AtomicBool,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            send: tokio::sync::Mutex::new(SendQueue::default()),
            recv: tokio::sync::Mutex::new(Reassembler::default()),
            send_ready: Notify::new(),
            fin: AtomicBool::new(false),
        }
    }
}

impl SessionState {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::{Reassembler, SendQueue};

    #[test]
    fn send_queue_trims_acknowledged_chunks() {
        let mut q = SendQueue::default();
        assert_eq!(q.push(b"abc".to_vec().into()), 0);
        assert_eq!(q.push(b"defg".to_vec().into()), 3);
        q.ack(3);
        q.rewind();
        let offsets: Vec<_> = q.take_pending().iter().map(|(o, _)| *o).collect();
        assert_eq!(offsets, vec![3]);
        q.ack(7);
        assert!(q.is_drained());
    }

    #[test]
    fn send_queue_resends_after_rewind() {
        let mut q = SendQueue::default();
        q.push(b"abc".to_vec().into());
        assert_eq!(q.take_pending().len(), 1);
        assert!(!q.is_drained());
        q.rewind();
        assert_eq!(q.take_pending().len(), 1);
    }

    #[test]
    fn send_queue_sends_partial_remainder() {
        let mut q = SendQueue::default();
        q.push(b"abcdef".to_vec().into());
        q.take_pending();
        q.ack(2);
        q.rewind();
        let pending = q.take_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].0, 2);
        assert_eq!(&pending[0].1[..], b"cdef");
    }

    #[test]
    fn reassembler_drops_duplicates_and_reorders() {
        let mut r = Reassembler::default();
        assert_eq!(r.accept(0, b"abc".to_vec().into()).len(), 1);
        assert_eq!(r.applied(), 3);
        assert!(r.accept(0, b"abc".to_vec().into()).is_empty());
        assert!(r.accept(6, b"ghi".to_vec().into()).is_empty());
        let flushed = r.accept(3, b"def".to_vec().into());
        assert_eq!(flushed.len(), 2);
        assert_eq!(r.applied(), 9);
    }
}
