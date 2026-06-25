//! Transaction support for the high-level client.
//!
//! BACnet confirmed requests are correlated to their responses by an *invoke
//! ID*: a single byte chosen by the requester and echoed back in the
//! ComplexAck / SimpleAck / Error / Reject / Abort PDU. This module owns the
//! allocation of those IDs.
//!
//! The current client issues one request at a time and blocks for the reply, so
//! a monotonic wrapping counter is sufficient. It is kept behind its own type
//! (with interior mutability) so that a future concurrent or async client can
//! grow it into a full outstanding-transaction table without changing callers.

use std::sync::atomic::{AtomicU8, Ordering};

/// Allocates invoke IDs for confirmed-request transactions.
#[derive(Debug, Default)]
pub(crate) struct InvokeIdAllocator {
    next: AtomicU8,
}

impl InvokeIdAllocator {
    /// Create an allocator starting from invoke ID 0.
    pub(crate) fn new() -> Self {
        Self {
            next: AtomicU8::new(0),
        }
    }

    /// Return the next invoke ID, wrapping from 255 back to 0.
    pub(crate) fn next_id(&self) -> u8 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocates_sequentially() {
        let alloc = InvokeIdAllocator::new();
        assert_eq!(alloc.next_id(), 0);
        assert_eq!(alloc.next_id(), 1);
        assert_eq!(alloc.next_id(), 2);
    }

    #[test]
    fn wraps_at_byte_boundary() {
        let alloc = InvokeIdAllocator::new();
        // Advance to 255.
        for _ in 0..255 {
            alloc.next_id();
        }
        assert_eq!(alloc.next_id(), 255);
        // The next allocation must wrap back to 0 rather than overflow-panic.
        assert_eq!(alloc.next_id(), 0);
    }
}
