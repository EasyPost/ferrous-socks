use std::sync::atomic::{AtomicU64, Ordering};


pub(crate) struct Stats {
    in_flight: AtomicU64,
    request_id: AtomicU64,
}

impl Stats {
    pub fn new() -> Self {
        Stats {
            in_flight: AtomicU64::default(),
            request_id: AtomicU64::new(1)
        }
    }

    pub fn start_request(&self) -> u64 {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        self.request_id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn finish_request(&self, request_id: u64) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
    }
}
