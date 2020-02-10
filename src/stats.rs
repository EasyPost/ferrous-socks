use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::net::SocketAddr;
use std::time::Instant;

use tokio::sync::RwLock;

use crate::request::Request;


#[derive(Debug)]
pub struct Session{
    source_address: SocketAddr,
    dest_address: Option<Request>,
    start_time: Instant,
}


impl Session {
    fn new(source_address: SocketAddr) -> Self {
        Session {
            source_address,
            dest_address: None,
            start_time: Instant::now()
        }
    }

    fn set_request(&mut self, request: &Request) {
        self.dest_address = Some(request.clone());
    }
}


#[derive(Debug)]
pub struct Stats {
    handshake_failed: AtomicU64,
    handshake_success: AtomicU64,
    in_flight: AtomicU64,
    next_request_id: AtomicU64,
    sessions: RwLock<HashMap<u64, Session>>,
}

impl Stats {
    pub fn new() -> Self {
        Stats {
            handshake_failed: AtomicU64::default(),
            handshake_success: AtomicU64::default(),
            in_flight: AtomicU64::default(),
            next_request_id: AtomicU64::new(1),
            sessions: RwLock::new(HashMap::new()),
        }
    }

    pub fn handshake_failed(&self) {
        self.handshake_failed.fetch_add(1, Ordering::Relaxed);
    }

    pub fn handshake_success(&self) {
        self.handshake_success.fetch_add(1, Ordering::Relaxed);
    }

    pub async fn start_request(&self, source_address: SocketAddr) -> u64 {
        self.in_flight.fetch_add(1, Ordering::Relaxed);
        let conn_id = self.next_request_id.fetch_add(1, Ordering::SeqCst);
        let mut lock = self.sessions.write().await;
        lock.insert(conn_id, Session::new(source_address));
        conn_id
    }

    pub async fn finish_request(&self, request_id: u64) {
        self.in_flight.fetch_sub(1, Ordering::Relaxed);
        let mut lock = self.sessions.write().await;
        lock.remove(&request_id);
    }

    pub async fn set_request(&self, request_id: u64, request: &Request) {
        let mut lock = self.sessions.write().await;
        lock.get_mut(&request_id).map(|s| s.set_request(request));
    }
}
