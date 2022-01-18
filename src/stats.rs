use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::SystemTime;

use log::debug;
use serde::Serialize;
use tokio::sync::RwLock;

use crate::request::{Connection, Request};
use crate::util::serialize_system_time;

trait StatIncrement {
    type BaseType;

    fn stat_increment(&self);
    fn load_stat(&self) -> Self::BaseType;
}

impl StatIncrement for AtomicU64 {
    type BaseType = u64;

    fn stat_increment(&self) {
        self.fetch_add(1, Ordering::Relaxed);
    }

    fn load_stat(&self) -> u64 {
        self.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Serialize)]
pub struct InFlightConnection {
    local_end: SocketAddr,
    remote_end: SocketAddr,
}

impl InFlightConnection {
    fn new(local_end: SocketAddr, remote_end: SocketAddr) -> Self {
        InFlightConnection {
            local_end,
            remote_end,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Session {
    source_address: SocketAddr,
    request: Option<Request>,
    connection: Option<InFlightConnection>,
    #[serde(serialize_with = "serialize_system_time")]
    start_time: SystemTime,
}

impl Session {
    fn new(source_address: SocketAddr) -> Self {
        Session {
            source_address,
            request: None,
            connection: None,
            start_time: SystemTime::now(),
        }
    }

    fn set_request(&mut self, request: &Request) {
        self.request = Some(request.clone());
    }

    fn set_connection(&mut self, connection: InFlightConnection) {
        self.connection = Some(connection)
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    handshake_failed: AtomicU64,
    handshake_success: AtomicU64,
    handshake_authenticated: AtomicU64,
    handshake_timeout: AtomicU64,
    session_success: AtomicU64,
    session_error: AtomicU64,
    session_timeout: AtomicU64,
    connection_connected: AtomicU64,
    connection_not_allowed: AtomicU64,
    connection_address_not_supported: AtomicU64,
    connection_socks_failure: AtomicU64,
    connection_network_unreachable: AtomicU64,
    in_flight: AtomicU64,
    next_request_id: AtomicU64,
    bytes_client_to_server: AtomicU64,
    bytes_server_to_client: AtomicU64,
    sessions: RwLock<HashMap<u64, Session>>,
    proxy_protocol_timeout: AtomicU64,
}

#[derive(Debug, Serialize)]
pub struct DumpableStats<'a> {
    handshake_failed: u64,
    handshake_success: u64,
    handshake_timeout: u64,
    session_success: u64,
    session_error: u64,
    session_timeout: u64,
    connection_connected: u64,
    connection_not_allowed: u64,
    connection_address_not_supported: u64,
    connection_socks_failure: u64,
    connection_network_unreachable: u64,
    bytes_client_to_server: u64,
    bytes_server_to_client: u64,
    in_flight: u64,
    sessions: &'a HashMap<u64, Session>,
    proxy_protocol_timeout: u64,
}

impl Stats {
    pub fn new() -> Self {
        Stats {
            next_request_id: AtomicU64::new(1),
            sessions: RwLock::new(HashMap::new()),
            ..Default::default()
        }
    }

    pub fn handshake_failed(&self) {
        self.handshake_failed.stat_increment();
    }

    pub fn handshake_authenticated(&self) {
        self.handshake_authenticated.stat_increment();
    }

    pub fn handshake_success(&self) {
        self.handshake_success.stat_increment();
    }

    pub fn handshake_timeout(&self) {
        self.handshake_timeout.stat_increment();
    }

    pub fn session_success(&self) {
        self.session_success.stat_increment();
    }

    pub fn session_error(&self) {
        self.session_error.stat_increment();
    }

    pub fn session_timeout(&self) {
        self.session_timeout.stat_increment();
    }

    pub fn proxy_protocol_timeout(&self) {
        self.proxy_protocol_timeout.stat_increment();
    }

    pub fn record_connection(&self, c: &Result<Connection, ::std::io::Error>) {
        match c {
            Ok(Connection::Connected(_)) => self.connection_connected.stat_increment(),
            Ok(Connection::AddressNotSupported) => {
                self.connection_address_not_supported.stat_increment()
            }
            Ok(Connection::NotAllowed) => self.connection_not_allowed.stat_increment(),
            Ok(Connection::SocksFailure) => self.connection_socks_failure.stat_increment(),
            Err(_) => self.connection_network_unreachable.stat_increment(),
        }
    }

    pub async fn start_request(&self, source_address: SocketAddr) -> u64 {
        self.in_flight.stat_increment();
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

    pub fn record_traffic(&self, stoc: u64, ctos: u64) {
        debug!("copied {} bytes from c->s and {} bytes s->c", ctos, stoc);
        self.bytes_server_to_client
            .fetch_add(stoc, Ordering::Relaxed);
        self.bytes_client_to_server
            .fetch_add(ctos, Ordering::Relaxed);
    }

    pub async fn set_request(&self, request_id: u64, request: &Request) {
        let mut lock = self.sessions.write().await;
        if let Some(s) = lock.get_mut(&request_id) {
            s.set_request(request)
        }
    }

    pub async fn set_connection(
        &self,
        request_id: u64,
        local_end: SocketAddr,
        remote_end: SocketAddr,
    ) {
        let mut lock = self.sessions.write().await;
        if let Some(s) = lock.get_mut(&request_id) {
            s.set_connection(InFlightConnection::new(local_end, remote_end))
        }
    }

    pub async fn serialize_to_vec(&self) -> Result<Vec<u8>, serde_json::error::Error> {
        let lock = self.sessions.read().await;
        let buf = DumpableStats {
            handshake_failed: self.handshake_failed.load_stat(),
            handshake_success: self.handshake_success.load_stat(),
            handshake_timeout: self.handshake_timeout.load_stat(),
            session_success: self.session_success.load_stat(),
            session_error: self.session_error.load_stat(),
            session_timeout: self.session_timeout.load_stat(),
            in_flight: self.in_flight.load_stat(),
            connection_connected: self.connection_connected.load_stat(),
            connection_address_not_supported: self.connection_address_not_supported.load_stat(),
            connection_not_allowed: self.connection_not_allowed.load_stat(),
            connection_socks_failure: self.connection_socks_failure.load_stat(),
            connection_network_unreachable: self.connection_network_unreachable.load_stat(),
            bytes_server_to_client: self.bytes_server_to_client.load_stat(),
            bytes_client_to_server: self.bytes_client_to_server.load_stat(),
            sessions: &*lock,
            proxy_protocol_timeout: self.proxy_protocol_timeout.load_stat(),
        };
        serde_json::to_vec(&buf)
    }
}
