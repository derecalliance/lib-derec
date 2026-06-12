//! In-process transport that buffers outbound `(endpoint, bytes)`
//! pairs in an `Arc<Mutex<VecDeque>>` so the test driver can drain
//! them and feed each message to the matching peer.

use derec_library::protocol::{DeRecTransport, TransportFuture};
use derec_proto::TransportProtocol;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

type Envelope = (TransportProtocol, Vec<u8>);

#[derive(Clone, Default)]
pub struct InProcessTransport {
    outbox: Arc<Mutex<VecDeque<Envelope>>>,
}

impl InProcessTransport {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn drain(&self) -> Vec<Envelope> {
        let mut guard = self.outbox.lock().expect("transport outbox mutex poisoned");
        guard.drain(..).collect()
    }
}

impl DeRecTransport for InProcessTransport {
    fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> TransportFuture<'_> {
        let entry = (endpoint.clone(), message);
        let outbox = self.outbox.clone();
        Box::pin(async move {
            outbox
                .lock()
                .expect("transport outbox mutex poisoned")
                .push_back(entry);
            Ok(())
        })
    }
}
