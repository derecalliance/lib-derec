//! Test peer composed of a Postgres-backed protocol + in-process
//! transport + a label. Multiple peers can share one `SharedClient`
//! (and therefore one isolated schema) to exercise multi-tenant
//! scenarios.

use std::collections::HashMap;

use derec_library::protocol::{DeRecEvent, DeRecProtocol, DeRecProtocolBuilder};
use derec_proto::{Protocol, TransportProtocol};

use crate::db::SharedClient;
use crate::stores::{
    PostgresChannelStore, PostgresSecretStore, PostgresShareStore, PostgresUserSecretStore,
};
use crate::transport::InProcessTransport;

pub const DEFAULT_TEST_SECRET_ID: u64 = 0xDE_2EC;

pub type PostgresProtocol = DeRecProtocol<
    PostgresChannelStore,
    PostgresShareStore,
    PostgresSecretStore,
    PostgresUserSecretStore,
    PostgresInMemoryStateStore,
    InProcessTransport,
>;

/// In-memory state store used by the postgres smoke test until the
/// real postgres-backed implementation ships. Each row is keyed by
/// `(secret_id, StateKey)` and holds the full `StateItem` payload.
#[derive(Default, Clone)]
pub struct PostgresInMemoryStateStore {
    data: HashMap<(u64, derec_library::protocol::StateKey), derec_library::protocol::StateItem>,
}
impl derec_library::protocol::DeRecStateStore for PostgresInMemoryStateStore {
    fn save(
        &mut self,
        secret_id: u64,
        item: derec_library::protocol::StateItem,
    ) -> derec_library::protocol::StateStoreFuture<'_, ()> {
        self.data.insert((secret_id, item.key()), item);
        Box::pin(std::future::ready(Ok(())))
    }
    fn load(
        &self,
        secret_id: u64,
        key: derec_library::protocol::StateKey,
    ) -> derec_library::protocol::StateStoreFuture<'_, Option<derec_library::protocol::StateItem>>
    {
        let result = self.data.get(&(secret_id, key)).cloned();
        Box::pin(std::future::ready(Ok(result)))
    }
    fn remove(
        &mut self,
        secret_id: u64,
        key: derec_library::protocol::StateKey,
    ) -> derec_library::protocol::StateStoreFuture<'_, bool> {
        let removed = self.data.remove(&(secret_id, key)).is_some();
        Box::pin(std::future::ready(Ok(removed)))
    }
    fn load_all(
        &self,
        secret_id: u64,
        kind: derec_library::protocol::StateKind,
    ) -> derec_library::protocol::StateStoreFuture<'_, Vec<derec_library::protocol::StateItem>>
    {
        let entries: Vec<derec_library::protocol::StateItem> = self
            .data
            .iter()
            .filter(|((s, k), _)| *s == secret_id && k.kind() == kind)
            .map(|(_, item)| item.clone())
            .collect();
        Box::pin(std::future::ready(Ok(entries)))
    }
}

pub struct Peer {
    pub label: &'static str,
    pub uri: String,
    pub protocol: PostgresProtocol,
    pub transport: InProcessTransport,
}

#[derive(Clone, Copy)]
pub struct PeerOptions {
    pub secret_id: u64,
    pub threshold: usize,
    pub replica_id: Option<u64>,
}

impl Default for PeerOptions {
    fn default() -> Self {
        Self {
            secret_id: DEFAULT_TEST_SECRET_ID,
            threshold: 2,
            replica_id: None,
        }
    }
}

impl Peer {
    pub fn new(client: SharedClient, label: &'static str, uri: &str) -> Self {
        Self::with_options(client, label, uri, PeerOptions::default())
    }

    pub fn with_secret_id(
        client: SharedClient,
        label: &'static str,
        uri: &str,
        secret_id: u64,
    ) -> Self {
        Self::with_options(
            client,
            label,
            uri,
            PeerOptions {
                secret_id,
                ..Default::default()
            },
        )
    }

    /// Construct a peer with the supplied per-flow auto-accept policy.
    /// Uses default `PeerOptions` for everything else.
    pub fn with_auto_accept(
        client: SharedClient,
        label: &'static str,
        uri: &str,
        policy: derec_library::protocol::AutoAcceptPolicy,
    ) -> Self {
        Self::with_full_options(client, label, uri, PeerOptions::default(), policy)
    }

    pub fn with_options(
        client: SharedClient,
        label: &'static str,
        uri: &str,
        options: PeerOptions,
    ) -> Self {
        Self::with_full_options(
            client,
            label,
            uri,
            options,
            derec_library::protocol::AutoAcceptPolicy::default(),
        )
    }

    fn with_full_options(
        client: SharedClient,
        label: &'static str,
        uri: &str,
        options: PeerOptions,
        auto_accept: derec_library::protocol::AutoAcceptPolicy,
    ) -> Self {
        let transport = InProcessTransport::new();
        let channel_store = PostgresChannelStore::new(client.clone());
        let share_store = PostgresShareStore::new(client.clone());
        let secret_store = PostgresSecretStore::new(client.clone());
        let user_secret_store = PostgresUserSecretStore::new(client);

        let mut builder = DeRecProtocolBuilder::new(options.secret_id)
            .with_channel_store(channel_store)
            .with_share_store(share_store)
            .with_secret_store(secret_store)
            .with_user_secret_store(user_secret_store)
            .with_transport(transport.clone())
            .with_state_store(PostgresInMemoryStateStore::default())
            .with_own_transport(uri)
            .with_threshold(options.threshold)
            .with_auto_accept(auto_accept);
        if let Some(rid) = options.replica_id {
            builder = builder.with_replica_id(rid);
        }
        let protocol = builder
            .build()
            .expect("test fixture: builder.build() should succeed");

        Self {
            label,
            uri: uri.to_owned(),
            protocol,
            transport,
        }
    }

    pub fn drain(&self) -> Vec<(TransportProtocol, Vec<u8>)> {
        self.transport.drain()
    }
}

pub async fn deliver(peer: &mut Peer, bytes: &[u8]) -> Vec<DeRecEvent> {
    let mut collected = peer
        .protocol
        .process(bytes)
        .await
        .unwrap_or_else(|e| panic!("[{}] process() failed: {e}", peer.label));

    let mut i = 0;
    while i < collected.len() {
        let action = match std::mem::replace(&mut collected[i], DeRecEvent::NoOp) {
            DeRecEvent::ActionRequired { action, .. } => Some(action),
            other => {
                collected[i] = other;
                None
            }
        };
        if let Some(action) = action {
            let mut accept_events = peer
                .protocol
                .accept(action)
                .await
                .unwrap_or_else(|e| panic!("[{}] accept() failed: {e}", peer.label));
            collected.append(&mut accept_events);
        }
        i += 1;
    }

    collected
}

pub async fn pump_many(peers: &mut [&mut Peer]) -> Vec<DeRecEvent> {
    let mut all_events = Vec::new();
    loop {
        let mut pending: Vec<(usize, Vec<u8>)> = Vec::new();
        for src in 0..peers.len() {
            for (tp, bytes) in peers[src].drain() {
                let dest = peers
                    .iter()
                    .position(|p| p.uri == tp.uri)
                    .unwrap_or_else(|| {
                        let known = peers
                            .iter()
                            .map(|p| p.uri.as_str())
                            .collect::<Vec<_>>()
                            .join(", ");
                        panic!("no peer for destination uri {} (have {known})", tp.uri)
                    });
                pending.push((dest, bytes));
            }
        }
        if pending.is_empty() {
            break;
        }
        for (dest, bytes) in pending {
            let mut events = deliver(peers[dest], &bytes).await;
            all_events.append(&mut events);
        }
    }
    all_events
}
