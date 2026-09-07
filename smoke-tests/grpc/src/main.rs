// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Three DeRec nodes — one owner and two helpers — talking to each other
//! over real gRPC sockets.
//!
//! Unlike the other smoke tests in this directory, this one exercises no
//! language binding. It is a reference implementation of the one thing
//! `derec-library` deliberately leaves to the application: moving envelope
//! bytes between peers.
//!
//! Every node runs a `DeRecTransport` gRPC server *and* dials its peers'.
//! `Send` returns `google.protobuf.Empty`, so a request carries no reply —
//! a responder answers by opening a fresh `Send` back to the requester's
//! advertised endpoint, correlated by the envelope's `traceId`.

mod transport;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use derec_library::protocol::types::{
    ChannelQuery, ChannelRecord, HelperChannel, ReplicaMember, Target, UserSecret, UserSecrets,
};
use derec_library::protocol::{
    ChannelStoreFuture, DeRecChannelStore, DeRecEvent, DeRecFlow, DeRecProtocol,
    DeRecProtocolBuilder, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecUserSecretStore,
    MissingPolicy, SecretKind, SecretStoreError, SecretStoreFuture, SecretValue, Share,
    ShareStoreFuture, StateItem, StateKey, StateKind, StateStoreFuture,
};
use derec_library::transport::TransportProtocol;
use derec_library::types::ChannelId;
use derec_proto::SenderKind;
use prost::Message as _;
use tokio::sync::{Mutex, mpsc};

use transport::GrpcTransport;
use transport::pb::de_rec_transport_server::{
    DeRecTransport as GrpcDelivery, DeRecTransportServer,
};

/// One `DeRecProtocol` instance manages exactly one secret, named by this
/// identifier. The owner protects it; the helpers hold shares of it. All
/// three nodes are constructed with the same value so their stores agree on
/// which secret the traffic is about.
const SECRET_ID: u64 = 0xDE_2EC;

/// Upper bound on how long any single phase may take before the run is
/// declared failed. Generous relative to loopback round-trips; it exists so
/// a stalled flow fails loudly instead of hanging.
const PHASE_TIMEOUT: Duration = Duration::from_secs(20);

const OWNER_ADDR: &str = "127.0.0.1:50051";
const HELPER_A_ADDR: &str = "127.0.0.1:50052";
const HELPER_B_ADDR: &str = "127.0.0.1:50053";

/// Why this run needs two helpers rather than one.
///
/// The trap is the silent clause, so take it first: **fewer than
/// `threshold` paired helpers means no split runs and nothing is stored,
/// and no error is raised.** `start(ProtectSecret)` returns `Ok`, the
/// helper is never contacted, and no `ShareStored` / `ShareConfirmed`
/// event ever arrives — the flow simply does nothing. The gate is
/// `helpers.len() >= threshold` in the library's sharing handler; the
/// `else` branch skips distribution entirely.
///
/// The loud clause is the one you meet first: `build()` rejects any
/// `threshold` below 2, because a lone helper who can reconstruct the
/// secret is not threshold sharing.
///
/// Together they force a floor of two paired helpers before a single share
/// moves. Setting `threshold = 2` and pairing one helper satisfies the
/// builder and still stores nothing.
const THRESHOLD: usize = 2;

// ---------------------------------------------------------------------------
// Stores
//
// Plain in-memory implementations of the six persistence traits the builder
// requires. They carry no gRPC-specific behaviour; a real application would
// swap them for durable ones.
// ---------------------------------------------------------------------------

#[derive(Default)]
struct InMemoryChannelStore {
    helper_rows: HashMap<(u64, u64), HelperChannel>,
    member_rows: HashMap<(u64, u64), ReplicaMember>,
    links: HashMap<(u64, u64), HashSet<u64>>,
}

impl DeRecChannelStore for InMemoryChannelStore {
    fn load(
        &self,
        secret_id: u64,
        query: ChannelQuery,
    ) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
        let result = match query {
            ChannelQuery::Helper { channel_id } => self
                .helper_rows
                .get(&(secret_id, channel_id.0))
                .cloned()
                .map(ChannelRecord::Helper),
            ChannelQuery::Replica { replica_id, .. } => self
                .member_rows
                .get(&(secret_id, replica_id.0))
                .cloned()
                .map(ChannelRecord::Replica),
        };
        Box::pin(std::future::ready(Ok(result)))
    }

    fn save(&mut self, secret_id: u64, record: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
        match record {
            ChannelRecord::Helper(h) => {
                self.helper_rows.insert((secret_id, h.channel_id.0), h);
            }
            ChannelRecord::Replica(r) => {
                self.member_rows.insert((secret_id, r.replica_id.0), r);
            }
        }
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(&mut self, secret_id: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
        let removed = match query {
            ChannelQuery::Helper { channel_id } => self
                .helper_rows
                .remove(&(secret_id, channel_id.0))
                .is_some(),
            ChannelQuery::Replica { replica_id, .. } => self
                .member_rows
                .remove(&(secret_id, replica_id.0))
                .is_some(),
        };
        Box::pin(std::future::ready(Ok(removed)))
    }

    fn helpers(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
        let entries: Vec<HelperChannel> = self
            .helper_rows
            .iter()
            .filter(|((s, _), _)| *s == secret_id)
            .map(|(_, c)| c.clone())
            .collect();
        Box::pin(std::future::ready(Ok(entries)))
    }

    fn replicas(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
        let entries: Vec<ReplicaMember> = self
            .member_rows
            .iter()
            .filter(|((s, _), _)| *s == secret_id)
            .map(|(_, m)| m.clone())
            .collect();
        Box::pin(std::future::ready(Ok(entries)))
    }

    fn link_channel(
        &mut self,
        secret_id: u64,
        a: ChannelId,
        b: ChannelId,
    ) -> ChannelStoreFuture<'_, ()> {
        let (a, b) = (a.0, b.0);
        if a != b {
            self.links.entry((secret_id, a)).or_default().insert(b);
            self.links.entry((secret_id, b)).or_default().insert(a);
        }
        Box::pin(std::future::ready(Ok(())))
    }

    fn linked_channels(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<u64> = VecDeque::new();
        queue.push_back(channel_id.0);

        while let Some(curr) = queue.pop_front() {
            if !visited.insert(curr) {
                continue;
            }
            if let Some(neighbors) = self.links.get(&(secret_id, curr)) {
                for &n in neighbors {
                    if !visited.contains(&n) {
                        queue.push_back(n);
                    }
                }
            }
        }

        let result: Vec<ChannelId> = visited.into_iter().map(ChannelId).collect();
        Box::pin(std::future::ready(Ok(result)))
    }
}

#[derive(Default)]
struct InMemorySecretStore {
    data: HashMap<(u64, u64, u8), SecretValue>,
}

impl DeRecSecretStore for InMemorySecretStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>> {
        let result = self
            .data
            .get(&(secret_id, channel_id.0, kind as u8))
            .map(clone_secret_value);
        Box::pin(std::future::ready(Ok(result)))
    }

    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        kind: SecretKind,
        missing_policy: MissingPolicy,
    ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
        let k = kind as u8;
        let mut result: Vec<(ChannelId, SecretValue)> = Vec::with_capacity(channel_ids.len());
        let mut missing: Vec<u64> = Vec::new();
        for cid in channel_ids {
            match self.data.get(&(secret_id, cid.0, k)) {
                Some(v) => result.push((*cid, clone_secret_value(v))),
                None => missing.push(cid.0),
            }
        }
        if missing_policy == MissingPolicy::Fail && !missing.is_empty() {
            return Box::pin(std::future::ready(Err(SecretStoreError::MissingEntries {
                kind,
                channel_ids: missing,
            })));
        }
        Box::pin(std::future::ready(Ok(result)))
    }

    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        value: SecretValue,
    ) -> SecretStoreFuture<'_, ()> {
        let kind = match &value {
            SecretValue::SharedKey(_) => SecretKind::SharedKey as u8,
            SecretValue::PairingSecret(_) => SecretKind::PairingSecret as u8,
            SecretValue::PairingContact(_) => SecretKind::PairingContact as u8,
        };
        self.data.insert((secret_id, channel_id.0, kind), value);
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, ()> {
        self.data.remove(&(secret_id, channel_id.0, kind as u8));
        Box::pin(std::future::ready(Ok(())))
    }
}

fn clone_secret_value(v: &SecretValue) -> SecretValue {
    match v {
        SecretValue::SharedKey(k) => SecretValue::SharedKey(*k),
        SecretValue::PairingSecret(p) => SecretValue::PairingSecret(p.clone()),
        SecretValue::PairingContact(c) => SecretValue::PairingContact(c.clone()),
    }
}

#[derive(Default)]
struct InMemoryShareStore {
    data: HashMap<(u64, u64, u32), Share>,
}

impl DeRecShareStore for InMemoryShareStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let cid = channel_id.0;
        let version_set: HashSet<u32> = versions.iter().copied().collect();
        let result: Vec<Share> = self
            .data
            .iter()
            .filter(|((c, s, v), _)| {
                *c == cid && *s == secret_id && (version_set.is_empty() || version_set.contains(v))
            })
            .map(|(_, s)| s.clone())
            .collect();
        Box::pin(std::future::ready(Ok(result)))
    }

    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let cid_set: HashSet<u64> = channel_ids.iter().map(|c| c.0).collect();
        let version_set: HashSet<u32> = versions.iter().copied().collect();
        let result: Vec<Share> = self
            .data
            .iter()
            .filter(|((c, s, v), _)| {
                cid_set.contains(c)
                    && *s == secret_id
                    && (version_set.is_empty() || version_set.contains(v))
            })
            .map(|(_, s)| s.clone())
            .collect();
        Box::pin(std::future::ready(Ok(result)))
    }

    fn load_all(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let cid_set: HashSet<u64> = channel_ids.iter().map(|c| c.0).collect();
        let result: Vec<Share> = self
            .data
            .iter()
            .filter(|((c, s, _), _)| cid_set.contains(c) && *s == secret_id)
            .map(|(_, share)| share.clone())
            .collect();
        Box::pin(std::future::ready(Ok(result)))
    }

    fn latest_version(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<u32>> {
        let max = self
            .data
            .keys()
            .filter(|(_, s, _)| *s == secret_id)
            .map(|(_, _, v)| *v)
            .max();
        Box::pin(std::future::ready(Ok(max)))
    }

    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        share: Share,
    ) -> ShareStoreFuture<'_, ()> {
        let _ = secret_id;
        let key = (channel_id.0, share.secret_id, share.version);
        self.data.insert(key, share);
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove_channel(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ShareStoreFuture<'_, ()> {
        let cid = channel_id.0;
        self.data
            .retain(|(c, s, _), _| !(*c == cid && *s == secret_id));
        Box::pin(std::future::ready(Ok(())))
    }
}

#[derive(Default)]
struct InMemoryUserSecretStore {
    data: HashMap<u64, UserSecrets>,
}

impl DeRecUserSecretStore for InMemoryUserSecretStore {
    fn load_latest(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
        let value = self.data.get(&secret_id).cloned();
        Box::pin(std::future::ready(Ok(value)))
    }

    fn save_latest(&mut self, secret_id: u64, value: UserSecrets) -> ShareStoreFuture<'_, ()> {
        self.data.insert(secret_id, value);
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(&mut self, secret_id: u64) -> ShareStoreFuture<'_, ()> {
        self.data.remove(&secret_id);
        Box::pin(std::future::ready(Ok(())))
    }
}

#[derive(Default)]
struct InMemoryStateStore {
    data: HashMap<(u64, StateKey), StateItem>,
}

impl DeRecStateStore for InMemoryStateStore {
    fn save(&mut self, secret_id: u64, item: StateItem) -> StateStoreFuture<'_, ()> {
        self.data.insert((secret_id, item.key()), item);
        Box::pin(std::future::ready(Ok(())))
    }

    fn load(&self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, Option<StateItem>> {
        let result = self.data.get(&(secret_id, key)).cloned();
        Box::pin(std::future::ready(Ok(result)))
    }

    fn remove(&mut self, secret_id: u64, key: StateKey) -> StateStoreFuture<'_, bool> {
        let removed = self.data.remove(&(secret_id, key)).is_some();
        Box::pin(std::future::ready(Ok(removed)))
    }

    fn load_all(&self, secret_id: u64, kind: StateKind) -> StateStoreFuture<'_, Vec<StateItem>> {
        let entries: Vec<StateItem> = self
            .data
            .iter()
            .filter(|((s, k), _)| *s == secret_id && k.kind() == kind)
            .map(|(_, item)| item.clone())
            .collect();
        Box::pin(std::future::ready(Ok(entries)))
    }
}

type GrpcProtocol = DeRecProtocol<
    InMemoryChannelStore,
    InMemoryShareStore,
    InMemorySecretStore,
    InMemoryUserSecretStore,
    InMemoryStateStore,
    GrpcTransport,
>;

// ---------------------------------------------------------------------------
// Node: one protocol instance, one inbound queue, one server, one worker
// ---------------------------------------------------------------------------

/// An observed event tagged with the node that emitted it.
type TaggedEvent = (&'static str, DeRecEvent);

/// Server half of the transport.
///
/// The handler queues the envelope and returns immediately. Processing it
/// inline would deadlock: this node's protocol lock would still be held
/// while the peer, inside the very call it is waiting on, opened its own
/// `Send` back to this node to deliver the response. `Send` returning
/// `Empty` is what makes deferring correct — the caller is being told the
/// envelope was accepted, not that it was acted upon.
struct InboundService {
    inbox: mpsc::UnboundedSender<Vec<u8>>,
}

#[tonic::async_trait]
impl GrpcDelivery for InboundService {
    async fn send(
        &self,
        request: tonic::Request<derec_proto::DeRecMessage>,
    ) -> Result<tonic::Response<()>, tonic::Status> {
        let envelope = request.into_inner();
        self.inbox
            .send(envelope.encode_to_vec())
            .map_err(|_| tonic::Status::unavailable("node is shutting down"))?;
        Ok(tonic::Response::new(()))
    }
}

struct Node {
    label: &'static str,
    uri: String,
    protocol: Arc<Mutex<GrpcProtocol>>,
}

impl Node {
    /// Build a node, bind its server, and start the task that drains its
    /// inbound queue.
    ///
    /// `unserved_https_offer`, when set, makes this node advertise an
    /// additional `https://` endpoint via `with_own_transports` — listed
    /// *before* its real gRPC endpoint, and never actually served (this
    /// function still binds only a gRPC listener below). Pairing must still
    /// complete over gRPC, because the peer's own preference order decides
    /// which offered endpoint is used, not the order this node wrote them
    /// in.
    async fn start(
        label: &'static str,
        addr: &'static str,
        threshold: usize,
        events: mpsc::UnboundedSender<TaggedEvent>,
        unserved_https_offer: Option<&str>,
    ) -> Self {
        let uri = format!("grpc://{addr}");
        let served = TransportProtocol::new(uri.clone(), derec_proto::Protocol::Grpc);

        // `with_unsafe_connection(true)` is mandatory here, loopback or not.
        // `TransportPolicy::check_own` exempts a node's *own* loopback
        // endpoint from the plaintext ban, but `check_peer` has no such
        // exemption — and each node receives the other's `grpc://127.0.0.1:…`
        // as a peer endpoint during pairing. Without the opt-in, pairing
        // fails with `PlaintextRefused`.
        let builder = DeRecProtocolBuilder::new(SECRET_ID)
            .with_channel_store(InMemoryChannelStore::default())
            .with_share_store(InMemoryShareStore::default())
            .with_secret_store(InMemorySecretStore::default())
            .with_user_secret_store(InMemoryUserSecretStore::default())
            .with_state_store(InMemoryStateStore::default())
            .with_transport(GrpcTransport);

        let builder = match unserved_https_offer {
            Some(https_uri) => builder.with_own_transports([
                TransportProtocol::new(https_uri.to_owned(), derec_proto::Protocol::Https),
                served,
            ]),
            None => builder.with_own_transport(served),
        };

        let protocol = builder
            .with_threshold(threshold)
            .with_unsafe_connection(true)
            .build()
            .unwrap_or_else(|e| panic!("[{label}] builder.build() failed: {e}"));

        let protocol = Arc::new(Mutex::new(protocol));
        let (inbox_tx, inbox_rx) = mpsc::unbounded_channel::<Vec<u8>>();

        let socket = addr
            .parse()
            .unwrap_or_else(|e| panic!("[{label}] bad listen address {addr}: {e}"));
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(DeRecTransportServer::new(InboundService {
                    inbox: inbox_tx,
                }))
                .serve(socket)
                .await
                .unwrap_or_else(|e| panic!("[{label}] gRPC server on {addr} failed: {e}"));
        });

        tokio::spawn(drain_inbox(label, protocol.clone(), inbox_rx, events));

        await_listening(label, addr).await;
        println!("[{label}] listening on {uri}");

        Self {
            label,
            uri,
            protocol,
        }
    }
}

/// Poll the listener until it accepts a connection, so the first protocol
/// message is not dispatched into a socket that has not been bound yet.
async fn await_listening(label: &str, addr: &str) {
    for _ in 0..100 {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("[{label}] gRPC server never came up on {addr}");
}

/// Feed queued envelopes to `process`, auto-accept whatever the protocol
/// asks the application to decide, and publish the resulting events.
///
/// Responses produced here leave over a fresh outbound `Send`; nothing is
/// returned to the peer that delivered the request.
async fn drain_inbox(
    label: &'static str,
    protocol: Arc<Mutex<GrpcProtocol>>,
    mut inbox: mpsc::UnboundedReceiver<Vec<u8>>,
    events: mpsc::UnboundedSender<TaggedEvent>,
) {
    while let Some(bytes) = inbox.recv().await {
        let mut guard = protocol.lock().await;
        let produced = match guard.process(&bytes).await {
            Ok(produced) => produced,
            Err(e) => panic!("[{label}] process() failed: {e}"),
        };
        let produced = accept_pending(label, &mut guard, produced).await;
        drop(guard);

        for event in produced {
            if events.send((label, event)).is_err() {
                return;
            }
        }
    }
}

/// Satisfy every `ActionRequired` the protocol raised, appending whatever
/// each `accept` produces. An application would surface these to a user;
/// the smoke test accepts unconditionally.
async fn accept_pending(
    label: &str,
    protocol: &mut GrpcProtocol,
    mut events: Vec<DeRecEvent>,
) -> Vec<DeRecEvent> {
    let mut i = 0;
    while i < events.len() {
        let action = match std::mem::replace(&mut events[i], DeRecEvent::NoOp) {
            DeRecEvent::ActionRequired { action, .. } => Some(action),
            other => {
                events[i] = other;
                None
            }
        };
        if let Some(action) = action {
            let mut accepted = protocol
                .accept(action)
                .await
                .unwrap_or_else(|e| panic!("[{label}] accept() failed: {e}"));
            events.append(&mut accepted);
        }
        i += 1;
    }
    events
}

// ---------------------------------------------------------------------------
// Event bus
// ---------------------------------------------------------------------------

/// Collects events from all nodes so a phase can block until the network
/// has produced what it was supposed to.
///
/// This is the shape a push-only transport forces on a driver: there is no
/// call to await a reply on, so progress is observed through events rather
/// than return values.
struct Bus {
    rx: mpsc::UnboundedReceiver<TaggedEvent>,
    seen: Vec<TaggedEvent>,
}

impl Bus {
    /// Block until at least `count` collected events satisfy `matches`,
    /// then return references to them. Panics on timeout.
    async fn wait_for(
        &mut self,
        what: &str,
        count: usize,
        matches: impl Fn(&DeRecEvent) -> bool,
    ) -> Vec<&TaggedEvent> {
        let deadline = tokio::time::Instant::now() + PHASE_TIMEOUT;
        loop {
            let hits = self.seen.iter().filter(|(_, e)| matches(e)).count();
            if hits >= count {
                break;
            }
            match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                Ok(Some(tagged)) => self.seen.push(tagged),
                Ok(None) => panic!("event bus closed while waiting for {count}x {what}"),
                Err(_) => panic!(
                    "timed out after {PHASE_TIMEOUT:?} waiting for {count}x {what} (saw {hits})"
                ),
            }
        }
        self.seen
            .iter()
            .filter(|(_, e)| matches(e))
            .collect::<Vec<_>>()
    }

    /// Drop everything collected so far, so the next phase counts only its
    /// own events.
    fn reset(&mut self) {
        self.seen.clear();
    }
}

/// Assert that `sources` holds `expected` distinct values.
///
/// Counting events is not enough to show a fan-out reached every peer: two
/// events of the right shape can both come from one node, or both describe
/// one channel, while the other peer contributed nothing. The discriminator
/// differs by event — the emitting node for events raised on the receiving
/// side, the `channel_id` for events the owner raises once per peer — so
/// the caller picks it.
fn assert_distinct<K: std::fmt::Debug + Eq + std::hash::Hash>(
    what: &str,
    sources: Vec<K>,
    expected: usize,
) {
    let distinct = sources.iter().collect::<HashSet<_>>().len();
    assert_eq!(
        distinct, expected,
        "expected {expected} {what} from distinct sources, got {sources:?}"
    );
}

// ---------------------------------------------------------------------------
// Flow
// ---------------------------------------------------------------------------

#[tokio::main]
async fn main() {
    println!("── DeRec over gRPC ─────────────────────────────────────────");

    let (tx, rx) = mpsc::unbounded_channel::<TaggedEvent>();
    let mut bus = Bus {
        rx,
        seen: Vec::new(),
    };

    // The owner advertises both transports it could speak, https first,
    // while this run only ever serves gRPC for it (see `Node::start`). Both
    // helpers pair against it successfully anyway, over gRPC — proof that
    // selection is driven by each helper's own served-transport preference,
    // not by the order the owner listed its offers in.
    let owner = Node::start(
        "owner",
        OWNER_ADDR,
        THRESHOLD,
        tx.clone(),
        Some("https://owner.example.com/derec"),
    )
    .await;
    let helper_a = Node::start("helper-a", HELPER_A_ADDR, THRESHOLD, tx.clone(), None).await;
    let helper_b = Node::start("helper-b", HELPER_B_ADDR, THRESHOLD, tx, None).await;

    let channel_a = pair(&owner, &helper_a, ChannelId(1), &mut bus).await;
    let channel_b = pair(&owner, &helper_b, ChannelId(2), &mut bus).await;
    let version = protect_secret(&owner, &mut bus).await;
    verify_shares(&owner, &mut bus, version).await;

    println!("── All gRPC transport phases passed ────────────────────────");
    println!(
        "{} paired with {} on {channel_a:?} and {} on {channel_b:?}; \
         share v{version} stored and verified on both",
        owner.uri, helper_a.uri, helper_b.uri
    );
}

/// Pairing: the owner mints a contact, the helper starts the handshake
/// against it, and every subsequent leg travels over the wire on its own.
async fn pair(
    owner: &Node,
    helper: &Node,
    pairing_channel_id: ChannelId,
    bus: &mut Bus,
) -> ChannelId {
    println!(
        "[pair] owner mints a contact; {} opens the handshake",
        helper.label
    );

    let contact = owner
        .protocol
        .lock()
        .await
        .create_contact(
            Some(pairing_channel_id),
            derec_proto::ContactMode::InlineKeys,
            None,
        )
        .await
        .expect("owner.create_contact failed");

    helper
        .protocol
        .lock()
        .await
        .start(DeRecFlow::Pairing {
            kind: SenderKind::Helper,
            contact,
            peer_communication_info: HashMap::from([("name".to_owned(), helper.label.to_owned())]),
        })
        .await
        .expect("helper start(Pairing) failed");

    let completed = bus
        .wait_for("PairingCompleted", 2, |e| {
            matches!(e, DeRecEvent::PairingCompleted { .. })
        })
        .await;

    // One completion per end of the channel. Both events landing on the
    // same node would mean one side never finished, so the emitters must
    // be distinct before their agreement on the channel_id means anything.
    let completions: Vec<(&'static str, ChannelId)> = completed
        .iter()
        .filter_map(|(label, e)| match e {
            DeRecEvent::PairingCompleted { channel_id, .. } => Some((*label, *channel_id)),
            _ => None,
        })
        .collect();
    assert_distinct(
        "PairingCompleted",
        completions.iter().map(|(label, _)| *label).collect(),
        2,
    );

    let channel_ids: Vec<ChannelId> = completions.iter().map(|(_, cid)| *cid).collect();
    assert!(
        channel_ids.windows(2).all(|w| w[0] == w[1]),
        "both ends must rotate to the same long-term channel_id, got {channel_ids:?}"
    );
    let channel_id = channel_ids[0];
    assert_ne!(
        channel_id, pairing_channel_id,
        "the long-term channel_id must differ from the transient pairing id"
    );

    let owner_fp = owner
        .protocol
        .lock()
        .await
        .get_fingerprint(channel_id)
        .await
        .expect("owner get_fingerprint failed");
    let helper_fp = helper
        .protocol
        .lock()
        .await
        .get_fingerprint(channel_id)
        .await
        .expect("helper get_fingerprint failed");
    assert_eq!(
        owner_fp, helper_fp,
        "fingerprints must match across both ends of the channel"
    );

    println!("[pair] {} and {} paired ✓", owner.label, helper.label);
    bus.reset();
    channel_id
}

/// Distribution: the owner splits a secret and pushes one share to each
/// helper; each helper stores its share and pushes a confirmation back on
/// its own connection.
async fn protect_secret(owner: &Node, bus: &mut Bus) -> u32 {
    println!("[protect] owner distributes a secret");

    owner
        .protocol
        .lock()
        .await
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![UserSecret {
                id: vec![1, 2, 3],
                name: "grpc smoke-test secret".to_owned(),
                data: b"super-secret-value".to_vec(),
            }],
            description: Some("grpc smoke-test distribution".to_owned()),
        })
        .await
        .expect("owner start(ProtectSecret) failed");

    // `ShareStored` is raised on the helper that did the storing, so the
    // emitting node is what distinguishes the two.
    let stored_by: Vec<&'static str> = bus
        .wait_for("ShareStored", 2, |e| {
            matches!(e, DeRecEvent::ShareStored { .. })
        })
        .await
        .iter()
        .map(|(label, _)| *label)
        .collect();
    assert_distinct("ShareStored", stored_by, 2);

    // `ShareConfirmed`, by contrast, is raised on the *owner* — once per
    // helper that answered. Both events carry the same label, so the
    // channel is what separates them.
    let confirmed: Vec<(ChannelId, u32)> = bus
        .wait_for("ShareConfirmed", 2, |e| {
            matches!(e, DeRecEvent::ShareConfirmed { .. })
        })
        .await
        .iter()
        .filter_map(|(_, e)| match e {
            DeRecEvent::ShareConfirmed {
                channel_id,
                version,
            } => Some((*channel_id, *version)),
            _ => None,
        })
        .collect();
    assert_distinct(
        "ShareConfirmed",
        confirmed.iter().map(|(cid, _)| *cid).collect(),
        2,
    );

    let version = confirmed
        .first()
        .expect("ShareConfirmed carries the stored version")
        .1;
    assert!(
        confirmed.iter().all(|(_, v)| *v == version),
        "both helpers must confirm the same version, got {confirmed:?}"
    );

    println!("[protect] share v{version} stored and confirmed by both helpers ✓");
    bus.reset();
    version
}

/// Verification: the owner challenges each helper to prove it still holds
/// its share. Every proof arrives as a fresh inbound `Send`, matched to the
/// outstanding challenge by the envelope's traceId.
async fn verify_shares(owner: &Node, bus: &mut Bus, version: u32) {
    println!("[verify] owner challenges both helpers for share v{version}");

    let secret_id = owner.protocol.lock().await.secret_id();
    owner
        .protocol
        .lock()
        .await
        .start(DeRecFlow::VerifyShares {
            secret_id,
            version,
            target: Target::All,
        })
        .await
        .expect("owner start(VerifyShares) failed");

    // Like `ShareConfirmed`, this is raised on the challenger once per
    // proof received, so distinctness is per channel rather than per node.
    let verified: Vec<(ChannelId, u32)> = bus
        .wait_for("ShareVerified", 2, |e| {
            matches!(e, DeRecEvent::ShareVerified { .. })
        })
        .await
        .iter()
        .filter_map(|(_, e)| match e {
            DeRecEvent::ShareVerified {
                channel_id,
                version,
            } => Some((*channel_id, *version)),
            _ => None,
        })
        .collect();
    assert_distinct(
        "ShareVerified",
        verified.iter().map(|(cid, _)| *cid).collect(),
        2,
    );
    assert!(
        verified.iter().all(|(_, v)| *v == version),
        "every ShareVerified must name the challenged version, got {verified:?}"
    );

    println!("[verify] both helpers proved possession of v{version} ✓");
    bus.reset();
}
