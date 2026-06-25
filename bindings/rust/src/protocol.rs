//! Protocol-level smoke test for the `DeRecProtocol` orchestrator.
//!
//! Mirrors the current store/transport trait API used by the reference-app
//! backend (`apps/backend/src/stores.rs`). Instead of an HTTP transport, an
//! in-process transport routes encoded bytes between two protocol instances
//! by their advertised transport URI. Each flow is driven by
//! `protocol.start(...)`, transported bytes are fed to the peer's
//! `protocol.process(...)`, and every `ActionRequired` event is satisfied via
//! `protocol.accept(...)` (mirroring the backend actor's auto-accept).
//!
//! Coverage preserved in spirit from the legacy smoke test:
//! pairing -> sharing -> discovery + recovery. Recovery is exercised by
//! re-pairing on a fresh channel and linking it to the original channel via
//! `channel_store.link_channel` (the post-refactor replacement for the old
//! copy-shares approach).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};

use derec_library::protocol::{
    ChannelStoreFuture, DeRecChannelStore, DeRecEvent, DeRecFlow, DeRecProtocol,
    DeRecProtocolBuilder, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    DeRecUserSecretStore, MissingPolicy, SecretKind, SecretStoreError, SecretStoreFuture,
    SecretValue, Share, ShareStoreFuture, TransportFuture,
};
use derec_library::protocol::types::{Channel, Target, UserSecret, UserSecrets};
use derec_library::types::ChannelId;
use derec_proto::{Protocol, SenderKind, TransportProtocol};

/// Default secret identifier wired into every `Peer` constructor that
/// doesn't request a specific one. Tests that exercise multiple secrets
/// override it explicitly via [`Peer::with_options`].
const DEFAULT_TEST_SECRET_ID: u64 = 0xDE_2EC;

pub async fn run_all() {
    run_pairing_flow().await;
    run_hashed_keys_pairing_flow().await;
    run_replica_id_wiring_flow().await;
    run_protect_secret_with_replica_targets_flow().await;
    run_sharing_flow().await;
    run_discovery_and_recovery_flow().await;
    run_unpairing_flow().await;
    run_update_channel_info_flow().await;
    run_reply_to_flow().await;
    run_auto_publish_on_pair_flow().await;
    run_replica_sync_version_progression_flow().await;
    run_replica_group_key_handover_flow().await;
    run_auto_accept_flow().await;
    run_start_pairing_rejects_already_paired_channel().await;
}


/// Stores paired channels plus the channel-link graph (channels belonging to
/// the same Owner identity, e.g. after a recovery re-pairing). The link graph
/// is a bidirectional adjacency list; `linked_channels` is a BFS over it.
#[derive(Default)]
struct InMemoryChannelStore {
    data: HashMap<(u64, u64), Channel>,
    links: HashMap<(u64, u64), HashSet<u64>>,
}

impl DeRecChannelStore for InMemoryChannelStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, Option<Channel>> {
        let result = self.data.get(&(secret_id, channel_id.0)).cloned();
        Box::pin(std::future::ready(Ok(result)))
    }

    fn save(&mut self, secret_id: u64, channel: Channel) -> ChannelStoreFuture<'_, ()> {
        self.data.insert((secret_id, channel.id.0), channel);
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ChannelStoreFuture<'_, bool> {
        let removed = self.data.remove(&(secret_id, channel_id.0)).is_some();
        Box::pin(std::future::ready(Ok(removed)))
    }

    fn channels(&self, secret_id: u64) -> ChannelStoreFuture<'_, Vec<Channel>> {
        let entries: Vec<Channel> = self
            .data
            .iter()
            .filter(|((s, _), _)| *s == secret_id)
            .map(|(_, c)| c.clone())
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


/// Stores shares keyed by `(channel_id, secret_id, version)`. Pure keyed
/// store — channel linking lives in [`InMemoryChannelStore`]; `load_many`
/// is fed the resolved channel set by the recovery handler (and `load_all`
/// by the discovery handler).
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
        let result: Vec<Share> = if versions.is_empty() {
            self.data
                .iter()
                .filter(|((c, s, _), _)| *c == cid && *s == secret_id)
                .map(|(_, s)| s.clone())
                .collect()
        } else {
            let version_set: HashSet<u32> = versions.iter().copied().collect();
            self.data
                .iter()
                .filter(|((c, s, v), _)| {
                    *c == cid && *s == secret_id && version_set.contains(v)
                })
                .map(|(_, s)| s.clone())
                .collect()
        };
        Box::pin(std::future::ready(Ok(result)))
    }

    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let cid_set: HashSet<u64> = channel_ids.iter().map(|c| c.0).collect();
        let result: Vec<Share> = if versions.is_empty() {
            self.data
                .iter()
                .filter(|((c, s, _), _)| cid_set.contains(c) && *s == secret_id)
                .map(|(_, s)| s.clone())
                .collect()
        } else {
            let version_set: HashSet<u32> = versions.iter().copied().collect();
            self.data
                .iter()
                .filter(|((c, s, v), _)| {
                    cid_set.contains(c) && *s == secret_id && version_set.contains(v)
                })
                .map(|(_, s)| s.clone())
                .collect()
        };
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


/// Per-`secret_id` snapshot of the most recent `start(ProtectSecret)`
/// bag. Holds at most one entry per id; `save_latest` overwrites.
#[derive(Default)]
struct InMemoryUserSecretStore {
    data: HashMap<u64, UserSecrets>,
}

impl DeRecUserSecretStore for InMemoryUserSecretStore {
    fn load_latest(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
        let value = self.data.get(&secret_id).cloned();
        Box::pin(std::future::ready(Ok(value)))
    }

    fn save_latest(
        &mut self,
        secret_id: u64,
        value: UserSecrets,
    ) -> ShareStoreFuture<'_, ()> {
        self.data.insert(secret_id, value);
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(&mut self, secret_id: u64) -> ShareStoreFuture<'_, ()> {
        self.data.remove(&secret_id);
        Box::pin(std::future::ready(Ok(())))
    }
}


/// Buffers outbound `(endpoint, bytes)` instead of performing network I/O.
/// `drain()` retrieves and clears the pending messages. The buffer is shared
/// via `Arc<Mutex<..>>` so the driver can drain it while the protocol instance
/// retains a clone.
#[derive(Clone, Default)]
struct InProcessTransport {
    outbox: Arc<Mutex<VecDeque<(TransportProtocol, Vec<u8>)>>>,
}

impl InProcessTransport {
    fn new() -> Self {
        Self::default()
    }

    fn drain(&self) -> Vec<(TransportProtocol, Vec<u8>)> {
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


type SmokeProtocol = DeRecProtocol<
    InMemoryChannelStore,
    InMemoryShareStore,
    InMemorySecretStore,
    InMemoryUserSecretStore,
    InProcessTransport,
>;

/// A protocol instance plus the metadata needed to route messages to it: its
/// own advertised transport URI and a handle to drain its outbox.
struct Peer {
    label: &'static str,
    uri: String,
    protocol: SmokeProtocol,
    transport: InProcessTransport,
}

impl Peer {
    /// Build a peer with the default threshold (`2`). Use
    /// [`Peer::with_threshold`] for single-helper scenarios where the Owner's
    /// `ProtectSecret` would otherwise fail with `InvalidThreshold`.
    fn new(label: &'static str, uri: &str) -> Self {
        Self::with_threshold(label, uri, 2)
    }

    fn with_threshold(label: &'static str, uri: &str, threshold: usize) -> Self {
        Self::with_options(label, uri, threshold, false, None, DEFAULT_TEST_SECRET_ID)
    }

    /// Same as [`Peer::new`] but flips `with_auto_reply_to(true)` on the
    /// builder so every outbound request stamps `replyTo = own_transport`.
    fn with_auto_reply_to(label: &'static str, uri: &str) -> Self {
        Self::with_options(label, uri, 2, true, None, DEFAULT_TEST_SECRET_ID)
    }

    /// Configure a per-flow auto-accept policy on the builder. The
    /// orchestrator will internally accept any inbound action whose
    /// flow the policy opts into and emit `AutoAccepted` in place of
    /// `ActionRequired`.
    fn with_auto_accept(
        label: &'static str,
        uri: &str,
        policy: derec_library::protocol::AutoAcceptPolicy,
    ) -> Self {
        Self::with_full_options(
            label,
            uri,
            2,
            false,
            None,
            DEFAULT_TEST_SECRET_ID,
            policy,
        )
    }

    /// Configure a local `replica_id`, enabling this peer to participate in
    /// replica-mode pairings. The id is generated fresh per peer; pass
    /// `Some(id)` from the caller side if you need two peers to share the
    /// same value (e.g. testing peer-identity round-trip).
    fn with_replica_id(label: &'static str, uri: &str, replica_id: u64) -> Self {
        Self::with_options(
            label,
            uri,
            2,
            false,
            Some(replica_id),
            DEFAULT_TEST_SECRET_ID,
        )
    }

    /// Pin a specific `secret_id` on the builder. Used by tests that
    /// assert the wire `secret_id` against a known value (e.g. recovery
    /// scenarios where the discovered secret_id must match what the owner
    /// originally published).
    fn with_secret_id(label: &'static str, uri: &str, secret_id: u64) -> Self {
        Self::with_options(label, uri, 2, false, None, secret_id)
    }

    /// Pin both `secret_id` and `replica_id` on the builder.
    fn with_secret_id_and_replica_id(
        label: &'static str,
        uri: &str,
        secret_id: u64,
        replica_id: u64,
    ) -> Self {
        Self::with_options(label, uri, 2, false, Some(replica_id), secret_id)
    }

    fn with_options(
        label: &'static str,
        uri: &str,
        threshold: usize,
        auto_reply_to: bool,
        replica_id: Option<u64>,
        secret_id: u64,
    ) -> Self {
        Self::with_full_options(
            label,
            uri,
            threshold,
            auto_reply_to,
            replica_id,
            secret_id,
            derec_library::protocol::AutoAcceptPolicy::default(),
        )
    }

    fn with_full_options(
        label: &'static str,
        uri: &str,
        threshold: usize,
        auto_reply_to: bool,
        replica_id: Option<u64>,
        secret_id: u64,
        auto_accept: derec_library::protocol::AutoAcceptPolicy,
    ) -> Self {
        let transport = InProcessTransport::new();
        let mut builder = DeRecProtocolBuilder::new(secret_id)
            .with_channel_store(InMemoryChannelStore::default())
            .with_share_store(InMemoryShareStore::default())
            .with_secret_store(InMemorySecretStore::default())
            .with_user_secret_store(InMemoryUserSecretStore::default())
            .with_transport(transport.clone())
            .with_own_transport(uri)
            .with_threshold(threshold)
            .with_auto_reply_to(auto_reply_to)
            .with_auto_accept(auto_accept);
        if let Some(id) = replica_id {
            builder = builder.with_replica_id(id);
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

    fn drain(&self) -> Vec<(TransportProtocol, Vec<u8>)> {
        self.transport.drain()
    }
}

/// Feed `bytes` to `peer.process`, then satisfy every emitted
/// `ActionRequired` via `peer.accept` (mirroring the backend actor's
/// auto-accept). Returns all events produced by `process` and the subsequent
/// `accept` calls so callers can assert on them.
async fn deliver(peer: &mut Peer, bytes: &[u8]) -> Vec<DeRecEvent> {
    let mut collected = peer
        .protocol
        .process(bytes)
        .await
        .unwrap_or_else(|e| panic!("[{}] process() failed: {e}", peer.label));

    let mut i = 0;
    while i < collected.len() {
        // Take ownership of any pending action by swapping in a NoOp.
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

/// Drain `from`'s outbox and deliver each message to whichever peer's own URI
/// matches the destination endpoint, recursively transporting any responses
/// until the network is quiescent. Returns the events observed on the *other*
/// side for the first hop so the caller can assert on protocol progress.
async fn pump(from: &mut Peer, to: &mut Peer) -> Vec<DeRecEvent> {
    let mut all_events = Vec::new();
    let mut pending: VecDeque<(String, Vec<u8>)> = from
        .drain()
        .into_iter()
        .map(|(tp, bytes)| (tp.uri, bytes))
        .collect();

    while let Some((dest_uri, bytes)) = pending.pop_front() {
        let target: &mut Peer = if dest_uri == to.uri {
            &mut *to
        } else if dest_uri == from.uri {
            &mut *from
        } else {
            panic!(
                "no peer for destination uri {dest_uri} (have {} / {})",
                from.uri, to.uri
            );
        };

        let mut events = deliver(target, &bytes).await;
        // Any replies the target just queued must continue to be routed.
        for (tp, reply) in target.drain() {
            pending.push_back((tp.uri, reply));
        }
        all_events.append(&mut events);
    }

    all_events
}

/// Multi-peer variant of [`pump`] for flows that fan out to more than two
/// participants in a single round (e.g. an Owner sending `StoreShareRequest`
/// to several helpers at once). Drains every peer's outbox, dispatches each
/// message to the peer whose URI matches the destination, and repeats until
/// the network is quiescent.
async fn pump_many(peers: &mut [&mut Peer]) -> Vec<DeRecEvent> {
    let mut all_events = Vec::new();

    loop {
        // Collect a snapshot of every pending message across all peers. Doing
        // this in a single pass (rather than interleaving drains and delivers)
        // sidesteps borrow conflicts on the peer slice.
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
                        panic!(
                            "no peer for destination uri {} (peers: {})",
                            tp.uri, known
                        )
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


/// Drive a full pairing handshake: Owner creates a contact, Helper starts
/// pairing from it, and bytes are pumped both ways until both sides report
/// `PairingCompleted`.
async fn pair(owner: &mut Peer, helper: &mut Peer, channel_id: ChannelId) {
    let contact = owner
        .protocol
        .create_contact(Some(channel_id), derec_proto::ContactMode::InlineKeys)
        .await
        .expect("owner.create_contact failed");

    helper
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::Helper,
            contact,
            peer_communication_info: std::collections::HashMap::from([(
                "name".to_owned(),
                "helper".to_owned(),
            )]),
        })
        .await
        .expect("helper start(Pairing) failed");

    // Helper -> Owner (PairRequest), Owner -> Helper (PairResponse), etc.
    let helper_to_owner = pump(helper, owner).await;
    assert!(
        helper_to_owner
            .iter()
            .any(|e| matches!(e, DeRecEvent::PairingCompleted { .. })),
        "expected PairingCompleted while pumping helper->owner"
    );

    // Owner may still have the PairResponse queued; flush it to the helper.
    let owner_to_helper = pump(owner, helper).await;
    let pairing_completed = helper_to_owner
        .iter()
        .chain(owner_to_helper.iter())
        .filter(|e| matches!(e, DeRecEvent::PairingCompleted { .. }))
        .count();
    assert!(
        pairing_completed >= 2,
        "expected PairingCompleted on both sides (got {pairing_completed})"
    );
}

async fn run_pairing_flow() {
    println!("=== Protocol pairing flow test ===");

    let channel_id = ChannelId(1);
    let mut owner = Peer::new("owner", "https://owner.example.com");
    let mut helper = Peer::new("helper", "https://helper.example.com");

    pair(&mut owner, &mut helper, channel_id).await;

    let owner_sid = owner.protocol.secret_id();
    let helper_sid = helper.protocol.secret_id();
    let owner_channel = owner
        .protocol
        .channel_store
        .load(owner_sid, channel_id)
        .await
        .expect("owner channel_store.load failed");
    let helper_channel = helper
        .protocol
        .channel_store
        .load(helper_sid, channel_id)
        .await
        .expect("helper channel_store.load failed");
    assert!(
        owner_channel.is_some(),
        "owner must have a paired channel after pairing"
    );
    assert!(
        helper_channel.is_some(),
        "helper must have a paired channel after pairing"
    );

    // Both parties must derive the same fingerprint from the shared key.
    let owner_fp = owner
        .protocol
        .get_fingerprint(channel_id)
        .await
        .expect("owner get_fingerprint failed");
    let helper_fp = helper
        .protocol
        .get_fingerprint(channel_id)
        .await
        .expect("helper get_fingerprint failed");
    assert_eq!(
        owner_fp, helper_fp,
        "owner and helper fingerprints must match"
    );

    println!("Protocol pairing flow test passed.");
}


/// Drive a full HashedKeys pairing handshake: Owner creates a HashedKeys
/// contact (binding hash only, no inline public keys), Helper kicks off the
/// PrePair leg, Owner publishes its real keys via `accept_pre_pair`, Helper
/// validates the hash and auto-proceeds to a regular `PairRequest`, then
/// both sides reach `PairingCompleted`. The whole multi-leg chain drains
/// through a single `pump` call.
async fn pair_hashed_keys(owner: &mut Peer, helper: &mut Peer, channel_id: ChannelId) {
    let contact = owner
        .protocol
        .create_contact(Some(channel_id), derec_proto::ContactMode::HashedKeys)
        .await
        .expect("owner.create_contact(HashedKeys) failed");

    assert!(
        contact.contact_binding_hash.is_some(),
        "HashedKeys contact must carry a binding hash"
    );
    assert!(
        contact.mlkem_encapsulation_key.is_none() && contact.ecies_public_key.is_none(),
        "HashedKeys contact must NOT carry inline public keys"
    );

    helper
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::Helper,
            contact,
            peer_communication_info: std::collections::HashMap::from([(
                "name".to_owned(),
                "helper".to_owned(),
            )]),
        })
        .await
        .expect("helper start(Pairing) failed");

    // pump's loop chains PrePairRequest -> PrePairResponse -> PairRequest
    // -> PairResponse in a single drain pass since each hop pushes the
    // next message back into the queue.
    let events = pump(helper, owner).await;

    assert!(
        !events
            .iter()
            .any(|e| matches!(e, DeRecEvent::PrePairRejected { .. })),
        "happy path must not emit PrePairRejected"
    );

    let pairing_completed = events
        .iter()
        .filter(|e| matches!(e, DeRecEvent::PairingCompleted { .. }))
        .count();
    assert!(
        pairing_completed >= 2,
        "expected PairingCompleted on both sides (got {pairing_completed})"
    );
}

async fn run_hashed_keys_pairing_flow() {
    println!("=== Protocol HashedKeys pairing flow test ===");

    let channel_id = ChannelId(1);
    let mut owner = Peer::new("owner", "https://owner.example.com");
    let mut helper = Peer::new("helper", "https://helper.example.com");

    pair_hashed_keys(&mut owner, &mut helper, channel_id).await;

    let owner_sid = owner.protocol.secret_id();
    let helper_sid = helper.protocol.secret_id();
    let owner_channel = owner
        .protocol
        .channel_store
        .load(owner_sid, channel_id)
        .await
        .expect("owner channel_store.load failed");
    let helper_channel = helper
        .protocol
        .channel_store
        .load(helper_sid, channel_id)
        .await
        .expect("helper channel_store.load failed");
    assert!(
        owner_channel.is_some(),
        "owner must have a paired channel after HashedKeys pairing"
    );
    assert!(
        helper_channel.is_some(),
        "helper must have a paired channel after HashedKeys pairing"
    );

    let owner_fp = owner
        .protocol
        .get_fingerprint(channel_id)
        .await
        .expect("owner get_fingerprint failed");
    let helper_fp = helper
        .protocol
        .get_fingerprint(channel_id)
        .await
        .expect("helper get_fingerprint failed");
    assert_eq!(
        owner_fp, helper_fp,
        "owner and helper fingerprints must match after HashedKeys pairing"
    );

    println!("Protocol HashedKeys pairing flow test passed.");

    // Negative: tampering the binding hash before the scanner starts must
    // surface `PrePairHashMismatch` once the real keys arrive — the
    // security-relevant guarantee of the HashedKeys mode.
    println!("=== Protocol HashedKeys pairing — tampered binding hash ===");

    let channel_id = ChannelId(2);
    let mut owner = Peer::new("owner", "https://owner.example.com");
    let mut helper = Peer::new("helper", "https://helper.example.com");

    let mut contact = owner
        .protocol
        .create_contact(Some(channel_id), derec_proto::ContactMode::HashedKeys)
        .await
        .expect("owner.create_contact(HashedKeys) failed");
    contact
        .contact_binding_hash
        .as_mut()
        .expect("HashedKeys contact must carry binding hash")[0] ^= 0xff;

    helper
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::Helper,
            contact,
            peer_communication_info: std::collections::HashMap::new(),
        })
        .await
        .expect("helper start(Pairing) failed");

    // Hand-route helper -> owner -> helper so we can intercept the
    // PrePairResponse with `process()` directly and observe the error
    // instead of having `deliver` panic.
    let mut from_helper = helper.drain();
    assert_eq!(
        from_helper.len(),
        1,
        "helper should have queued exactly one PrePairRequest"
    );
    let (_, pre_pair_request_bytes) = from_helper.pop().unwrap();
    let _ = deliver(&mut owner, &pre_pair_request_bytes).await;

    let mut from_owner = owner.drain();
    assert_eq!(
        from_owner.len(),
        1,
        "owner should have queued exactly one PrePairResponse"
    );
    let (_, pre_pair_response_bytes) = from_owner.pop().unwrap();
    let err = helper
        .protocol
        .process(&pre_pair_response_bytes)
        .await
        .err()
        .expect("tampered binding hash must cause process() to return Err");
    assert!(
        matches!(
            err.source,
            derec_library::Error::Pairing(
                derec_library::primitives::pairing::PairingError::PrePairHashMismatch
            )
        ),
        "tampered binding hash must surface PrePairHashMismatch, got: {err}"
    );

    println!("Protocol HashedKeys pairing — tampered binding hash test passed.");
}


/// Exercises the `derec.replica_id` wiring. Three scenarios:
///
/// 1. **Happy path**: two replica-configured peers complete a replica-mode
///    pairing; both sides' `Channel.replica_id` carries the *peer*'s id (the
///    bytes round-trip through `CommunicationInfo`).
/// 2. **Initiator missing replica_id**: `start(Pairing { kind: Replica })`
///    on a protocol built without `with_replica_id` fails fast with
///    `Error::ReplicaIdNotConfigured` — no bytes hit the wire.
/// 3. **Responder missing replica_id**: an incoming `PairRequest` with
///    `sender_kind == Replica` against a contact creator that has no
///    `replica_id` configured returns the same error from `process()`.
async fn run_replica_id_wiring_flow() {
    println!("=== Protocol replica_id wiring flow ===");

    // -- Scenario 1: happy path --
    let owner_id = 0x1111_2222_3333_4444u64;
    let helper_id = 0xAAAA_BBBB_CCCC_DDDDu64;
    let channel_id = ChannelId(1);

    let mut owner = Peer::with_replica_id("owner", "https://owner.example.com", owner_id);
    let mut helper = Peer::with_replica_id("helper", "https://helper.example.com", helper_id);

    let contact = owner
        .protocol
        .create_contact(Some(channel_id), derec_proto::ContactMode::InlineKeys)
        .await
        .expect("owner.create_contact failed");

    helper
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::ReplicaDestination,
            contact,
            peer_communication_info: std::collections::HashMap::new(),
        })
        .await
        .expect("helper start(Pairing, kind=Replica) failed");

    let helper_to_owner = pump(&mut helper, &mut owner).await;
    let owner_to_helper = pump(&mut owner, &mut helper).await;
    let all_events: Vec<&DeRecEvent> =
        helper_to_owner.iter().chain(owner_to_helper.iter()).collect();

    assert!(
        helper_to_owner
            .iter()
            .any(|e| matches!(e, DeRecEvent::PairingCompleted { .. })),
        "expected PairingCompleted for replica pairing"
    );

    // Both sides emit ReplicaPaired alongside PairingCompleted, with the
    // peer's replica id as payload. The local side's role (Source vs
    // Destination) lives on Channel.role and is asserted further below.
    // The handshake completes inside a single pump round, so search the
    // union of both event streams and discriminate by the carried id.
    let owner_side = all_events.iter().any(|e| matches!(
        e,
        DeRecEvent::ReplicaPaired { channel_id: c, peer_replica_id }
            if *c == channel_id && *peer_replica_id == helper_id
    ));
    assert!(
        owner_side,
        "owner-side ReplicaPaired must fire carrying helper_id",
    );

    let helper_side = all_events.iter().any(|e| matches!(
        e,
        DeRecEvent::ReplicaPaired { channel_id: c, peer_replica_id }
            if *c == channel_id && *peer_replica_id == owner_id
    ));
    assert!(
        helper_side,
        "helper-side ReplicaPaired must fire carrying owner_id",
    );

    // Both sides' Channel records carry the PEER's replica id (not their own).
    let owner_sid = owner.protocol.secret_id();
    let helper_sid = helper.protocol.secret_id();
    let owner_channel = owner
        .protocol
        .channel_store
        .load(owner_sid, channel_id)
        .await
        .expect("owner channel load")
        .expect("owner channel must exist");
    let helper_channel = helper
        .protocol
        .channel_store
        .load(helper_sid, channel_id)
        .await
        .expect("helper channel load")
        .expect("helper channel must exist");

    assert_eq!(
        owner_channel.replica_id,
        Some(helper_id),
        "owner-side Channel.replica_id must carry helper's id, got {:?}",
        owner_channel.replica_id,
    );
    assert_eq!(
        helper_channel.replica_id,
        Some(owner_id),
        "helper-side Channel.replica_id must carry owner's id, got {:?}",
        helper_channel.replica_id,
    );
    // Helper scanned as ReplicaDestination → helper has local role
    // ReplicaDestination, owner (contact creator) has the inverted role
    // ReplicaSource on its side of the channel.
    assert_eq!(owner_channel.role, SenderKind::ReplicaSource);
    assert_eq!(helper_channel.role, SenderKind::ReplicaDestination);

    // The reserved key MUST NOT leak into the free-form communication_info
    // map exposed to the app — extract_communication_info strips it.
    assert!(
        !owner_channel
            .communication_info
            .contains_key("derec.replica_id"),
        "owner-side communication_info must not contain reserved key"
    );
    assert!(
        !helper_channel
            .communication_info
            .contains_key("derec.replica_id"),
        "helper-side communication_info must not contain reserved key"
    );

    println!("  happy path: both sides carry peer replica_id ✓");


    // -- Scenario 2: initiator missing replica_id --
    let mut owner = Peer::with_replica_id("owner", "https://owner.example.com", owner_id);
    let mut helper_unconfigured = Peer::new("helper", "https://helper.example.com");

    let contact = owner
        .protocol
        .create_contact(Some(ChannelId(2)), derec_proto::ContactMode::InlineKeys)
        .await
        .expect("owner.create_contact failed");

    let result = helper_unconfigured
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::ReplicaDestination,
            contact,
            peer_communication_info: std::collections::HashMap::new(),
        })
        .await;
    assert!(
        matches!(result, Err(derec_library::Error::ReplicaIdNotConfigured)),
        "unconfigured initiator must refuse replica-mode start, got {result:?}"
    );
    // And: no bytes left the wire.
    assert!(
        helper_unconfigured.drain().is_empty(),
        "no outbound traffic should have been generated"
    );

    println!("  initiator without replica_id: ReplicaIdNotConfigured ✓");


    // -- Scenario 3: responder missing replica_id --
    // Helper IS configured, Owner is NOT. Helper sends a Replica PairRequest;
    // Owner's process() must reject it before surfacing any ActionRequired.
    let mut owner_unconfigured = Peer::new("owner", "https://owner.example.com");
    let mut helper = Peer::with_replica_id("helper", "https://helper.example.com", helper_id);

    let contact = owner_unconfigured
        .protocol
        .create_contact(Some(ChannelId(3)), derec_proto::ContactMode::InlineKeys)
        .await
        .expect("owner.create_contact failed");

    helper
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::ReplicaDestination,
            contact,
            peer_communication_info: std::collections::HashMap::new(),
        })
        .await
        .expect("helper start should succeed (helper IS configured)");

    let mut from_helper = helper.drain();
    assert_eq!(
        from_helper.len(),
        1,
        "helper should have queued exactly one PairRequest"
    );
    let (_, pair_request_bytes) = from_helper.pop().unwrap();
    let err = owner_unconfigured
        .protocol
        .process(&pair_request_bytes)
        .await
        .err()
        .expect("unconfigured responder must refuse replica-mode PairRequest");
    assert!(
        matches!(err.source, derec_library::Error::ReplicaIdNotConfigured),
        "expected ReplicaIdNotConfigured on responder, got: {err}"
    );

    println!("  responder without replica_id: ReplicaIdNotConfigured ✓");

    println!("Protocol replica_id wiring flow test passed.");
}


/// Exercises `ProtectSecret` with a mixed target set of helpers and
/// replicas. Asserts that each replica target receives one
/// `StoreShareRequest` carrying the **full `Secret` payload** (tagged
/// with `share_algorithm = SHARE_ALGORITHM_REPLICA_SECRET = 1`),
/// distinct from the per-helper VSS share fragments.
async fn run_protect_secret_with_replica_targets_flow() {
    println!("=== Protocol ProtectSecret(replica targets) flow ===");

    let owner_id = 0xAAAA_AAAA_AAAA_AAAAu64;
    let replica_id = 0xBBBB_BBBB_BBBB_BBBBu64;
    let helper_a_channel = ChannelId(1);
    let helper_b_channel = ChannelId(2);
    let replica_channel = ChannelId(3);

    // VSS requires threshold >= 2 and threshold <= helper count, so this
    // scenario uses 2 helpers + 1 replica. The replica doesn't
    // participate in the split (it gets the full secret).
    let mut owner = Peer::with_secret_id_and_replica_id(
        "owner",
        "https://owner.example.com",
        0xC0FFEE,
        owner_id,
    );
    let mut helper_a = Peer::new("helper-a", "https://helper-a.example.com");
    let mut helper_b = Peer::new("helper-b", "https://helper-b.example.com");
    let mut replica =
        Peer::with_replica_id("replica", "https://replica.example.com", replica_id);

    // 1. Owner pairs with two Helpers (classic share path targets).
    pair(&mut owner, &mut helper_a, helper_a_channel).await;
    pair(&mut owner, &mut helper_b, helper_b_channel).await;

    // 2. Owner pairs with another device in Replica mode (secret sync target).
    let replica_contact = owner
        .protocol
        .create_contact(Some(replica_channel), derec_proto::ContactMode::InlineKeys)
        .await
        .expect("owner.create_contact failed");
    replica
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::ReplicaDestination,
            contact: replica_contact,
            peer_communication_info: std::collections::HashMap::new(),
        })
        .await
        .expect("replica start(Pairing, kind=Replica) failed");
    let _ = pump(&mut replica, &mut owner).await;
    let _ = pump(&mut owner, &mut replica).await;

    let owner_sid = owner.protocol.secret_id();
    let owner_replica_channel = owner
        .protocol
        .channel_store
        .load(owner_sid, replica_channel)
        .await
        .expect("owner replica channel load")
        .expect("owner replica channel must exist");
    // Replica scanned as ReplicaDestination → owner has ReplicaSource role.
    assert_eq!(owner_replica_channel.role, SenderKind::ReplicaSource);

    // Replica channels start `Pending` and stay there until the app
    // calls `verify_fingerprint` (the protocol's confirmation gate).
    // In production each side displays the local fingerprint to the
    // user, who reads off the other device's fingerprint and confirms
    // they match; the in-memory smoke test just cross-confirms.
    let owner_fp = owner
        .protocol
        .get_fingerprint(replica_channel)
        .await
        .expect("owner fingerprint");
    let replica_fp = replica
        .protocol
        .get_fingerprint(replica_channel)
        .await
        .expect("replica fingerprint");
    assert_eq!(
        owner_fp, replica_fp,
        "owner and replica must derive the same fingerprint from K_replica"
    );
    let confirmed_owner = owner
        .protocol
        .verify_fingerprint(replica_channel, &replica_fp)
        .await
        .expect("owner verify_fingerprint");
    let confirmed_replica = replica
        .protocol
        .verify_fingerprint(replica_channel, &owner_fp)
        .await
        .expect("replica verify_fingerprint");
    assert!(
        confirmed_owner && confirmed_replica,
        "both sides must accept the matching fingerprint",
    );

    // Owner's verify_fingerprint auto-publishes an empty-secret roster
    // snapshot to every paired peer (the multi-device sync invariant —
    // a newly-Paired Replica must observe the current state without
    // waiting for the app to drive an explicit ProtectSecret). The
    // assertions below target the explicit publish; drain the
    // auto-publish round here so the outbox starts empty.
    let auto_publish = owner.transport.drain();
    assert_eq!(
        auto_publish.len(),
        3,
        "verify_fingerprint auto-publish must fan out to 2 helpers + 1 replica (v=1, empty secrets)"
    );

    // 3. Owner protects a secret targeting BOTH helpers and the replica.
    let secret_data = b"secret-payload-for-replica-and-helper".to_vec();
    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![UserSecret {
                id: vec![0x01],
                name: "shared-secret".to_owned(),
                data: secret_data.clone(),
            }],
            description: Some("replica + helper distribution".to_owned()),
        })
        .await
        .expect("owner start(ProtectSecret) with replica target failed");

    // 4. Owner's outbox must hold three envelopes — one per helper + one
    //    for the replica.
    let outbound = owner.transport.drain();
    assert_eq!(
        outbound.len(),
        3,
        "expected three outbound StoreShareRequests (two helpers + one replica), got {}",
        outbound.len()
    );

    let helper_a_env = outbound
        .iter()
        .find(|(tp, _)| tp.uri == helper_a.uri)
        .expect("one envelope must route to helper-a");
    let replica_env = outbound
        .iter()
        .find(|(tp, _)| tp.uri == replica.uri)
        .expect("one envelope must route to the replica");

    // 5. Decrypt the inner StoreShareRequest on each side using its
    //    shared key, and assert payload shape:
    //    helper → share_algorithm == 0 (VSS share fragment)
    //    replica → share_algorithm == 1 (full secret, contains secret_data)
    let helper_a_sid = helper_a.protocol.secret_id();
    let replica_sid = replica.protocol.secret_id();
    let helper_a_key = match helper_a
        .protocol
        .secret_store
        .load(helper_a_sid, helper_a_channel, SecretKind::SharedKey)
        .await
        .expect("helper-a key load")
        .expect("helper-a shared key must exist")
    {
        SecretValue::SharedKey(k) => k,
        _ => panic!("helper-a SharedKey value mismatch"),
    };
    let replica_key = match replica
        .protocol
        .secret_store
        .load(replica_sid, replica_channel, SecretKind::SharedKey)
        .await
        .expect("replica key load")
        .expect("replica shared key must exist")
    {
        SecretValue::SharedKey(k) => k,
        _ => panic!("replica SharedKey value mismatch"),
    };

    let helper_msg = decode_store_share_request(&helper_a_env.1, &helper_a_key);
    assert_eq!(
        helper_msg.share_algorithm, 0,
        "helper envelope must carry VSS share (algorithm 0), got {}",
        helper_msg.share_algorithm
    );

    let replica_msg = decode_store_share_request(&replica_env.1, &replica_key);
    assert_eq!(
        replica_msg.share_algorithm, 1,
        "replica envelope must carry full secret (algorithm 1 = REPLICA_SECRET), got {}",
        replica_msg.share_algorithm
    );

    // 6. The replica's share bytes are the canonical DeRecSecret payload —
    //    it must contain the original secret data, byte-for-byte.
    assert!(
        contains_subslice(&replica_msg.share, &secret_data),
        "replica envelope must contain the original secret payload (full secret)"
    );

    // 7. Helper share is a VSS fragment whose payload bytes do NOT contain
    //    the raw secret verbatim (it's a polynomial share + commitment).
    //    The replica payload's `contains_subslice` check above is the
    //    counterpart proving the FULL secret is there.
    assert!(
        !contains_subslice(&helper_msg.share, &secret_data),
        "helper VSS fragment must NOT contain the raw secret bytes",
    );

    // 8. All targets share the same secret_id and version on this round.
    assert_eq!(helper_msg.secret_id, replica_msg.secret_id);
    assert_eq!(helper_msg.version, replica_msg.version);

    println!(
        "  helper envelope: share_algorithm=0 (VSS), {}B  ✓",
        helper_msg.share.len()
    );
    println!(
        "  replica envelope: share_algorithm=1 (full secret), {}B, contains secret  ✓",
        replica_msg.share.len()
    );


    // 9. End-to-end receiver side: feed the replica envelope into the
    //    replica peer's process(). It should auto-ack and emit a
    //    ReplicaSecretReceived event. Owner then processes the ack and
    //    emits ReplicaSecretAcked.
    println!("  -- receiver-side replica dispatch --");

    let replica_events = replica
        .protocol
        .process(&replica_env.1)
        .await
        .expect("replica.process(StoreShareRequest) must succeed");
    let received = replica_events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::ReplicaSecretReceived {
                channel_id: c,
                from_replica_id,
                secret_id,
                version: _,
                secret,
                shares,
            } if *c == replica_channel => Some((
                *from_replica_id,
                *secret_id,
                secret.clone(),
                shares.clone(),
            )),
            _ => None,
        })
        .expect("replica.process should emit ReplicaSecretReceived");
    let (received_from, received_secret_id, received_secret, shares) = received;
    assert_eq!(received_from, owner_id, "from_replica_id must be owner's id");
    assert_eq!(received_secret_id, 0xC0FFEE, "secret_id mismatch");
    // Typed event: the Secret carries the user-secret bytes
    // verbatim (one entry, since the test wrote one UserSecret).
    assert_eq!(received_secret.secrets.len(), 1, "secret must carry one user secret");
    assert_eq!(
        received_secret.secrets[0].data, secret_data,
        "secret.secrets[0].data must round-trip the original user secret"
    );
    // Owner had 2 helpers in this test, so the share map (composite's
    // `shares` field) must contain one entry per helper, keyed by the
    // helper channel ids (channel_id is the only identifier shared
    // between Source and Destination — the Destination needs it to map
    // each share back to its helper if it ever takes over recovery).
    assert_eq!(
        shares.len(),
        2,
        "composite must carry the helper-share map (2 helpers)"
    );
    let share_channel_ids: std::collections::BTreeSet<u64> =
        shares.iter().map(|s| s.channel_id).collect();
    assert_eq!(
        share_channel_ids,
        std::collections::BTreeSet::from([helper_a_channel.0, helper_b_channel.0]),
        "ChannelShare entries must be keyed by the two helper channel ids",
    );
    for s in &shares {
        assert!(
            !s.committed_share.is_empty(),
            "ChannelShare.committed_share must be non-empty bytes"
        );
    }

    // owner_replica_id round-trips the Source's id verbatim — this is
    // what lets a Destination attribute the secret back to its origin
    // during conflict resolution.
    assert_eq!(
        received_secret.owner_replica_id, owner_id,
        "secret.owner_replica_id must echo the Source's replica_id"
    );

    // secret.helpers: snapshot of the Source's paired helpers at protect
    // time. Exactly two entries here (helper-a + helper-b), each with a
    // non-empty shared_key and the transport_uri the owner saw at pair.
    assert_eq!(
        received_secret.helpers.len(),
        2,
        "secret.helpers must contain one entry per paired helper (got {})",
        received_secret.helpers.len()
    );
    let helper_channel_ids: std::collections::BTreeSet<u64> =
        received_secret.helpers.iter().map(|h| h.channel_id).collect();
    assert_eq!(
        helper_channel_ids,
        std::collections::BTreeSet::from([helper_a_channel.0, helper_b_channel.0]),
        "secret.helpers must carry both helper channel ids"
    );
    for h in &received_secret.helpers {
        assert_eq!(
            h.shared_key.len(),
            32,
            "HelperInfo.shared_key must be a 32-byte symmetric key"
        );
    }

    // secret.replicas: snapshot of the Source's paired Destinations.
    // ReplicaDestination is the only kind that ends up here in this
    // scenario — replica_id, sender_kind, channel_id, transport_uri,
    // and shared_key must all match what the Source negotiated.
    assert_eq!(
        received_secret.replicas.len(),
        1,
        "secret.replicas must contain the single Destination (got {})",
        received_secret.replicas.len()
    );
    let destination = &received_secret.replicas[0];
    assert_eq!(
        destination.replica_id, replica_id,
        "ReplicaInfo.replica_id must echo the Destination's replica_id"
    );
    assert_eq!(
        destination.channel_id,
        replica_channel.0,
        "ReplicaInfo.channel_id must match the Source-side channel id"
    );
    assert_eq!(
        destination.sender_kind,
        SenderKind::ReplicaDestination as i32,
        "ReplicaInfo.sender_kind must be ReplicaDestination"
    );
    assert_eq!(
        destination.transport_uri, replica.uri,
        "ReplicaInfo.transport_uri must echo the Destination's URI"
    );

    println!(
        "  replica received: from={:x}, secret_id={:x}, secret: {} entry(s) / {} helper(s) / {} replica(s), {} helper share(s)  ✓",
        received_from,
        received_secret_id,
        received_secret.secrets.len(),
        received_secret.helpers.len(),
        received_secret.replicas.len(),
        shares.len()
    );

    // Replica auto-acked → drain replica's outbox and feed it to owner.
    let mut replica_outbound = replica.transport.drain();
    assert_eq!(
        replica_outbound.len(),
        1,
        "replica must auto-ack with exactly one StoreShareResponse"
    );
    let (_, ack_bytes) = replica_outbound.pop().unwrap();

    let owner_events = owner
        .protocol
        .process(&ack_bytes)
        .await
        .expect("owner.process(StoreShareResponse) on replica channel must succeed");
    let acked = owner_events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::ReplicaSecretAcked {
                channel_id: c,
                from_replica_id,
                status,
                memo,
                ..
            } if *c == replica_channel => Some((*from_replica_id, *status, memo.clone())),
            _ => None,
        })
        .expect("owner.process should emit ReplicaSecretAcked");
    assert_eq!(
        acked.0, replica_id,
        "ReplicaSecretAcked.from_replica_id must be replica's id"
    );
    assert_eq!(acked.1, 0, "expected StatusEnum::Ok (0), got status={}", acked.1);
    println!(
        "  owner received ack: from={:x}, status={}, memo={:?}  ✓",
        acked.0, acked.1, acked.2
    );

    println!("Protocol ProtectSecret(replica targets) flow test passed.");
}


/// Decode and decrypt a `StoreShareRequest` envelope using the given
/// shared key. Panics on any malformed input — only used by smoke tests
/// where the envelope shape is guaranteed by the sender path.
///
/// The envelope is a `DeRecMessage` proto whose `message` field carries
/// the channel-encrypted inner ciphertext; `extract_inner_message` only
/// handles the decryption step, so we decode the outer envelope here.
fn decode_store_share_request(
    envelope_bytes: &[u8],
    shared_key: &[u8; 32],
) -> derec_proto::StoreShareRequestMessage {
    use derec_library::derec_message::extract_inner_message;
    use prost::Message as _;

    let envelope = derec_proto::DeRecMessage::decode(envelope_bytes)
        .expect("envelope must be a valid DeRecMessage proto");
    let inner = extract_inner_message(&envelope.message, shared_key)
        .expect("envelope inner ciphertext must decrypt with the channel shared key");
    match inner {
        derec_proto::MessageBody::StoreShareRequest(req) => req,
        _ => panic!("expected StoreShareRequest, got {:?}", std::any::type_name_of_val(&inner)),
    }
}


async fn run_sharing_flow() {
    println!("=== Protocol sharing flow test ===");

    let channel_a = ChannelId(1);
    let channel_b = ChannelId(2);
    let mut owner = Peer::with_secret_id("owner", "https://owner.example.com", 42);
    let mut helper_a = Peer::new("helper-a", "https://helper-a.example.com");
    let mut helper_b = Peer::new("helper-b", "https://helper-b.example.com");

    pair(&mut owner, &mut helper_a, channel_a).await;
    pair(&mut owner, &mut helper_b, channel_b).await;
    println!("Pairing complete — distributing a secret (threshold=2, helpers=2)");

    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![UserSecret {
                id: vec![1, 2, 3],
                name: "smoke-test secret".to_owned(),
                data: b"super-secret-value".to_vec(),
            }],
            description: Some("smoke-test distribution".to_owned()),
        })
        .await
        .expect("owner start(ProtectSecret) failed");

    // ProtectSecret fans out to both helpers in the same round, so a 2-peer
    // pump can't route — drain the whole network until quiescent and
    // partition the resulting events by `channel_id` to assert per-helper.
    let events = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b]).await;

    let stored_for = |cid: ChannelId| {
        events.iter().any(|e| {
            matches!(e, DeRecEvent::ShareStored { channel_id, .. } if *channel_id == cid)
        })
    };
    assert!(stored_for(channel_a), "expected ShareStored on helper-a");
    assert!(stored_for(channel_b), "expected ShareStored on helper-b");

    let confirmed = events
        .iter()
        .filter(|e| matches!(e, DeRecEvent::ShareConfirmed { .. }))
        .count();
    assert_eq!(
        confirmed, 2,
        "expected ShareConfirmed from both helpers (got {confirmed})"
    );

    println!("Protocol sharing flow test passed.");
}


async fn run_discovery_and_recovery_flow() {
    println!("=== Protocol discovery & recovery flow test ===");

    let channel_a = ChannelId(1);
    let channel_b = ChannelId(2);
    let recovery_channel_a = ChannelId(100);
    let recovery_channel_b = ChannelId(101);
    let secret_id_bytes = vec![9_u8, 9, 9];
    let protected_secret_id: u64 = 7777;
    let secret_data = b"correct horse battery staple".to_vec();

    // VSS sharing requires threshold ≥ 2, so the discovery+recovery scenario
    // pairs the Owner with two helpers and reconstructs from both shares.
    let mut owner =
        Peer::with_secret_id("owner", "https://owner.example.com", protected_secret_id);
    // Helpers serving this owner are bound to the same secret id — every
    // store on the helper side partitions by that id, which is the only
    // model that's coherent under the new trait surface (one protocol =
    // one helped-with secret).
    let mut helper_a =
        Peer::with_secret_id("helper-a", "https://helper-a.example.com", protected_secret_id);
    let mut helper_b =
        Peer::with_secret_id("helper-b", "https://helper-b.example.com", protected_secret_id);


    pair(&mut owner, &mut helper_a, channel_a).await;
    pair(&mut owner, &mut helper_b, channel_b).await;
    println!("Initial pairing complete on channels {channel_a:?} and {channel_b:?}.");

    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![UserSecret {
                id: secret_id_bytes.clone(),
                name: "wallet seed".to_owned(),
                data: secret_data.clone(),
            }],
            description: Some("wallet seed phrase".to_owned()),
        })
        .await
        .expect("owner start(ProtectSecret) failed");

    let share_events = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b]).await;
    let stored_on = |cid: ChannelId| {
        share_events
            .iter()
            .any(|e| matches!(e, DeRecEvent::ShareStored { channel_id, .. } if *channel_id == cid))
    };
    assert!(stored_on(channel_a), "expected ShareStored on helper-a");
    assert!(stored_on(channel_b), "expected ShareStored on helper-b");
    let confirmed = share_events
        .iter()
        .filter(|e| matches!(e, DeRecEvent::ShareConfirmed { .. }))
        .count();
    assert_eq!(
        confirmed, 2,
        "expected ShareConfirmed from both helpers (got {confirmed})"
    );
    println!("Secret distributed and confirmed by both helpers.");

    // A recovering Owner has lost local state, so it pairs again with each
    // Helper on a brand-new channel. The Owner is the pairing initiator here.
    // Simulate state loss explicitly so the pair-completion auto-publish hook
    // has nothing to replay against the new channels.
    owner
        .protocol
        .user_secret_store
        .remove(owner.protocol.secret_id())
        .await
        .expect("clearing user_secret_store");

    for (helper, fresh_cid, label) in [
        (&mut helper_a, recovery_channel_a, "helper-a"),
        (&mut helper_b, recovery_channel_b, "helper-b"),
    ] {
        let recovery_contact = owner
            .protocol
            .create_contact(Some(fresh_cid), derec_proto::ContactMode::InlineKeys)
            .await
            .unwrap_or_else(|e| panic!("owner.create_contact (recovery, {label}) failed: {e}"));

        helper
            .protocol
            .start(DeRecFlow::Pairing {
                kind: SenderKind::Helper,
                contact: recovery_contact,
                peer_communication_info: std::collections::HashMap::from([(
                    "name".to_owned(),
                    "recovering-owner".to_owned(),
                )]),
            })
            .await
            .unwrap_or_else(|e| panic!("{label} start(Pairing recovery) failed: {e}"));

        let r = pump_many(&mut [&mut owner, helper]).await;
        let paired = r
            .iter()
            .filter(|e| matches!(e, DeRecEvent::PairingCompleted { .. }))
            .count();
        assert!(
            paired >= 2,
            "expected recovery PairingCompleted on both sides for {label} (got {paired})"
        );
    }
    println!(
        "Recovery re-pairing complete on channels {recovery_channel_a:?} and {recovery_channel_b:?}."
    );

    // Each helper links its original channel to its new recovery channel so
    // discovery (which resolves the connected component then `load_many`)
    // finds the share stored under the original channel.
    let helper_a_sid = helper_a.protocol.secret_id();
    let helper_b_sid = helper_b.protocol.secret_id();
    let owner_sid = owner.protocol.secret_id();
    helper_a
        .protocol
        .channel_store
        .link_channel(helper_a_sid, channel_a, recovery_channel_a)
        .await
        .expect("helper-a link_channel failed");
    helper_b
        .protocol
        .channel_store
        .link_channel(helper_b_sid, channel_b, recovery_channel_b)
        .await
        .expect("helper-b link_channel failed");

    // Simulate the Owner-side state loss: drop the original channels so
    // recovery only fans out to the recovery channels. Without this step,
    // recovery would receive duplicate shares (one per original + one per
    // linked recovery channel) and Lagrange interpolation would panic on
    // colliding x-coordinates.
    owner
        .protocol
        .channel_store
        .remove(owner_sid, channel_a)
        .await
        .expect("owner remove(channel_a) failed");
    owner
        .protocol
        .channel_store
        .remove(owner_sid, channel_b)
        .await
        .expect("owner remove(channel_b) failed");

    // Scope discovery to the *recovery* channels only. The Owner still has
    // the original pairings live in this smoke test (we don't simulate state
    // loss), but a real recovering Owner would only have the recovery
    // channels — and including the original channels here would produce
    // duplicate shares that break Lagrange interpolation.

    owner
        .protocol
        .start(DeRecFlow::Discovery {
            target: Target::Many(vec![recovery_channel_a, recovery_channel_b]),
        })
        .await
        .expect("owner start(Discovery) failed");

    let discovery_events = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b]).await;
    let discovered: Vec<_> = discovery_events
        .iter()
        .filter_map(|e| match e {
            DeRecEvent::SecretsDiscovered {
                channel_id,
                secrets,
            } => Some((*channel_id, secrets.clone())),
            _ => None,
        })
        .collect();
    assert!(
        !discovered.is_empty(),
        "expected at least one SecretsDiscovered event on owner"
    );

    let entry = discovered
        .iter()
        .flat_map(|(_, secrets)| secrets.iter())
        .find(|e| e.secret_id == protected_secret_id)
        .expect("discovered list must contain the distributed secret");
    assert!(
        entry
            .versions
            .iter()
            .any(|v| v.description == "wallet seed phrase"),
        "version description must be preserved through discovery"
    );
    let recover_version = entry
        .versions
        .iter()
        .map(|v| v.version)
        .max()
        .expect("discovered secret must have at least one version");
    println!(
        "Owner discovered secret_id={protected_secret_id} v{recover_version} across {} helper(s); recovering.",
        discovered.len()
    );


    owner
        .protocol
        .start(DeRecFlow::RecoverSecret {
            secret_id: protected_secret_id,
            version: recover_version,
        })
        .await
        .expect("owner start(RecoverSecret) failed");

    let recovery_events = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b]).await;
    let recovered = recovery_events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::SecretRecovered { secret } => Some(secret.clone()),
            _ => None,
        })
        .expect("expected SecretRecovered event on owner");

    // The library now decodes the protect-side wrapping for us — assert the
    // recovered `Secret` carries the typed `UserSecret` the owner originally
    // protected (id + name + data all round-trip).
    let recovered_user_secret = recovered
        .secrets
        .iter()
        .find(|s| s.id == secret_id_bytes)
        .expect("recovered Secret must include the UserSecret with the original id");
    assert_eq!(
        recovered_user_secret.data, secret_data,
        "recovered UserSecret.data must match the original protected bytes"
    );
    assert_eq!(
        recovered_user_secret.name, "wallet seed",
        "recovered UserSecret.name must round-trip"
    );
    println!(
        "Owner successfully reconstructed the secret: UserSecret '{}' ({}B) ✓",
        recovered_user_secret.name,
        recovered_user_secret.data.len()
    );

    println!("Protocol discovery & recovery flow test passed.");
}


fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}


/// Drives a full unpair handshake under [`UnpairAck::Required`]: Owner starts
/// the flow, Helper auto-accepts (via `deliver`), Owner processes the `Ok`
/// response, and both sides tear down their channel state. Verifies the
/// `Unpaired` events fire on **both** sides and that `channel_store::load`
/// returns `None` afterwards.
async fn run_unpairing_flow() {
    println!("=== Protocol unpairing flow (Required ack) ===");

    let channel_id = ChannelId(7);
    let mut owner = Peer::new("owner", "https://owner.example.com");
    let mut helper = Peer::new("helper", "https://helper.example.com");

    pair(&mut owner, &mut helper, channel_id).await;
    println!("Pairing complete — sending unpair request");

    // The builder default is `UnpairAck::Required`, which is what this
    // scenario exercises — the owner waits for the helper's `Ok` before
    // dropping local state.

    owner
        .protocol
        .start(DeRecFlow::Unpair {
            target: Target::Single(channel_id),
            memo: Some("decommissioning".to_owned()),
        })
        .await
        .expect("owner start(Unpair) failed");

    // `pump` routes the UnpairRequest from Owner to Helper, recursively
    // routes the Helper's `Ok` response back to the Owner, and returns every
    // event emitted along the way. We expect two `Unpaired` events — one on
    // each side — both for the same `channel_id`.
    let events = pump(&mut owner, &mut helper).await;
    let unpaired = events
        .iter()
        .filter(|e| matches!(e, DeRecEvent::Unpaired { channel_id: c } if *c == channel_id))
        .count();
    assert!(
        unpaired >= 2,
        "expected two Unpaired events (helper + owner), got {unpaired} (in {} total events)",
        events.len()
    );
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, DeRecEvent::UnpairRejected { .. })),
        "the Required-ack flow with helper auto-accept must not produce UnpairRejected events"
    );

    let owner_sid = owner.protocol.secret_id();
    let helper_sid = helper.protocol.secret_id();
    let owner_channel = owner
        .protocol
        .channel_store
        .load(owner_sid, channel_id)
        .await
        .expect("owner channel_store.load failed");
    let helper_channel = helper
        .protocol
        .channel_store
        .load(helper_sid, channel_id)
        .await
        .expect("helper channel_store.load failed");
    assert!(
        owner_channel.is_none(),
        "owner channel must be removed after unpair"
    );
    assert!(
        helper_channel.is_none(),
        "helper channel must be removed after unpair"
    );

    // Negative test: a Helper attempting to initiate `Unpair` is refused with
    // `RoleMismatch` before any bytes hit the wire.
    let helper_init_channel = ChannelId(8);
    let mut owner = Peer::new("owner", "https://owner.example.com");
    let mut helper = Peer::new("helper", "https://helper.example.com");
    pair(&mut owner, &mut helper, helper_init_channel).await;
    let result = helper
        .protocol
        .start(DeRecFlow::Unpair {
            target: Target::Single(helper_init_channel),
            memo: Some("helper trying to unpair".to_owned()),
        })
        .await;
    assert!(
        matches!(result, Err(derec_library::Error::RoleMismatch { .. })),
        "Helper-initiated Unpair must be refused with RoleMismatch, got {result:?}"
    );

    println!("Protocol unpairing flow test passed.");
}


/// Drives a full `UpdateChannelInfo` round-trip: Owner mutates local state via
/// `set_communication_info` / `set_own_transport`, broadcasts the update,
/// Helper auto-accepts via `accept(action)`, both sides emit
/// `ChannelInfoUpdated`, and the channel record on the responder reflects the
/// new metadata.
async fn run_update_channel_info_flow() {
    println!("=== Protocol UpdateChannelInfo flow ===");

    let channel_id = ChannelId(42);
    let mut owner = Peer::new("owner", "https://owner.example.com");
    let mut helper = Peer::new("helper", "https://helper.example.com");

    pair(&mut owner, &mut helper, channel_id).await;
    println!("Pairing complete — preparing UpdateChannelInfo broadcast");

    // Owner mutates local state, then propagates the change.
    let new_uri = "https://owner.NEW.example.com".to_owned();
    let new_info: std::collections::HashMap<String, String> = [
        ("name".to_owned(), "Owner-renamed".to_owned()),
        ("email".to_owned(), "owner.new@example.com".to_owned()),
    ]
    .into_iter()
    .collect();

    owner.protocol.set_communication_info(new_info.clone());
    owner
        .protocol
        .set_own_transport(new_uri.clone())
        .expect("test fixture: valid URI should pass set_own_transport validation");
    // Simulate "the new endpoint is up before the update is sent" — the
    // pump dispatches by `Peer::uri`, so this is the in-memory equivalent
    // of starting to listen on the new URI.
    owner.uri = new_uri.clone();

    owner
        .protocol
        .start(DeRecFlow::UpdateChannelInfo {
            target: Target::Single(channel_id),
            communication_info: Some(new_info.clone()),
            transport_protocol: Some(TransportProtocol {
                uri: new_uri.clone(),
                protocol: Protocol::Https.into(),
            }),
        })
        .await
        .expect("owner start(UpdateChannelInfo) failed");

    // pump routes the request to the Helper, then the Helper's response back.
    let events = pump(&mut owner, &mut helper).await;

    let helper_updated = events.iter().any(|e| {
        matches!(
            e,
            DeRecEvent::ChannelInfoUpdated { channel_id: c, .. } if *c == channel_id
        )
    });
    assert!(
        helper_updated,
        "expected ChannelInfoUpdated on the Helper after accept"
    );

    let owner_updated = events
        .iter()
        .filter(|e| matches!(e, DeRecEvent::ChannelInfoUpdated { channel_id: c, .. } if *c == channel_id))
        .count();
    assert!(
        owner_updated >= 2,
        "expected ChannelInfoUpdated on both Owner and Helper (got {owner_updated})"
    );

    // Helper's stored Channel must now mirror the Owner's announced metadata.
    let helper_sid = helper.protocol.secret_id();
    let helper_channel = helper
        .protocol
        .channel_store
        .load(helper_sid, channel_id)
        .await
        .expect("helper channel_store.load failed")
        .expect("helper channel must still exist after UpdateChannelInfo");
    assert_eq!(
        helper_channel.transport.uri, new_uri,
        "helper's stored transport URI must reflect the announced update"
    );
    assert_eq!(
        helper_channel.communication_info, new_info,
        "helper's stored communication_info must mirror the announced map"
    );

    // Negative test: an update with neither field set is rejected up front.
    let empty_result = owner
        .protocol
        .start(DeRecFlow::UpdateChannelInfo {
            target: Target::Single(channel_id),
            communication_info: None,
            transport_protocol: None,
        })
        .await;
    assert!(
        matches!(empty_result, Err(derec_library::Error::InvalidInput(_))),
        "expected InvalidInput when both fields are None, got {empty_result:?}"
    );

    println!("Protocol UpdateChannelInfo flow test passed.");
}


/// Asserts the two halves of the `replyTo` contract:
///
/// 1. With `with_auto_reply_to(true)`, every outbound channel-mode request
///    carries `replyTo = own_transport` on its inner request body.
/// 2. When a request arrives carrying a `replyTo` that differs from the
///    channel's stored peer endpoint, the responder routes the response
///    to `replyTo` (not to the stored endpoint).
///
/// Half (1) covers the requester side; half (2) covers the responder side.
/// Together they prove the wire format and routing override both work
/// without needing the full replica topology (which lives behind the
/// replica feature epic).
async fn run_reply_to_flow() {
    println!("=== Protocol replyTo flow ===");

    use derec_library::derec_message::{
        DeRecMessageBuilder, current_timestamp, extract_inner_message,
    };
    use derec_proto::{DeRecMessage, GetSecretIdsVersionsRequestMessage, MessageBody};
    use prost::Message as _;

    let channel_id = ChannelId(7);
    let mut owner = Peer::with_auto_reply_to("owner-reply", "https://owner-reply.example.com");
    let mut helper = Peer::new("helper-reply", "https://helper-reply.example.com");

    pair(&mut owner, &mut helper, channel_id).await;

    // Half 1: auto_reply_to populates request.reply_to on outbound.
    owner
        .protocol
        .start(DeRecFlow::Discovery {
            target: Target::Single(channel_id),
        })
        .await
        .expect("owner start(Discovery) failed");

    let outbound = owner.drain();
    assert_eq!(
        outbound.len(),
        1,
        "expected exactly one outbound Discovery request, got {}",
        outbound.len()
    );
    let (dest, envelope_bytes) = &outbound[0];
    assert_eq!(
        dest.uri, "https://helper-reply.example.com",
        "outbound request must still route to the channel's stored helper endpoint"
    );

    // The orchestrator carried our own_transport into the request body.
    let owner_sid = owner.protocol.secret_id();
    let SecretValue::SharedKey(shared_key) = owner
        .protocol
        .secret_store
        .load(owner_sid, channel_id, SecretKind::SharedKey)
        .await
        .expect("owner secret_store.load failed")
        .expect("owner shared_key must be present")
    else {
        panic!("expected SharedKey kind");
    };
    let inner =
        extract_inner_message(&DeRecMessage::decode(envelope_bytes.as_slice()).unwrap().message, &shared_key)
            .expect("inner decrypt failed");
    let MessageBody::GetSecretIdsVersionsRequest(req) = inner else {
        panic!("expected GetSecretIdsVersionsRequest, got {inner:?}");
    };
    let reply_to = req.reply_to.expect("auto_reply_to must populate replyTo");
    assert_eq!(
        reply_to.uri, "https://owner-reply.example.com",
        "replyTo.uri must equal the owner's own_transport"
    );

    // Half 2: responder routes to inbound replyTo (not the stored endpoint).
    // Hand-craft a Discovery request whose replyTo differs from the
    // owner's URI. Helper's stored peer endpoint still points to the owner,
    // so a correct implementation must route the response to the phantom
    // endpoint instead.
    let phantom_uri = "https://phantom-replica.example.com";
    let timestamp = current_timestamp();
    let crafted = GetSecretIdsVersionsRequestMessage {
        timestamp: Some(timestamp),
        reply_to: Some(TransportProtocol {
            uri: phantom_uri.to_owned(),
            protocol: Protocol::Https.into(),
        }),
    };
    let crafted_envelope = DeRecMessageBuilder::channel()
        .channel_id(channel_id)
        .timestamp(timestamp)
        .message_body(MessageBody::GetSecretIdsVersionsRequest(crafted))
        .encrypt(&shared_key)
        .expect("encrypt failed")
        .build()
        .expect("build failed")
        .encode_to_vec();

    // Drain any leftover envelopes from the previous half before feeding
    // the crafted request — we want only this exchange's outbox.
    helper.drain();
    let _ = deliver(&mut helper, &crafted_envelope).await;

    let helper_outbound = helper.drain();
    assert_eq!(
        helper_outbound.len(),
        1,
        "expected exactly one outbound Discovery response, got {}",
        helper_outbound.len()
    );
    let (response_dest, _) = &helper_outbound[0];
    assert_eq!(
        response_dest.uri, phantom_uri,
        "responder must route to request.replyTo when set, not the channel's stored endpoint"
    );

    println!("Protocol replyTo flow test passed.");
}

/// Exercises the auto-publish-on-pair hook: once the application has
/// handed off a secret via `start(ProtectSecret)`, any subsequent
/// helper-pair (or replica-pair after fingerprint verification) makes
/// the freshly-paired peer eligible for shares without an explicit
/// follow-up call. The test pairs two helpers, calls `ProtectSecret`
/// once, then pairs a third helper and asserts that helper-c received
/// a share without any additional `start` call from the owner.
async fn run_auto_publish_on_pair_flow() {
    println!("=== Protocol auto-publish-on-pair flow ===");

    let channel_a = ChannelId(1);
    let channel_b = ChannelId(2);
    let channel_c = ChannelId(3);

    let mut owner = Peer::with_secret_id("owner", "https://owner.example.com", 0xABCDE);
    let mut helper_a = Peer::new("helper-a", "https://helper-a.example.com");
    let mut helper_b = Peer::new("helper-b", "https://helper-b.example.com");
    let mut helper_c = Peer::new("helper-c", "https://helper-c.example.com");

    pair(&mut owner, &mut helper_a, channel_a).await;
    pair(&mut owner, &mut helper_b, channel_b).await;

    // First publish: explicit start(ProtectSecret). Both helpers receive
    // shares; the bag is cached on the protocol for any later pair-trigger.
    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![UserSecret {
                id: vec![0x42],
                name: "secret".to_owned(),
                data: b"initial-payload".to_vec(),
            }],
            description: Some("initial publish".to_owned()),
        })
        .await
        .expect("owner start(ProtectSecret) failed");

    let initial = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b]).await;
    let initial_stored = initial
        .iter()
        .filter(|e| matches!(e, DeRecEvent::ShareStored { .. }))
        .count();
    assert_eq!(
        initial_stored, 2,
        "initial publish must store one share per helper (got {initial_stored})"
    );

    // Pair a third helper. No follow-up `start` call from the owner —
    // the auto-publish hook fires off the cached bag, fanning out fresh
    // shares to a, b, AND c. The pump must include every helper so the
    // SSR envelopes addressed to a and b can be routed.
    let contact = owner
        .protocol
        .create_contact(Some(channel_c), derec_proto::ContactMode::InlineKeys)
        .await
        .expect("owner.create_contact(helper-c) failed");
    helper_c
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::Helper,
            contact,
            peer_communication_info: std::collections::HashMap::from([(
                "name".to_owned(),
                "helper-c".to_owned(),
            )]),
        })
        .await
        .expect("helper-c start(Pairing) failed");
    let auto = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b, &mut helper_c]).await;

    let stored_on_c = auto
        .iter()
        .any(|e| matches!(e, DeRecEvent::ShareStored { channel_id, .. } if *channel_id == channel_c));
    assert!(
        stored_on_c,
        "helper-c must receive a share via the pair-completion auto-publish"
    );

    println!("Protocol auto-publish-on-pair flow test passed.");
}


/// Walks the 0→8 version progression that proves the multi-device
/// sync invariant: every roster change or user-secret update bumps
/// the secret version, every paired Replica Destination receives the
/// fresh snapshot, and Helpers only receive VSS shares once the
/// threshold is met.
///
/// Sequence:
/// ```text
/// 0. new()                                          → latest = None
/// 1. pair replica A                                 → v=1, replicas=1
/// 2. ProtectSecret([s1])                            → v=2, secrets=1
/// 3. pair replica B (bootstrap)                     → v=3, replicas=2
/// 4. pair helper #1 (below threshold)               → v=4, helpers=1
/// 5. pair helper #2 (below threshold)               → v=5, helpers=2
/// 6. ProtectSecret([s1, s2])                        → v=6, secrets=2
/// 7. pair helper #3 (threshold met, VSS split)      → v=7, helpers=3 + shares
/// 8. pair replica C (full bootstrap + fresh shares) → v=8, replicas=3 + shares
/// ```
async fn run_replica_sync_version_progression_flow() {
    println!("=== Protocol replica sync — version progression v0→v8 ===");

    const PROTECTED_SECRET_ID: u64 = 0xABBA;
    const THRESHOLD: usize = 3;
    let owner_replica_id: u64 = 0x0001;
    let replica_a_id: u64 = 0x000A;
    let replica_b_id: u64 = 0x000B;
    let replica_c_id: u64 = 0x000C;

    let mut owner = Peer::with_options(
        "owner",
        "https://owner.example.com",
        THRESHOLD,
        false,
        Some(owner_replica_id),
        PROTECTED_SECRET_ID,
    );
    let mut replica_a = Peer::with_options(
        "replica-a",
        "https://replica-a.example.com",
        THRESHOLD,
        false,
        Some(replica_a_id),
        PROTECTED_SECRET_ID,
    );
    let mut replica_b = Peer::with_options(
        "replica-b",
        "https://replica-b.example.com",
        THRESHOLD,
        false,
        Some(replica_b_id),
        PROTECTED_SECRET_ID,
    );
    let mut replica_c = Peer::with_options(
        "replica-c",
        "https://replica-c.example.com",
        THRESHOLD,
        false,
        Some(replica_c_id),
        PROTECTED_SECRET_ID,
    );
    let mut helper_1 = Peer::with_options(
        "helper-1",
        "https://helper-1.example.com",
        THRESHOLD,
        false,
        None,
        PROTECTED_SECRET_ID,
    );
    let mut helper_2 = Peer::with_options(
        "helper-2",
        "https://helper-2.example.com",
        THRESHOLD,
        false,
        None,
        PROTECTED_SECRET_ID,
    );
    let mut helper_3 = Peer::with_options(
        "helper-3",
        "https://helper-3.example.com",
        THRESHOLD,
        false,
        None,
        PROTECTED_SECRET_ID,
    );

    // ── Step 0: brand-new instance ────────────────────────────────
    assert!(
        owner
            .protocol
            .user_secret_store
            .load_latest(PROTECTED_SECRET_ID)
            .await
            .unwrap()
            .is_none(),
        "step 0: a brand-new instance has no published secret snapshot"
    );
    println!("  step 0: user_secret_store latest = None  ✓");

    // ── Step 1: pair replica A → expect v=1 push to A ─────────────
    // Channel ids for each peer relationship — fixed up front so the
    // assertions can filter `ReplicaSecretReceived` events by channel id.
    let cid_a = ChannelId(1);
    let cid_b = ChannelId(3);
    let cid_c = ChannelId(8);
    let cid_h1 = ChannelId(11);
    let cid_h2 = ChannelId(12);
    let cid_h3 = ChannelId(13);

    // Replica destinations need the handshake to land, then the
    // fingerprint cross-confirmation, before the auto-publish fires.
    pair_replica_handshake(&mut owner, &mut replica_a, cid_a).await;
    cross_confirm_fingerprint(&mut owner, &mut replica_a, cid_a).await;
    let events =
        pump_many(&mut [&mut owner, &mut replica_a, &mut replica_b, &mut replica_c]).await;
    let received = find_replica_event(&events, cid_a)
        .expect("step 1: replica A must emit ReplicaSecretReceived");
    assert_eq!(received.version, 1, "step 1: replica A must receive v=1");
    assert_eq!(received.secret.helpers.len(), 0);
    assert_eq!(received.secret.secrets.len(), 0);
    assert_eq!(received.secret.replicas.len(), 1);
    assert_eq!(received.shares.len(), 0);
    assert_eq!(
        owner
            .protocol
            .user_secret_store
            .load_latest(PROTECTED_SECRET_ID)
            .await
            .unwrap()
            .map(|s| s.version),
        Some(1)
    );
    println!("  step 1: pair replica A → v=1, secret(h=0,s=0,r=1,shares=0)  ✓");

    // ── Step 2: ProtectSecret([s1]) → expect v=2 push to A ────────
    let s1 = UserSecret {
        id: vec![0x01],
        name: "secret-one".to_owned(),
        data: b"first-user-secret".to_vec(),
    };
    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![s1.clone()],
            description: Some("v=2 explicit publish".to_owned()),
        })
        .await
        .expect("ProtectSecret([s1]) failed");
    let events =
        pump_many(&mut [&mut owner, &mut replica_a, &mut replica_b, &mut replica_c]).await;
    let received = find_replica_event(&events, cid_a)
        .expect("step 2: replica A must emit ReplicaSecretReceived");
    assert_eq!(received.version, 2);
    assert_eq!(received.secret.helpers.len(), 0);
    assert_eq!(received.secret.secrets.len(), 1);
    assert_eq!(received.secret.secrets[0].data, s1.data);
    assert_eq!(received.secret.replicas.len(), 1);
    assert_eq!(received.shares.len(), 0);
    println!("  step 2: ProtectSecret([s1]) → v=2, secret(h=0,s=1,r=1,shares=0)  ✓");

    // ── Step 3: pair replica B → bootstrap; A also receives v=3 ───
    pair_replica_handshake(&mut owner, &mut replica_b, cid_b).await;
    cross_confirm_fingerprint(&mut owner, &mut replica_b, cid_b).await;
    let events =
        pump_many(&mut [&mut owner, &mut replica_a, &mut replica_b, &mut replica_c]).await;
    let received_a =
        find_replica_event(&events, cid_a).expect("step 3: A must observe v=3");
    let received_b =
        find_replica_event(&events, cid_b).expect("step 3: B must observe v=3 (bootstrap)");
    for (label, received) in [("A", &received_a), ("B", &received_b)] {
        assert_eq!(received.version, 3, "step 3: replica {label} receives v=3");
        assert_eq!(received.secret.helpers.len(), 0);
        assert_eq!(received.secret.secrets.len(), 1);
        assert_eq!(received.secret.secrets[0].data, s1.data);
        assert_eq!(received.secret.replicas.len(), 2);
        assert_eq!(received.shares.len(), 0);
    }
    println!("  step 3: pair replica B → v=3, secret(h=0,s=1,r=2,shares=0) on A+B  ✓");

    // ── Step 4: pair helper #1 → auto-publish v=4 (below threshold)
    helper_start_pair(&mut owner, &mut helper_1, cid_h1).await;
    let events = pump_many(&mut [
        &mut owner,
        &mut replica_a,
        &mut replica_b,
        &mut replica_c,
        &mut helper_1,
        &mut helper_2,
        &mut helper_3,
    ])
    .await;
    // helper-1 must not have stored anything (below threshold).
    assert!(
        !events.iter().any(|e| matches!(
            e,
            DeRecEvent::ShareStored { channel_id, .. } if *channel_id == cid_h1
        )),
        "step 4: helper-1 must not store a share (1 < threshold 3)"
    );
    for (label, cid) in [("A", cid_a), ("B", cid_b)] {
        let received = find_replica_event(&events, cid)
            .unwrap_or_else(|| panic!("step 4: replica {label} must observe v=4"));
        assert_eq!(received.version, 4);
        assert_eq!(received.secret.helpers.len(), 1);
        assert_eq!(received.secret.secrets.len(), 1);
        assert_eq!(received.secret.replicas.len(), 2);
        assert_eq!(received.shares.len(), 0, "below threshold, no shares");
    }
    println!("  step 4: pair helper #1 → v=4, secret(h=1,s=1,r=2,shares=0)  ✓");

    // ── Step 5: pair helper #2 → auto-publish v=5 ─────────────────
    helper_start_pair(&mut owner, &mut helper_2, cid_h2).await;
    let events = pump_many(&mut [
        &mut owner,
        &mut replica_a,
        &mut replica_b,
        &mut replica_c,
        &mut helper_1,
        &mut helper_2,
        &mut helper_3,
    ])
    .await;
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, DeRecEvent::ShareStored { .. })),
        "step 5: still below threshold, no helper stores a share"
    );
    let received_b =
        find_replica_event(&events, cid_b).expect("step 5: B must observe v=5");
    assert_eq!(received_b.version, 5);
    assert_eq!(received_b.secret.helpers.len(), 2);
    assert_eq!(received_b.shares.len(), 0);
    let _ = find_replica_event(&events, cid_a).expect("step 5: A must observe v=5");
    println!("  step 5: pair helper #2 → v=5, secret(h=2,s=1,r=2,shares=0)  ✓");

    // ── Step 6: ProtectSecret([s1, s2]) → v=6 ─────────────────────
    let s2 = UserSecret {
        id: vec![0x02],
        name: "secret-two".to_owned(),
        data: b"second-user-secret".to_vec(),
    };
    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![s1.clone(), s2.clone()],
            description: Some("v=6 explicit publish".to_owned()),
        })
        .await
        .expect("ProtectSecret([s1, s2]) failed");
    let events = pump_many(&mut [
        &mut owner,
        &mut replica_a,
        &mut replica_b,
        &mut replica_c,
        &mut helper_1,
        &mut helper_2,
        &mut helper_3,
    ])
    .await;
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, DeRecEvent::ShareStored { .. })),
        "step 6: still below threshold, no helper stores a share"
    );
    let received_a = find_replica_event(&events, cid_a).expect("step 6: A must see v=6");
    assert_eq!(received_a.version, 6);
    assert_eq!(received_a.secret.secrets.len(), 2);
    assert!(received_a.secret.secrets.iter().any(|us| us.data == s1.data));
    assert!(received_a.secret.secrets.iter().any(|us| us.data == s2.data));
    assert_eq!(received_a.secret.helpers.len(), 2);
    assert_eq!(received_a.shares.len(), 0);
    let _ = find_replica_event(&events, cid_b).expect("step 6: B must see v=6");
    println!("  step 6: ProtectSecret([s1, s2]) → v=6, secret(h=2,s=2,r=2,shares=0)  ✓");

    // ── Step 7: pair helper #3 → threshold met, VSS split ─────────
    helper_start_pair(&mut owner, &mut helper_3, cid_h3).await;
    let events = pump_many(&mut [
        &mut owner,
        &mut replica_a,
        &mut replica_b,
        &mut replica_c,
        &mut helper_1,
        &mut helper_2,
        &mut helper_3,
    ])
    .await;
    for (label, cid) in [("helper-1", cid_h1), ("helper-2", cid_h2), ("helper-3", cid_h3)] {
        assert!(
            events.iter().any(|e| matches!(
                e,
                DeRecEvent::ShareStored { channel_id, version: 7, .. } if *channel_id == cid
            )),
            "step 7: {label} must emit ShareStored at v=7"
        );
    }
    for (label, cid) in [("A", cid_a), ("B", cid_b)] {
        let received = find_replica_event(&events, cid)
            .unwrap_or_else(|| panic!("step 7: replica {label} must observe v=7"));
        assert_eq!(received.version, 7);
        assert_eq!(received.secret.helpers.len(), 3);
        assert_eq!(received.secret.secrets.len(), 2);
        assert_eq!(received.secret.replicas.len(), 2);
        assert_eq!(received.shares.len(), 3, "threshold met → 3 helper shares");
    }
    println!("  step 7: pair helper #3 → v=7, secret(h=3,s=2,r=2,shares=3); all 3 helpers ShareStored  ✓");

    // ── Step 8: pair replica C → full bootstrap + fresh helper VSS ─
    pair_replica_handshake(&mut owner, &mut replica_c, cid_c).await;
    cross_confirm_fingerprint(&mut owner, &mut replica_c, cid_c).await;
    let events = pump_many(&mut [
        &mut owner,
        &mut replica_a,
        &mut replica_b,
        &mut replica_c,
        &mut helper_1,
        &mut helper_2,
        &mut helper_3,
    ])
    .await;
    for (label, cid) in [("helper-1", cid_h1), ("helper-2", cid_h2), ("helper-3", cid_h3)] {
        assert!(
            events.iter().any(|e| matches!(
                e,
                DeRecEvent::ShareStored { channel_id, version: 8, .. } if *channel_id == cid
            )),
            "step 8: {label} must emit ShareStored at v=8 (fresh VSS round)"
        );
    }
    let received_c =
        find_replica_event(&events, cid_c).expect("step 8: replica C must observe v=8");
    assert_eq!(received_c.version, 8);
    assert_eq!(received_c.secret.helpers.len(), 3);
    assert_eq!(received_c.secret.secrets.len(), 2);
    assert_eq!(received_c.secret.replicas.len(), 3);
    assert_eq!(received_c.shares.len(), 3);
    for (label, cid) in [("A", cid_a), ("B", cid_b)] {
        let received = find_replica_event(&events, cid)
            .unwrap_or_else(|| panic!("step 8: replica {label} must observe v=8"));
        assert_eq!(received.version, 8);
        assert_eq!(received.secret.replicas.len(), 3);
    }
    println!(
        "  step 8: pair replica C → v=8, secret(h=3,s=2,r=3,shares=3) on A+B+C; all helpers refreshed  ✓"
    );

    println!("Protocol replica sync version progression flow test passed.");
}


/// Exercises the replica-group-key handover protocol.
///
/// All replica channels for a given `secret_id` must converge on a
/// single symmetric "group" key. The first replica pair on a fresh
/// Source defines K_group implicitly (its pair-handshake key IS the
/// group key); every subsequent newly-paired Destination starts on
/// an ephemeral pair-handshake key and is rotated to K_group during
/// its first `ProtectSecret` round via the
/// `ReplicaSecretPayload.shared_key` field.
///
/// Scenario:
///
/// 1. Source pairs Dest1 → K_group emerges as the Source↔Dest1 key.
/// 2. Source pairs Dest2 → on the verify_fingerprint auto-publish round,
///    Source's outbox carries one envelope encrypted with K_group (to
///    Dest1) and one encrypted with Dest2's K_ephemeral (to Dest2).
///    Dest2 receives the payload, swaps its stored key to K_group,
///    acks with K_group. After this round, all four channel entries
///    (Source→Dest1, Source→Dest2, Dest1's own, Dest2's own) hold
///    identical bytes.
/// 3. A follow-up `ProtectSecret` round encrypted with K_group reaches
///    Dest2 and is decrypted cleanly — proves the handover stuck.
async fn run_replica_group_key_handover_flow() {
    println!("=== Protocol replica group-key handover flow ===");

    // All three peers share the same `secret_id` — replica channel keys
    // are stored per `(secret_id, channel_id)`, so the handover assertion
    // queries on the receiver side must use the same partition the sender
    // wrote to.
    let sid = 0xBEEFu64;
    let owner_replica_id = 0xC0DE_C0DE_C0DE_C0DEu64;
    let dest1_replica_id = 0xD1D1_D1D1_D1D1_D1D1u64;
    let dest2_replica_id = 0xD2D2_D2D2_D2D2_D2D2u64;
    let dest1_channel = ChannelId(1);
    let dest2_channel = ChannelId(2);

    let mut source = Peer::with_secret_id_and_replica_id(
        "source",
        "https://source.example.com",
        sid,
        owner_replica_id,
    );
    let mut dest1 = Peer::with_options(
        "dest1",
        "https://dest1.example.com",
        2,
        false,
        Some(dest1_replica_id),
        sid,
    );
    let mut dest2 = Peer::with_options(
        "dest2",
        "https://dest2.example.com",
        2,
        false,
        Some(dest2_replica_id),
        sid,
    );

    // ── Step 1: pair Source↔Dest1; K_group implicitly emerges ────
    pair_replica_handshake(&mut source, &mut dest1, dest1_channel).await;
    cross_confirm_fingerprint(&mut source, &mut dest1, dest1_channel).await;
    let _ = pump_many(&mut [&mut source, &mut dest1, &mut dest2]).await;

    let k_after_pair_1 = load_channel_key(&source, sid, dest1_channel).await;
    let k_on_dest1 = load_channel_key(&dest1, sid, dest1_channel).await;
    assert_eq!(
        k_after_pair_1, k_on_dest1,
        "after pair 1: Source and Dest1 must hold the same channel key (the implicit K_group)"
    );
    let k_group = k_after_pair_1;
    println!("  step 1: pair Source↔Dest1 — K_group emerged, both sides agree  ✓");

    // ── Step 2: pair Source↔Dest2; handover round mutates Dest2's key ──
    pair_replica_handshake(&mut source, &mut dest2, dest2_channel).await;
    // Right after pair handshake (before verify_fingerprint triggers the
    // auto-publish round), both sides have stored a fresh K_ephemeral for
    // the new channel. The keys must NOT yet equal K_group.
    let k_ephemeral_source = load_channel_key(&source, sid, dest2_channel).await;
    let k_ephemeral_dest2 =
        load_channel_key(&dest2, sid, dest2_channel).await;
    assert_eq!(
        k_ephemeral_source, k_ephemeral_dest2,
        "post-handshake (pre-handover): Source and Dest2 must share the same ephemeral key"
    );
    assert_ne!(
        k_ephemeral_source, k_group,
        "post-handshake: Dest2's ephemeral key must NOT equal K_group yet"
    );

    cross_confirm_fingerprint(&mut source, &mut dest2, dest2_channel).await;
    let _ = pump_many(&mut [&mut source, &mut dest1, &mut dest2]).await;

    // After the handover round, every replica channel entry on both
    // sides must hold K_group.
    let k_source_dest1 = load_channel_key(&source, sid, dest1_channel).await;
    let k_source_dest2 = load_channel_key(&source, sid, dest2_channel).await;
    let k_dest1 = load_channel_key(&dest1, sid, dest1_channel).await;
    let k_dest2 = load_channel_key(&dest2, sid, dest2_channel).await;
    assert_eq!(k_source_dest1, k_group, "Source↔Dest1 must keep K_group");
    assert_eq!(
        k_source_dest2, k_group,
        "Source↔Dest2 must have rotated to K_group after the handover round"
    );
    assert_eq!(k_dest1, k_group, "Dest1 channel-key must equal K_group");
    assert_eq!(
        k_dest2, k_group,
        "Dest2 must have rotated its channel key to K_group via the StoreShareRequest.shared_key field"
    );
    println!("  step 2: pair Source↔Dest2 — Dest2 rotated K_ephemeral → K_group, all four entries match  ✓");

    // ── Step 3: post-handover round; must decrypt cleanly with K_group ──
    source
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![UserSecret {
                id: vec![0x42],
                name: "post-handover".to_owned(),
                data: b"k_group payload".to_vec(),
            }],
            description: Some("post-handover round".to_owned()),
        })
        .await
        .expect("source start(ProtectSecret) failed");
    let post_events = pump_many(&mut [&mut source, &mut dest1, &mut dest2]).await;

    let dest2_event = post_events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::ReplicaSecretReceived {
                channel_id: c,
                secret,
                ..
            } if *c == dest2_channel => Some(secret.clone()),
            _ => None,
        })
        .expect("Dest2 must observe ReplicaSecretReceived after the post-handover round");
    assert!(
        dest2_event
            .secrets
            .iter()
            .any(|us| us.data == b"k_group payload"),
        "Dest2 must successfully decrypt the post-handover payload using K_group"
    );

    // And on this round, since Dest2's stored key already equals K_group,
    // the envelope should carry an empty `replica_group_key` field in the
    // composite — Source's channel-key equals K_group so no handover.
    let k_source_dest2_final = load_channel_key(&source, sid, dest2_channel).await;
    assert_eq!(
        k_source_dest2_final, k_group,
        "K_group must remain stable across follow-up rounds (no spurious re-rotation)"
    );
    println!("  step 3: follow-up ProtectSecret round encrypted with K_group; Dest2 decrypted cleanly  ✓");

    println!("Protocol replica group-key handover flow test passed.");
}

/// Helper: load a channel's stored 32-byte `SharedKey` from a peer's
/// secret_store. Panics if missing — we only call this inside the
/// group-key flow after pairing/sync rounds have completed.
async fn load_channel_key(peer: &Peer, secret_id: u64, channel_id: ChannelId) -> [u8; 32] {
    use derec_library::protocol::DeRecSecretStore;
    let v = peer
        .protocol
        .secret_store
        .load(secret_id, channel_id, derec_library::protocol::SecretKind::SharedKey)
        .await
        .expect("secret_store.load failed")
        .expect("channel key must be present");
    match v {
        derec_library::protocol::SecretValue::SharedKey(k) => k,
        _ => panic!("expected SecretValue::SharedKey"),
    }
}

/// Drive only the cryptographic pair handshake between an Owner and
/// a ReplicaDestination. Stops at the `Pending` state — the caller
/// must call `cross_confirm_fingerprint` afterwards to trigger the
/// auto-publish on the Pending→Paired transition.
async fn pair_replica_handshake(owner: &mut Peer, replica: &mut Peer, channel_id: ChannelId) {
    let contact = owner
        .protocol
        .create_contact(Some(channel_id), derec_proto::ContactMode::InlineKeys)
        .await
        .expect("owner.create_contact failed");
    replica
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::ReplicaDestination,
            contact,
            peer_communication_info: std::collections::HashMap::new(),
        })
        .await
        .expect("replica start(Pairing, ReplicaDestination) failed");
    let _ = pump(replica, owner).await;
    let _ = pump(owner, replica).await;
}

async fn cross_confirm_fingerprint(owner: &mut Peer, replica: &mut Peer, channel_id: ChannelId) {
    let owner_fp = owner.protocol.get_fingerprint(channel_id).await.unwrap();
    let replica_fp = replica.protocol.get_fingerprint(channel_id).await.unwrap();
    assert_eq!(owner_fp, replica_fp);
    let ok_o = owner
        .protocol
        .verify_fingerprint(channel_id, &replica_fp)
        .await
        .unwrap();
    let ok_r = replica
        .protocol
        .verify_fingerprint(channel_id, &owner_fp)
        .await
        .unwrap();
    assert!(ok_o && ok_r, "cross-fingerprint verification must succeed");
}

/// Drive only the helper-side `start(Pairing { kind: Helper })`. The
/// surrounding `pump_many` (called after this) actually delivers the
/// PairRequest to the owner and routes everything to quiescence,
/// including the auto-publish fan-out to any paired Replicas.
async fn helper_start_pair(owner: &mut Peer, helper: &mut Peer, channel_id: ChannelId) {
    let contact = owner
        .protocol
        .create_contact(Some(channel_id), derec_proto::ContactMode::InlineKeys)
        .await
        .expect("owner.create_contact failed");
    helper
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::Helper,
            contact,
            peer_communication_info: std::collections::HashMap::new(),
        })
        .await
        .expect("helper start(Pairing) failed");
}

#[derive(Debug)]
struct ReceivedSecret {
    version: u32,
    secret: derec_library::protocol::types::Secret,
    shares: Vec<derec_library::protocol::types::ChannelShare>,
}

/// Look up the `ReplicaSecretReceived` event for the channel id and
/// return a typed view of its fields. Returns `None` if no event for
/// that channel was emitted in this pump.
fn find_replica_event(events: &[DeRecEvent], channel_id: ChannelId) -> Option<ReceivedSecret> {
    events.iter().find_map(|e| match e {
        DeRecEvent::ReplicaSecretReceived {
            channel_id: cid,
            version,
            secret,
            shares,
            ..
        } if *cid == channel_id => Some(ReceivedSecret {
            version: *version,
            secret: secret.clone(),
            shares: shares.clone(),
        }),
        _ => None,
    })
}

/// Drives a sharing round end-to-end with the Helper configured to
/// auto-accept `StoreShare` requests. Asserts that the Helper's event
/// stream contains `AutoAccepted` + `ShareStored` (no `ActionRequired`
/// for the sharing action) and that the Owner receives its
/// `ShareConfirmed` ack.
///
/// Note: pairing is still gated by `ActionRequired` because the
/// `AutoAcceptPolicy` only opts in to `store_share`. A real deployment
/// that wants the full chain automated would set
/// `AutoAcceptPolicy::all()` (or flip `pairing: true` explicitly) —
/// see the policy's rustdoc for the per-flow trade-offs.
async fn run_auto_accept_flow() {
    use derec_library::protocol::{AutoAcceptPolicy, PendingActionKind};

    println!("=== Protocol auto-accept flow test ===");

    let channel_a = ChannelId(1);
    let channel_b = ChannelId(2);
    let policy = AutoAcceptPolicy {
        store_share: true,
        ..Default::default()
    };

    let mut owner = Peer::with_secret_id("owner", "https://owner.example.com", 99);
    let mut helper_a =
        Peer::with_auto_accept("helper-a", "https://helper-a.example.com", policy);
    let mut helper_b =
        Peer::with_auto_accept("helper-b", "https://helper-b.example.com", policy);

    pair(&mut owner, &mut helper_a, channel_a).await;
    pair(&mut owner, &mut helper_b, channel_b).await;
    println!("Pairing complete — distributing a secret (helpers auto-accept StoreShare)");

    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secrets: vec![UserSecret {
                id: vec![1, 2, 3],
                name: "auto-accept smoke secret".to_owned(),
                data: b"auto-accepted-value".to_vec(),
            }],
            description: Some("auto-accept smoke".to_owned()),
        })
        .await
        .expect("owner start(ProtectSecret) failed");

    let events = pump_many(&mut [&mut owner, &mut helper_a, &mut helper_b]).await;

    let auto_accepted_count = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                DeRecEvent::AutoAccepted {
                    action_kind: PendingActionKind::StoreShare,
                    ..
                }
            )
        })
        .count();
    assert_eq!(
        auto_accepted_count, 2,
        "expected AutoAccepted{{StoreShare}} on both helpers (got {auto_accepted_count})"
    );

    let action_required_for_store_share = events.iter().any(|e| matches!(
        e,
        DeRecEvent::ActionRequired {
            action: derec_library::protocol::PendingAction::StoreShare { .. },
            ..
        }
    ));
    assert!(
        !action_required_for_store_share,
        "auto-accept should suppress ActionRequired{{StoreShare}}"
    );

    let stored_a = events
        .iter()
        .any(|e| matches!(e, DeRecEvent::ShareStored { channel_id: cid, .. } if *cid == channel_a));
    let stored_b = events
        .iter()
        .any(|e| matches!(e, DeRecEvent::ShareStored { channel_id: cid, .. } if *cid == channel_b));
    assert!(stored_a, "expected ShareStored on helper-a");
    assert!(stored_b, "expected ShareStored on helper-b");

    let confirmed = events
        .iter()
        .filter(|e| matches!(e, DeRecEvent::ShareConfirmed { .. }))
        .count();
    assert_eq!(
        confirmed, 2,
        "expected ShareConfirmed from both helpers (got {confirmed})"
    );

    println!("Protocol auto-accept flow test passed.");
}

/// Regression: `start(Pairing, Helper, fresh_contact)` on a channel
/// id that already finished pairing must error with
/// `Error::InvalidInput` rather than silently overwriting the
/// completed-pair state. Guards the defensive
/// `reject_start_on_paired_channel` check in
/// `handlers::pairing::start_inlined_keys` / `start_hashed_keys`.
async fn run_start_pairing_rejects_already_paired_channel() {
    use derec_library::protocol::types::ChannelStatus;
    use derec_library::protocol::AutoAcceptPolicy;

    println!("=== Protocol start(Pairing) rejects already-Paired channel ===");

    let channel_id = ChannelId(1000);
    let policy = AutoAcceptPolicy::all();
    let mut owner = Peer::with_auto_accept("owner", "https://owner.example.com", policy);
    let mut helper = Peer::with_auto_accept("helper", "https://helper.example.com", policy);

    // Phase 1: normal pairing → channel(Paired), SharedKey, no PairingSecret/PairingContact.
    pair(&mut owner, &mut helper, channel_id).await;
    let secret_id = helper.protocol.secret_id();

    let channel_post_pair = helper
        .protocol
        .channel_store
        .load(secret_id, channel_id)
        .await
        .expect("load")
        .expect("channel exists");
    assert_eq!(channel_post_pair.status, ChannelStatus::Paired);

    // Phase 2: ask owner for a NEW contact on the same channel_id and
    // try to re-run helper.start(Pairing). The defensive check at the
    // top of `start_inlined_keys` should refuse with
    // `Error::ChannelAlreadyPaired` rather than mutating local state.
    let fresh_contact = owner
        .protocol
        .create_contact(Some(channel_id), derec_proto::ContactMode::InlineKeys)
        .await
        .expect("owner.create_contact (round 2)");
    let result = helper
        .protocol
        .start(DeRecFlow::Pairing {
            kind: SenderKind::Helper,
            contact: fresh_contact,
            peer_communication_info: std::collections::HashMap::new(),
        })
        .await;

    match result {
        Err(derec_library::Error::ChannelAlreadyPaired { channel_id: cid }) => {
            assert_eq!(cid, channel_id, "ChannelAlreadyPaired must carry the offending channel id");
        }
        other => panic!(
            "expected Err(ChannelAlreadyPaired) on start(Pairing) for already-Paired channel; got {other:?}"
        ),
    }

    // State must be unchanged from after Phase 1.
    let channel_post_double_start = helper
        .protocol
        .channel_store
        .load(secret_id, channel_id)
        .await
        .expect("load")
        .expect("channel exists");
    let shared_key = helper
        .protocol
        .secret_store
        .load(secret_id, channel_id, SecretKind::SharedKey)
        .await
        .expect("load SharedKey");
    let pairing_secret = helper
        .protocol
        .secret_store
        .load(secret_id, channel_id, SecretKind::PairingSecret)
        .await
        .expect("load PairingSecret");
    let pairing_contact = helper
        .protocol
        .secret_store
        .load(secret_id, channel_id, SecretKind::PairingContact)
        .await
        .expect("load PairingContact");

    assert_eq!(
        channel_post_double_start.status,
        ChannelStatus::Paired,
        "channel.status must remain Paired after the rejected start"
    );
    assert!(shared_key.is_some(), "SharedKey must remain after the rejected start");
    assert!(
        pairing_secret.is_none(),
        "PairingSecret must remain absent after the rejected start"
    );
    assert!(
        pairing_contact.is_none(),
        "PairingContact must remain absent after the rejected start"
    );

    // Helper outbox must be empty: the rejected start must not have
    // queued a (now-stale) PairRequest envelope.
    let queued = helper.drain();
    assert!(
        queued.is_empty(),
        "rejected start must not queue any outbound envelope; got {} message(s)",
        queued.len()
    );

    println!("  helper.start(Pairing) on already-Paired channel → Err(ChannelAlreadyPaired), no state change  ✓");
    println!("Protocol start(Pairing) rejects already-Paired channel test passed.");
}
