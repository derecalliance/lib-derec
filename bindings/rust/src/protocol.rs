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
    DeRecProtocolBuilder, DeRecSecretStore, DeRecShareStore, DeRecTransport, MissingPolicy,
    SecretKind, SecretStoreError, SecretStoreFuture, SecretValue, Share, ShareStoreFuture,
    TransportFuture,
};
use derec_library::types::{Channel, ChannelId, Target, UserSecret};
use derec_proto::{Protocol, SenderKind, TransportProtocol};

pub fn run_all() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("failed to build tokio runtime");

    rt.block_on(run_pairing_flow());
    rt.block_on(run_sharing_flow());
    rt.block_on(run_discovery_and_recovery_flow());
    rt.block_on(run_unpairing_flow());
    rt.block_on(run_update_channel_info_flow());
    rt.block_on(run_reply_to_flow());
}


/// Stores paired channels plus the channel-link graph (channels belonging to
/// the same Owner identity, e.g. after a recovery re-pairing). The link graph
/// is a bidirectional adjacency list; `linked_channels` is a BFS over it.
#[derive(Default)]
struct InMemoryChannelStore {
    data: HashMap<u64, Channel>,
    links: HashMap<u64, HashSet<u64>>,
}

impl DeRecChannelStore for InMemoryChannelStore {
    fn load(&self, channel_id: ChannelId) -> ChannelStoreFuture<'_, Option<Channel>> {
        let result = self.data.get(&channel_id.0).cloned();
        Box::pin(std::future::ready(Ok(result)))
    }

    fn save(&mut self, channel: Channel) -> ChannelStoreFuture<'_, ()> {
        self.data.insert(channel.id.0, channel);
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(&mut self, channel_id: ChannelId) -> ChannelStoreFuture<'_, bool> {
        let removed = self.data.remove(&channel_id.0).is_some();
        Box::pin(std::future::ready(Ok(removed)))
    }

    fn channels(&self) -> ChannelStoreFuture<'_, Vec<Channel>> {
        let entries: Vec<Channel> = self.data.values().cloned().collect();
        Box::pin(std::future::ready(Ok(entries)))
    }

    fn link_channel(&mut self, a: ChannelId, b: ChannelId) -> ChannelStoreFuture<'_, ()> {
        let (a, b) = (a.0, b.0);
        if a != b {
            self.links.entry(a).or_default().insert(b);
            self.links.entry(b).or_default().insert(a);
        }
        Box::pin(std::future::ready(Ok(())))
    }

    fn linked_channels(&self, channel_id: ChannelId) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
        // BFS over the link graph; the start node is included so an unlinked
        // channel returns just itself.
        let mut visited: HashSet<u64> = HashSet::new();
        let mut queue: VecDeque<u64> = VecDeque::new();
        queue.push_back(channel_id.0);

        while let Some(curr) = queue.pop_front() {
            if !visited.insert(curr) {
                continue;
            }
            if let Some(neighbors) = self.links.get(&curr) {
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
    data: HashMap<(u64, u8), SecretValue>,
}

impl DeRecSecretStore for InMemorySecretStore {
    fn load(
        &self,
        channel_id: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>> {
        let result = self
            .data
            .get(&(channel_id.0, kind as u8))
            .map(clone_secret_value);
        Box::pin(std::future::ready(Ok(result)))
    }

    fn load_many(
        &self,
        channel_ids: &[ChannelId],
        kind: SecretKind,
        missing_policy: MissingPolicy,
    ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
        let k = kind as u8;
        let mut result: Vec<(ChannelId, SecretValue)> = Vec::with_capacity(channel_ids.len());
        let mut missing: Vec<u64> = Vec::new();
        for cid in channel_ids {
            match self.data.get(&(cid.0, k)) {
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

    fn save(&mut self, channel_id: ChannelId, value: SecretValue) -> SecretStoreFuture<'_, ()> {
        let kind = match &value {
            SecretValue::SharedKey(_) => SecretKind::SharedKey as u8,
            SecretValue::PairingSecret(_) => SecretKind::PairingSecret as u8,
            SecretValue::PairingContact(_) => SecretKind::PairingContact as u8,
        };
        self.data.insert((channel_id.0, kind), value);
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(&mut self, channel_id: ChannelId, kind: SecretKind) -> SecretStoreFuture<'_, ()> {
        self.data.remove(&(channel_id.0, kind as u8));
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
        channel_id: ChannelId,
        secret_id: u64,
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
        channel_ids: &[ChannelId],
        secret_id: u64,
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

    fn load_all(&self, channel_ids: &[ChannelId]) -> ShareStoreFuture<'_, Vec<Share>> {
        let cid_set: HashSet<u64> = channel_ids.iter().map(|c| c.0).collect();
        let result: Vec<Share> = self
            .data
            .iter()
            .filter(|((c, _, _), _)| cid_set.contains(c))
            .map(|(_, s)| s.clone())
            .collect();
        Box::pin(std::future::ready(Ok(result)))
    }

    fn latest_version(&self) -> ShareStoreFuture<'_, Option<u32>> {
        let max = self.data.keys().map(|(_, _, v)| *v).max();
        Box::pin(std::future::ready(Ok(max)))
    }

    fn save(&mut self, channel_id: ChannelId, share: Share) -> ShareStoreFuture<'_, ()> {
        let key = (channel_id.0, share.secret_id, share.version);
        self.data.insert(key, share);
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove_channel(&mut self, channel_id: ChannelId) -> ShareStoreFuture<'_, ()> {
        let cid = channel_id.0;
        self.data.retain(|(c, _, _), _| *c != cid);
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
        Self::with_options(label, uri, threshold, false)
    }

    /// Same as [`Peer::new`] but flips `with_auto_reply_to(true)` on the
    /// builder so every outbound request stamps `replyTo = own_transport`.
    fn with_auto_reply_to(label: &'static str, uri: &str) -> Self {
        Self::with_options(label, uri, 2, true)
    }

    fn with_options(label: &'static str, uri: &str, threshold: usize, auto_reply_to: bool) -> Self {
        let transport = InProcessTransport::new();
        let protocol = DeRecProtocolBuilder::new()
            .with_channel_store(InMemoryChannelStore::default())
            .with_share_store(InMemoryShareStore::default())
            .with_secret_store(InMemorySecretStore::default())
            .with_transport(transport.clone())
            .with_own_transport(TransportProtocol {
                uri: uri.to_owned(),
                protocol: Protocol::Https.into(),
            })
            .with_threshold(threshold)
            .with_auto_reply_to(auto_reply_to)
            .build();

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
        .create_contact(Some(channel_id))
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

    let owner_channel = owner
        .protocol
        .channel_store
        .load(channel_id)
        .await
        .expect("owner channel_store.load failed");
    let helper_channel = helper
        .protocol
        .channel_store
        .load(channel_id)
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


async fn run_sharing_flow() {
    println!("=== Protocol sharing flow test ===");

    let channel_a = ChannelId(1);
    let channel_b = ChannelId(2);
    let mut owner = Peer::new("owner", "https://owner.example.com");
    let mut helper_a = Peer::new("helper-a", "https://helper-a.example.com");
    let mut helper_b = Peer::new("helper-b", "https://helper-b.example.com");

    pair(&mut owner, &mut helper_a, channel_a).await;
    pair(&mut owner, &mut helper_b, channel_b).await;
    println!("Pairing complete — distributing a secret (threshold=2, helpers=2)");

    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secret_id: 42,
            target: Target::Many(vec![channel_a, channel_b]),
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
    let vault_secret_id: u64 = 7777;
    let secret_data = b"correct horse battery staple".to_vec();

    // VSS sharing requires threshold ≥ 2, so the discovery+recovery scenario
    // pairs the Owner with two helpers and reconstructs from both shares.
    let mut owner = Peer::new("owner", "https://owner.example.com");
    let mut helper_a = Peer::new("helper-a", "https://helper-a.example.com");
    let mut helper_b = Peer::new("helper-b", "https://helper-b.example.com");


    pair(&mut owner, &mut helper_a, channel_a).await;
    pair(&mut owner, &mut helper_b, channel_b).await;
    println!("Initial pairing complete on channels {channel_a:?} and {channel_b:?}.");

    owner
        .protocol
        .start(DeRecFlow::ProtectSecret {
            secret_id: vault_secret_id,
            target: Target::Many(vec![channel_a, channel_b]),
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
    for (helper, fresh_cid, label) in [
        (&mut helper_a, recovery_channel_a, "helper-a"),
        (&mut helper_b, recovery_channel_b, "helper-b"),
    ] {
        let recovery_contact = owner
            .protocol
            .create_contact(Some(fresh_cid))
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
    helper_a
        .protocol
        .channel_store
        .link_channel(channel_a, recovery_channel_a)
        .await
        .expect("helper-a link_channel failed");
    helper_b
        .protocol
        .channel_store
        .link_channel(channel_b, recovery_channel_b)
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
        .remove(channel_a)
        .await
        .expect("owner remove(channel_a) failed");
    owner
        .protocol
        .channel_store
        .remove(channel_b)
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
        .find(|e| e.secret_id == vault_secret_id)
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
        "Owner discovered secret_id={vault_secret_id} v{recover_version} across {} helper(s); recovering.",
        discovered.len()
    );


    owner
        .protocol
        .start(DeRecFlow::RecoverSecret {
            secret_id: vault_secret_id,
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

    // The reconstructed payload is the encoded secret bag; assert the original
    // secret bytes round-trip inside it.
    assert!(
        contains_subslice(&recovered, &secret_data),
        "recovered secret bag must contain the original secret bytes"
    );
    println!("Owner successfully reconstructed the secret.");

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

    let owner_channel = owner
        .protocol
        .channel_store
        .load(channel_id)
        .await
        .expect("owner channel_store.load failed");
    let helper_channel = helper
        .protocol
        .channel_store
        .load(channel_id)
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
    owner.protocol.set_own_transport(TransportProtocol {
        uri: new_uri.clone(),
        protocol: Protocol::Https.into(),
    });
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
    let helper_channel = helper
        .protocol
        .channel_store
        .load(channel_id)
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

    // --- Half 1: auto_reply_to populates request.reply_to on outbound ----
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
    let SecretValue::SharedKey(shared_key) = owner
        .protocol
        .secret_store
        .load(channel_id, SecretKind::SharedKey)
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

    // --- Half 2: responder routes to inbound replyTo (not stored endpoint) -
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
