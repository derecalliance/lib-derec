// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! A peer that keeps **no** protocol state between operations.
//!
//! [`crate::peer::Peer`] holds one long-lived `DeRecProtocol` for the whole
//! test, which is how an embedded application would use the library. A service
//! deployed as serverless functions cannot: each invocation starts with an
//! empty process, builds whatever it needs, answers, and exits.
//!
//! [`StatelessPeer`] models that. It owns no protocol — only the things that
//! genuinely outlive an invocation:
//!
//! - the **database**, which is the application's entire memory;
//! - the **wire**, since a message already sent is not un-sent by the sender
//!   restarting;
//! - **configuration** (`secret_id`, threshold, `replica_id`, endpoint), which
//!   in a real deployment comes from environment or config, not from RAM.
//!
//! Every operation goes through [`StatelessPeer::session`], which builds a
//! fresh protocol over fresh stores, and drops it when the operation returns.
//! Anything the library needs to remember across operations therefore has to
//! be in Postgres — which is precisely what this harness exists to prove.
//!
//! One invocation covers `process()` plus the `accept()` calls for the actions
//! it returned: that is a single inbound message being handled end to end, the
//! natural unit of work for one function invocation. A `start()` initiated by
//! the user is its own invocation.

use std::sync::atomic::{AtomicUsize, Ordering};

use derec_library::protocol::{AutoAcceptPolicy, DeRecEvent, DeRecProtocolBuilder, PendingAction};
use derec_proto::TransportProtocol;

use crate::db::SharedClient;
use crate::peer::{PeerOptions, PostgresProtocol};
use crate::stores::{
    PostgresChannelStore, PostgresSecretStore, PostgresShareStore, PostgresStateStore,
    PostgresUserSecretStore,
};
use crate::transport::InProcessTransport;

pub struct StatelessPeer {
    pub label: String,
    pub uri: String,
    client: SharedClient,
    /// The wire. Deliberately outside the protocol: a message handed to the
    /// transport has left the building, and rebuilding the protocol must not
    /// recall it.
    transport: InProcessTransport,
    options: PeerOptions,
    /// Round/unpair timeout in seconds, when the scenario needs a shorter one
    /// than the library default. `None` leaves the default in place.
    timeout_in_secs: Option<u64>,
    auto_accept: AutoAcceptPolicy,
    /// How many protocol instances this peer has built. Every one is a
    /// simulated invocation; the count is asserted on so the test cannot
    /// silently regress into holding a single instance.
    ///
    /// Atomic rather than a `Cell` so the peer is `Sync`, which is what lets
    /// one be shared behind an `Arc` and driven from several request handlers
    /// at once — the shape a real service has.
    invocations: AtomicUsize,
}

impl StatelessPeer {
    pub fn new(client: SharedClient, label: &str, uri: &str, options: PeerOptions) -> Self {
        Self {
            label: label.to_owned(),
            uri: uri.to_owned(),
            client,
            transport: InProcessTransport::new(),
            options,
            timeout_in_secs: None,
            auto_accept: AutoAcceptPolicy::default(),
            invocations: AtomicUsize::new(0),
        }
    }

    /// Swap in a different database, keeping identity, endpoint and the wire.
    ///
    /// Models an application whose local storage is gone — a reinstall, a
    /// wiped device, a re-provisioned instance — while the user and their
    /// endpoint are unchanged. This is the starting condition for recovery.
    pub fn reinstall(&mut self, client: SharedClient) {
        self.client = client;
    }

    /// Give this peer a replica identity it did not have before.
    ///
    /// `replica_id` is application-assigned, so a device that acquires one
    /// later — a recovered device rejoining its group, for instance — is an
    /// ordinary configuration change, not a protocol event.
    #[allow(dead_code)]
    pub fn set_replica_id(&mut self, replica_id: u64) {
        self.options.replica_id = Some(replica_id);
    }

    pub fn client(&self) -> SharedClient {
        self.client.clone()
    }

    /// Shorten this peer's timeout window. Ordinary configuration — in a real
    /// deployment it comes from config, not from code — so it takes effect on
    /// the next session like every other option.
    pub fn set_timeout(&mut self, secs: u64) {
        self.timeout_in_secs = Some(secs);
    }

    #[allow(dead_code)]
    pub fn secret_id(&self) -> u64 {
        self.options.secret_id
    }

    pub fn invocations(&self) -> usize {
        self.invocations.load(Ordering::Relaxed)
    }

    /// Build a protocol for exactly one operation.
    ///
    /// The returned value is expected to be dropped before the next
    /// operation. Nothing carries over except what was written to Postgres.
    pub fn session(&self) -> PostgresProtocol {
        self.invocations.fetch_add(1, Ordering::Relaxed);

        let mut builder = DeRecProtocolBuilder::new(self.options.secret_id)
            .with_channel_store(PostgresChannelStore::new(self.client.clone()))
            .with_share_store(PostgresShareStore::new(self.client.clone()))
            .with_secret_store(PostgresSecretStore::new(self.client.clone()))
            .with_user_secret_store(PostgresUserSecretStore::new(self.client.clone()))
            .with_state_store(PostgresStateStore::new(self.client.clone()))
            .with_transport(self.transport.clone())
            .with_own_transport(self.uri.as_str())
            .with_threshold(self.options.threshold)
            .with_auto_accept(self.auto_accept);
        if let Some(secs) = self.timeout_in_secs {
            // Only the liveness budgets are shortened. `inbound_message` is the
            // staleness window every message is judged against and stays at the
            // default — narrowing it here would start discarding the scenario's
            // own traffic rather than closing rounds faster.
            builder = builder.with_timeouts(derec_library::protocol::types::Timeouts {
                sharing_round: std::time::Duration::from_secs(secs),
                unpair_ack: std::time::Duration::from_secs(secs),
                ..Default::default()
            });
        }
        if let Some(rid) = self.options.replica_id {
            builder = builder.with_replica_id(rid);
        }
        builder
            .build()
            .unwrap_or_else(|e| panic!("[{}] builder.build() failed: {e}", self.label))
    }

    pub fn drain(&self) -> Vec<(TransportProtocol, Vec<u8>)> {
        self.transport.drain()
    }
}

/// Handle one inbound message: build a protocol, `process`, `accept` every
/// action it raised, drop the protocol.
///
/// The accepts share the invocation because they are the same unit of work —
/// one message arriving and being answered. Each `accept` still runs against
/// state re-read from Postgres, because the action carries only what the
/// library handed back.
pub async fn deliver(peer: &StatelessPeer, bytes: &[u8]) -> Vec<DeRecEvent> {
    try_deliver(peer, bytes)
        .await
        .unwrap_or_else(|e| panic!("[{}] process() failed: {e}", peer.label))
}

/// As [`deliver`], but surfacing the error instead of panicking.
///
/// A deployed endpoint receives whatever is sent to it, including replies to
/// channels it has already torn down, so `process()` returning an error is
/// ordinary operation rather than a fault. See
/// [`pump_tolerating_stale`] for where that arises by design.
pub async fn try_deliver(peer: &StatelessPeer, bytes: &[u8]) -> Result<Vec<DeRecEvent>, String> {
    let mut protocol = peer.session();

    let mut collected = protocol.process(bytes).await.map_err(|e| e.to_string())?;

    let mut i = 0;
    while i < collected.len() {
        let action: Option<PendingAction> =
            match std::mem::replace(&mut collected[i], DeRecEvent::NoOp) {
                DeRecEvent::ActionRequired { action, .. } => Some(action),
                other => {
                    collected[i] = other;
                    None
                }
            };
        if let Some(action) = action {
            let mut accept_events = protocol
                .accept(action)
                .await
                .unwrap_or_else(|e| panic!("[{}] accept() failed: {e}", peer.label));
            collected.append(&mut accept_events);
        }
        i += 1;
    }

    Ok(collected)
}

/// Route every queued message to its destination peer until the wire is
/// quiet, delivering each through its own invocation.
///
/// Takes shared references so a whole cast of peers can be pumped without
/// fighting the borrow checker; the mutable state lives in Postgres, which is
/// the point.
pub async fn pump(peers: &[&StatelessPeer]) -> Vec<DeRecEvent> {
    let mut all_events = Vec::new();
    loop {
        let mut in_flight: Vec<(usize, Vec<u8>)> = Vec::new();
        for (src, peer) in peers.iter().enumerate() {
            let _ = src;
            for (endpoint, bytes) in peer.drain() {
                let dest = peers
                    .iter()
                    .position(|p| p.uri == endpoint.uri)
                    .unwrap_or_else(|| {
                        let known: Vec<&str> = peers.iter().map(|p| p.uri.as_str()).collect();
                        panic!(
                            "no peer for destination uri {} (have {})",
                            endpoint.uri,
                            known.join(", ")
                        )
                    });
                in_flight.push((dest, bytes));
            }
        }
        if in_flight.is_empty() {
            break;
        }
        for (dest, bytes) in in_flight {
            all_events.extend(deliver(peers[dest], &bytes).await);
        }
    }
    all_events
}

/// Error text produced when a message arrives for a channel whose keys are
/// gone. Matched rather than swallowed wholesale so the harness still fails on
/// every other kind of processing error.
const STALE_CHANNEL: &str = "unknown channel_id";

/// As [`pump`], but counting — rather than failing on — replies that arrive
/// for a channel the recipient has already torn down.
///
/// `restore()` forces `UnpairAck::NotRequired` when it scraps the
/// recovery-mode channels, deliberately: waiting for acknowledgements would
/// leave those channels alive and indistinguishable from canonical ones, and
/// the next publish would double-send to every helper. The consequence is that
/// each helper still answers, and those answers reach an owner that no longer
/// holds the key.
///
/// A deployed service must absorb exactly this, so the harness does too —
/// while returning the count, so the test can assert it saw the number of
/// stale replies it expected and no more.
pub async fn pump_tolerating_stale(peers: &[&StatelessPeer]) -> (Vec<DeRecEvent>, usize) {
    let mut all_events = Vec::new();
    let mut stale = 0usize;
    loop {
        let mut in_flight: Vec<(usize, Vec<u8>)> = Vec::new();
        for peer in peers.iter() {
            for (endpoint, bytes) in peer.drain() {
                let dest = peers
                    .iter()
                    .position(|p| p.uri == endpoint.uri)
                    .unwrap_or_else(|| panic!("no peer for destination uri {}", endpoint.uri));
                in_flight.push((dest, bytes));
            }
        }
        if in_flight.is_empty() {
            break;
        }
        for (dest, bytes) in in_flight {
            match try_deliver(peers[dest], &bytes).await {
                Ok(events) => all_events.extend(events),
                Err(e) if e.contains(STALE_CHANNEL) => stale += 1,
                Err(e) => panic!("[{}] process() failed: {e}", peers[dest].label),
            }
        }
    }
    (all_events, stale)
}
