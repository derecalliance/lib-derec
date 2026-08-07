// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! In-memory store and transport doubles shared across `protocol` unit tests.
//!
//! Every double keeps its inner data behind `Arc<Mutex<...>>` so a test can
//! hold a clone, pre-seed state before the protocol is built (the protocol
//! owns the impl, so the only post-construction mutation path is through the
//! trait), and inspect the persisted state afterwards.

use crate::protocol::traits::{
    ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecTransport,
    DeRecUserSecretStore, SecretStoreFuture, ShareStoreFuture, TransportFuture,
};
use crate::protocol::types::{Channel, MissingPolicy, SecretKind, SecretValue, Share, UserSecrets};
use crate::protocol::{DeRecStateStore, StateItem, StateKey, StateKind, StateStoreFuture};
use crate::types::ChannelId;
use derec_proto::TransportProtocol;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Default, Clone)]
pub(crate) struct InMemChannelStore {
    pub(crate) data: Arc<Mutex<HashMap<(u64, u64), Channel>>>,
}

impl DeRecChannelStore for InMemChannelStore {
    fn load(&self, sid: u64, cid: ChannelId) -> ChannelStoreFuture<'_, Option<Channel>> {
        let v = self.data.lock().unwrap().get(&(sid, cid.0)).cloned();
        Box::pin(std::future::ready(Ok(v)))
    }
    fn save(&mut self, sid: u64, c: Channel) -> ChannelStoreFuture<'_, ()> {
        self.data.lock().unwrap().insert((sid, c.id.0), c);
        Box::pin(std::future::ready(Ok(())))
    }
    fn remove(&mut self, sid: u64, cid: ChannelId) -> ChannelStoreFuture<'_, bool> {
        let removed = self.data.lock().unwrap().remove(&(sid, cid.0)).is_some();
        Box::pin(std::future::ready(Ok(removed)))
    }
    fn channels(&self, sid: u64) -> ChannelStoreFuture<'_, Vec<Channel>> {
        let v: Vec<Channel> = self
            .data
            .lock()
            .unwrap()
            .iter()
            .filter(|((s, _), _)| *s == sid)
            .map(|(_, c)| c.clone())
            .collect();
        Box::pin(std::future::ready(Ok(v)))
    }
    fn link_channel(&mut self, _: u64, _: ChannelId, _: ChannelId) -> ChannelStoreFuture<'_, ()> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn linked_channels(&self, _: u64, cid: ChannelId) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
        Box::pin(std::future::ready(Ok(vec![cid])))
    }
}

#[derive(Default, Clone)]
pub(crate) struct InMemSecretStore {
    #[allow(clippy::type_complexity)]
    pub(crate) data: Arc<Mutex<HashMap<(u64, u64, u8), SecretValue>>>,
}

impl DeRecSecretStore for InMemSecretStore {
    fn load(
        &self,
        sid: u64,
        cid: ChannelId,
        kind: SecretKind,
    ) -> SecretStoreFuture<'_, Option<SecretValue>> {
        let v = self
            .data
            .lock()
            .unwrap()
            .get(&(sid, cid.0, kind as u8))
            .cloned();
        Box::pin(std::future::ready(Ok(v)))
    }
    fn load_many(
        &self,
        sid: u64,
        cids: &[ChannelId],
        kind: SecretKind,
        _: MissingPolicy,
    ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
        let mut out = Vec::new();
        for c in cids {
            if let Some(v) = self.data.lock().unwrap().get(&(sid, c.0, kind as u8)) {
                out.push((*c, v.clone()));
            }
        }
        Box::pin(std::future::ready(Ok(out)))
    }
    fn save(&mut self, sid: u64, cid: ChannelId, value: SecretValue) -> SecretStoreFuture<'_, ()> {
        let k = match &value {
            SecretValue::SharedKey(_) => SecretKind::SharedKey as u8,
            SecretValue::PairingSecret(_) => SecretKind::PairingSecret as u8,
            SecretValue::PairingContact(_) => SecretKind::PairingContact as u8,
        };
        self.data.lock().unwrap().insert((sid, cid.0, k), value);
        Box::pin(std::future::ready(Ok(())))
    }
    fn remove(&mut self, sid: u64, cid: ChannelId, kind: SecretKind) -> SecretStoreFuture<'_, ()> {
        self.data.lock().unwrap().remove(&(sid, cid.0, kind as u8));
        Box::pin(std::future::ready(Ok(())))
    }
}

#[derive(Default, Clone)]
pub(crate) struct InMemShareStore {
    #[allow(clippy::type_complexity)]
    pub(crate) data: Arc<Mutex<HashMap<(u64, u64, u32), Share>>>,
}

impl DeRecShareStore for InMemShareStore {
    fn load(&self, sid: u64, cid: ChannelId, versions: &[u32]) -> ShareStoreFuture<'_, Vec<Share>> {
        let lock = self.data.lock().unwrap();
        let out: Vec<Share> = lock
            .iter()
            .filter(|((s, c, v), _)| {
                *s == sid && *c == cid.0 && (versions.is_empty() || versions.contains(v))
            })
            .map(|(_, s)| s.clone())
            .collect();
        Box::pin(std::future::ready(Ok(out)))
    }
    fn load_many(&self, _: u64, _: &[ChannelId], _: &[u32]) -> ShareStoreFuture<'_, Vec<Share>> {
        Box::pin(std::future::ready(Ok(Vec::new())))
    }
    fn load_all(&self, _: u64, _: &[ChannelId]) -> ShareStoreFuture<'_, Vec<Share>> {
        Box::pin(std::future::ready(Ok(Vec::new())))
    }
    fn latest_version(&self, _: u64) -> ShareStoreFuture<'_, Option<u32>> {
        Box::pin(std::future::ready(Ok(None)))
    }
    fn save(&mut self, sid: u64, cid: ChannelId, share: Share) -> ShareStoreFuture<'_, ()> {
        let v = share.version;
        self.data.lock().unwrap().insert((sid, cid.0, v), share);
        Box::pin(std::future::ready(Ok(())))
    }
    fn remove_channel(&mut self, _: u64, _: ChannelId) -> ShareStoreFuture<'_, ()> {
        Box::pin(std::future::ready(Ok(())))
    }
}

#[derive(Default, Clone)]
pub(crate) struct InMemUserSecretStore {
    pub(crate) data: Arc<Mutex<HashMap<u64, UserSecrets>>>,
}

impl DeRecUserSecretStore for InMemUserSecretStore {
    fn load_latest(&self, sid: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
        let v = self.data.lock().unwrap().get(&sid).cloned();
        Box::pin(std::future::ready(Ok(v)))
    }
    fn save_latest(&mut self, sid: u64, value: UserSecrets) -> ShareStoreFuture<'_, ()> {
        self.data.lock().unwrap().insert(sid, value);
        Box::pin(std::future::ready(Ok(())))
    }
    fn remove(&mut self, sid: u64) -> ShareStoreFuture<'_, ()> {
        self.data.lock().unwrap().remove(&sid);
        Box::pin(std::future::ready(Ok(())))
    }
}

/// State store double that persists nothing — every load resolves empty.
#[derive(Default, Clone)]
pub(crate) struct InMemStateStore;
impl DeRecStateStore for InMemStateStore {
    fn save(&mut self, _: u64, _: StateItem) -> StateStoreFuture<'_, ()> {
        Box::pin(std::future::ready(Ok(())))
    }
    fn load(&self, _: u64, _: StateKey) -> StateStoreFuture<'_, Option<StateItem>> {
        Box::pin(std::future::ready(Ok(None)))
    }
    fn remove(&mut self, _: u64, _: StateKey) -> StateStoreFuture<'_, bool> {
        Box::pin(std::future::ready(Ok(false)))
    }
    fn load_all(&self, _: u64, _: StateKind) -> StateStoreFuture<'_, Vec<StateItem>> {
        Box::pin(std::future::ready(Ok(Vec::new())))
    }
}

/// State store double that actually persists, keyed by
/// `(secret_id, StateKey)` — the partitioning the trait contract
/// specifies. Tests that assert *which* partition a row landed in need
/// this; [`InMemStateStore`] cannot answer that question.
#[derive(Default, Clone)]
pub(crate) struct InMemPersistedStateStore {
    #[allow(clippy::type_complexity)]
    pub(crate) data: Arc<Mutex<HashMap<(u64, StateKey), StateItem>>>,
}
impl DeRecStateStore for InMemPersistedStateStore {
    fn save(&mut self, sid: u64, item: StateItem) -> StateStoreFuture<'_, ()> {
        self.data.lock().unwrap().insert((sid, item.key()), item);
        Box::pin(std::future::ready(Ok(())))
    }
    fn load(&self, sid: u64, key: StateKey) -> StateStoreFuture<'_, Option<StateItem>> {
        let v = self.data.lock().unwrap().get(&(sid, key)).cloned();
        Box::pin(std::future::ready(Ok(v)))
    }
    fn remove(&mut self, sid: u64, key: StateKey) -> StateStoreFuture<'_, bool> {
        let removed = self.data.lock().unwrap().remove(&(sid, key)).is_some();
        Box::pin(std::future::ready(Ok(removed)))
    }
    fn load_all(&self, sid: u64, kind: StateKind) -> StateStoreFuture<'_, Vec<StateItem>> {
        let v: Vec<StateItem> = self
            .data
            .lock()
            .unwrap()
            .iter()
            .filter(|((s, k), _)| *s == sid && k.kind() == kind)
            .map(|(_, i)| i.clone())
            .collect();
        Box::pin(std::future::ready(Ok(v)))
    }
}

#[derive(Default, Clone)]
pub(crate) struct NoopTransport;
impl DeRecTransport for NoopTransport {
    fn send(&self, _: &TransportProtocol, _: Vec<u8>) -> TransportFuture<'_> {
        Box::pin(std::future::ready(Ok(())))
    }
}

/// Transport double that records every outbound `(endpoint, envelope)`
/// in send order, so a test can assert both *that* a message went out
/// and *what* it carried.
#[derive(Default, Clone)]
pub(crate) struct RecordingTransport {
    #[allow(clippy::type_complexity)]
    pub(crate) sent: Arc<Mutex<Vec<(TransportProtocol, Vec<u8>)>>>,
}
impl RecordingTransport {
    /// Endpoint URIs of everything sent so far, in send order.
    pub(crate) fn sent_uris(&self) -> Vec<String> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(t, _)| t.uri.clone())
            .collect()
    }
    /// Raw envelopes sent so far, in send order.
    pub(crate) fn sent_envelopes(&self) -> Vec<Vec<u8>> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(_, b)| b.clone())
            .collect()
    }
}
impl DeRecTransport for RecordingTransport {
    fn send(&self, endpoint: &TransportProtocol, bytes: Vec<u8>) -> TransportFuture<'_> {
        self.sent.lock().unwrap().push((endpoint.clone(), bytes));
        Box::pin(std::future::ready(Ok(())))
    }
}

/// Drive an async test body to completion on a fresh current-thread runtime.
pub(crate) fn run_async<F: std::future::Future<Output = ()>>(f: F) {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime")
        .block_on(f)
}
