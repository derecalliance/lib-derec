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
use crate::protocol::types::{
    ChannelQuery, ChannelRecord, HelperChannel, HelperFilter, MissingPolicy, ReplicaFilter,
    ReplicaMember, SecretKind, SecretValue, Share, UserSecrets,
};
use crate::protocol::{DeRecStateStore, StateItem, StateKey, StateKind, StateStoreFuture};
use crate::types::ChannelId;
use derec_proto::TransportProtocol;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Two maps, mirroring the two primary keys the trait defines, plus the
/// channel-link graph recovery walks.
#[derive(Default, Clone)]
pub(crate) struct InMemChannelStore {
    pub(crate) helper_rows: Arc<Mutex<HashMap<(u64, u64), HelperChannel>>>,
    pub(crate) member_rows: Arc<Mutex<HashMap<(u64, u64), ReplicaMember>>>,
    /// Undirected edges, stored both ways so a walk can start at either end.
    #[allow(clippy::type_complexity)]
    pub(crate) links: Arc<Mutex<HashMap<(u64, u64), Vec<u64>>>>,
    /// When set, `remove_many` fails and removes nothing.
    pub(crate) fail_remove_many: Arc<Mutex<bool>>,
}

impl DeRecChannelStore for InMemChannelStore {
    fn load(&self, sid: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
        let found = match query {
            ChannelQuery::Helper { channel_id } => self
                .helper_rows
                .lock()
                .unwrap()
                .get(&(sid, channel_id.0))
                .cloned()
                .map(ChannelRecord::Helper),
            ChannelQuery::Replica { replica_id, .. } => self
                .member_rows
                .lock()
                .unwrap()
                .get(&(sid, replica_id.0))
                .cloned()
                .map(ChannelRecord::Replica),
        };
        Box::pin(std::future::ready(Ok(found)))
    }

    fn save(&mut self, sid: u64, record: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
        match record {
            ChannelRecord::Helper(h) => {
                self.helper_rows
                    .lock()
                    .unwrap()
                    .insert((sid, h.channel_id.0), h);
            }
            ChannelRecord::Replica(r) => {
                self.member_rows
                    .lock()
                    .unwrap()
                    .insert((sid, r.replica_id.0), r);
            }
        }
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(&mut self, sid: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
        let removed = match query {
            ChannelQuery::Helper { channel_id } => self
                .helper_rows
                .lock()
                .unwrap()
                .remove(&(sid, channel_id.0))
                .is_some(),
            ChannelQuery::Replica { replica_id, .. } => self
                .member_rows
                .lock()
                .unwrap()
                .remove(&(sid, replica_id.0))
                .is_some(),
        };
        Box::pin(std::future::ready(Ok(removed)))
    }
    fn remove_many(&mut self, sid: u64, queries: &[ChannelQuery]) -> ChannelStoreFuture<'_, ()> {
        if *self.fail_remove_many.lock().unwrap() {
            return Box::pin(std::future::ready(Err(
                crate::protocol::ChannelStoreError::Backend("channel store unavailable".into()),
            )));
        }
        let mut helpers = self.helper_rows.lock().unwrap();
        let mut members = self.member_rows.lock().unwrap();
        for query in queries {
            match *query {
                ChannelQuery::Helper { channel_id } => {
                    helpers.remove(&(sid, channel_id.0));
                }
                ChannelQuery::Replica { replica_id, .. } => {
                    members.remove(&(sid, replica_id.0));
                }
            }
        }
        Box::pin(std::future::ready(Ok(())))
    }

    fn helpers(
        &self,
        sid: u64,
        filter: HelperFilter,
    ) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
        let v: Vec<HelperChannel> = self
            .helper_rows
            .lock()
            .unwrap()
            .iter()
            .filter(|((s, _), _)| *s == sid)
            .map(|(_, c)| c.clone())
            .filter(|c| filter.matches(&c.channel_id, c.status, &c.peer_role))
            .collect();
        Box::pin(std::future::ready(Ok(v)))
    }

    fn replicas(
        &self,
        sid: u64,
        filter: ReplicaFilter,
    ) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
        let v: Vec<ReplicaMember> = self
            .member_rows
            .lock()
            .unwrap()
            .iter()
            .filter(|((s, _), _)| *s == sid)
            .map(|(_, m)| m.clone())
            .filter(|m| filter.matches(&m.replica_id, m.status, &m.role))
            .collect();
        Box::pin(std::future::ready(Ok(v)))
    }

    fn link_channel(&mut self, sid: u64, a: ChannelId, b: ChannelId) -> ChannelStoreFuture<'_, ()> {
        let mut links = self.links.lock().unwrap();
        for (from, to) in [(a.0, b.0), (b.0, a.0)] {
            let edges = links.entry((sid, from)).or_default();
            if !edges.contains(&to) {
                edges.push(to);
            }
        }
        drop(links);
        Box::pin(std::future::ready(Ok(())))
    }

    /// Transitive closure including the start node — the same walk a SQL
    /// store expresses with a recursive CTE. Returning only `[cid]`, as this
    /// used to, makes a multi-channel recovery unrepresentable in tests.
    fn linked_channels(&self, sid: u64, cid: ChannelId) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
        let links = self.links.lock().unwrap();
        let mut seen = vec![cid.0];
        let mut queue = vec![cid.0];
        while let Some(node) = queue.pop() {
            for next in links.get(&(sid, node)).into_iter().flatten() {
                if !seen.contains(next) {
                    seen.push(*next);
                    queue.push(*next);
                }
            }
        }
        drop(links);
        Box::pin(std::future::ready(Ok(seen
            .into_iter()
            .map(ChannelId)
            .collect())))
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
        missing_policy: MissingPolicy,
    ) -> SecretStoreFuture<'_, Vec<(ChannelId, SecretValue)>> {
        let data = self.data.lock().unwrap();
        let mut out = Vec::new();
        let mut missing = Vec::new();
        for c in cids {
            match data.get(&(sid, c.0, kind as u8)) {
                Some(v) => out.push((*c, v.clone())),
                None => missing.push(c.0),
            }
        }
        drop(data);
        if missing_policy == MissingPolicy::Fail && !missing.is_empty() {
            return Box::pin(std::future::ready(Err(
                crate::protocol::SecretStoreError::MissingEntries {
                    kind,
                    channel_ids: missing,
                },
            )));
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
    fn remove_many(
        &mut self,
        sid: u64,
        entries: &[(ChannelId, SecretKind)],
    ) -> SecretStoreFuture<'_, ()> {
        let mut data = self.data.lock().unwrap();
        for &(cid, kind) in entries {
            data.remove(&(sid, cid.0, kind as u8));
        }
        Box::pin(std::future::ready(Ok(())))
    }
}

#[derive(Default, Clone)]
pub(crate) struct InMemShareStore {
    #[allow(clippy::type_complexity)]
    pub(crate) data: Arc<Mutex<HashMap<(u64, u64, u32), Share>>>,
    /// What [`DeRecShareStore::keep_version`] answers on every call; when
    /// unset it answers `version - 1`, the version distributed before.
    pub(crate) keep: Arc<Mutex<Option<u32>>>,
    /// Every `(secret_id, version)` [`DeRecShareStore::keep_version`] was
    /// asked about, in call order.
    pub(crate) keep_version_calls: Arc<Mutex<Vec<(u64, u32)>>>,
    /// When set, every [`DeRecShareStore::keep_version`] fails with a backend
    /// error.
    pub(crate) keep_version_error: Arc<Mutex<bool>>,
    /// How many times the single-channel [`DeRecShareStore::load`] and the
    /// bulk [`DeRecShareStore::load_many`] were called.
    pub(crate) load_calls: Arc<Mutex<usize>>,
    pub(crate) load_many_calls: Arc<Mutex<usize>>,
    /// How many times [`DeRecShareStore::remove_versions_many`] was called.
    pub(crate) remove_versions_many_calls: Arc<Mutex<usize>>,
    /// When set, every [`DeRecShareStore::load_many`] fails with a backend
    /// error.
    pub(crate) fail_load_many: Arc<Mutex<bool>>,
}

impl InMemShareStore {
    /// The shares under `sid` on `cids` at `versions` (every version when
    /// empty), with their channels, ordered by version then channel.
    fn select(&self, sid: u64, cids: &[ChannelId], versions: &[u32]) -> Vec<(ChannelId, Share)> {
        let wanted: Vec<u64> = cids.iter().map(|c| c.0).collect();
        let lock = self.data.lock().unwrap();
        let mut out: Vec<(ChannelId, Share)> = lock
            .iter()
            .filter(|((s, c, v), _)| {
                *s == sid && wanted.contains(c) && (versions.is_empty() || versions.contains(v))
            })
            .map(|((_, c, _), share)| (ChannelId(*c), share.clone()))
            .collect();
        out.sort_by_key(|(c, share)| (share.version, c.0));
        out
    }
}

impl DeRecShareStore for InMemShareStore {
    fn load(&self, sid: u64, cid: ChannelId, versions: &[u32]) -> ShareStoreFuture<'_, Vec<Share>> {
        *self.load_calls.lock().unwrap() += 1;
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
    /// Ordered by `(version, channel_id)`. A store backed by a real database
    /// returns rows in whatever order the plan produces, so a caller that
    /// depends on which row arrives first is depending on something no store
    /// guarantees; a deterministic mock is what makes that dependence
    /// reproducible in a test instead of intermittent in production.
    fn load_many(
        &self,
        sid: u64,
        cids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<(ChannelId, Share)>> {
        *self.load_many_calls.lock().unwrap() += 1;
        if *self.fail_load_many.lock().unwrap() {
            return Box::pin(std::future::ready(Err(
                crate::protocol::ShareStoreError::Backend("share store backend unavailable".into()),
            )));
        }
        Box::pin(std::future::ready(Ok(self.select(sid, cids, versions))))
    }
    fn load_all(&self, sid: u64, cids: &[ChannelId]) -> ShareStoreFuture<'_, Vec<Share>> {
        Box::pin(std::future::ready(Ok(self
            .select(sid, cids, &[])
            .into_iter()
            .map(|(_, share)| share)
            .collect())))
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
    fn remove_versions(
        &mut self,
        sid: u64,
        cid: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, ()> {
        self.data
            .lock()
            .unwrap()
            .retain(|(s, c, v), _| !(*s == sid && *c == cid.0 && versions.contains(v)));
        Box::pin(std::future::ready(Ok(())))
    }
    fn remove_versions_many(
        &mut self,
        sid: u64,
        entries: &[(ChannelId, Vec<u32>)],
    ) -> ShareStoreFuture<'_, ()> {
        *self.remove_versions_many_calls.lock().unwrap() += 1;
        self.data.lock().unwrap().retain(|(s, c, v), _| {
            !(*s == sid
                && entries
                    .iter()
                    .any(|(cid, versions)| *c == cid.0 && versions.contains(v)))
        });
        Box::pin(std::future::ready(Ok(())))
    }
    fn keep_version(&self, sid: u64, version: u32) -> ShareStoreFuture<'_, u32> {
        self.keep_version_calls.lock().unwrap().push((sid, version));
        if *self.keep_version_error.lock().unwrap() {
            return Box::pin(std::future::ready(Err(
                crate::protocol::ShareStoreError::Backend(
                    "share store backend unavailable".to_owned().into(),
                ),
            )));
        }
        let keep = self
            .keep
            .lock()
            .unwrap()
            .unwrap_or(version.saturating_sub(1));
        Box::pin(std::future::ready(Ok(keep)))
    }
}

/// An in-memory share store that can be told to refuse (or fail) the
/// next `save` and/or `record_verification`, for exercising
/// [`crate::protocol::ShareStoreError::Refused`] and ordinary backend
/// failures through the `sharing`/`verification` handlers without a
/// bespoke store per test.
#[derive(Default, Clone)]
pub(crate) struct RefusingShareStore {
    pub(crate) inner: InMemShareStore,
    save_refusal: Arc<Mutex<Option<crate::protocol::Refusal>>>,
    save_backend_error: Arc<Mutex<bool>>,
    verification_refusal: Arc<Mutex<Option<crate::protocol::Refusal>>>,
    verification_backend_error: Arc<Mutex<bool>>,
    /// Every `(secret_id, channel_id, version)` `record_verification` was
    /// called with, in call order.
    #[allow(clippy::type_complexity)]
    verification_calls: Arc<Mutex<Vec<(u64, ChannelId, u32)>>>,
}

impl RefusingShareStore {
    pub(crate) fn set_refusal(&self, refusal: Option<crate::protocol::Refusal>) {
        *self.save_refusal.lock().unwrap() = refusal;
    }

    pub(crate) fn set_backend_error(&self, fail: bool) {
        *self.save_backend_error.lock().unwrap() = fail;
    }

    pub(crate) fn set_verification_refusal(&self, refusal: Option<crate::protocol::Refusal>) {
        *self.verification_refusal.lock().unwrap() = refusal;
    }

    pub(crate) fn set_verification_backend_error(&self, fail: bool) {
        *self.verification_backend_error.lock().unwrap() = fail;
    }

    pub(crate) fn verification_calls(&self) -> Vec<(u64, ChannelId, u32)> {
        self.verification_calls.lock().unwrap().clone()
    }
}

impl DeRecShareStore for RefusingShareStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        self.inner.load(secret_id, channel_id, versions)
    }
    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<(ChannelId, Share)>> {
        self.inner.load_many(secret_id, channel_ids, versions)
    }
    fn load_all(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        self.inner.load_all(secret_id, channel_ids)
    }
    fn latest_version(&self, secret_id: u64) -> ShareStoreFuture<'_, Option<u32>> {
        self.inner.latest_version(secret_id)
    }
    fn save(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        share: Share,
    ) -> ShareStoreFuture<'_, ()> {
        if let Some(refusal) = *self.save_refusal.lock().unwrap() {
            return Box::pin(std::future::ready(Err(
                crate::protocol::ShareStoreError::Refused(refusal),
            )));
        }
        if *self.save_backend_error.lock().unwrap() {
            return Box::pin(std::future::ready(Err(
                crate::protocol::ShareStoreError::Backend(
                    "share store backend unavailable".to_owned().into(),
                ),
            )));
        }
        self.inner.save(secret_id, channel_id, share)
    }
    fn remove_channel(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ShareStoreFuture<'_, ()> {
        self.inner.remove_channel(secret_id, channel_id)
    }
    fn remove_versions(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, ()> {
        self.inner.remove_versions(secret_id, channel_id, versions)
    }
    fn remove_versions_many(
        &mut self,
        secret_id: u64,
        entries: &[(ChannelId, Vec<u32>)],
    ) -> ShareStoreFuture<'_, ()> {
        self.inner.remove_versions_many(secret_id, entries)
    }
    fn keep_version(&self, secret_id: u64, version: u32) -> ShareStoreFuture<'_, u32> {
        self.inner.keep_version(secret_id, version)
    }
    fn record_verification(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
        version: u32,
    ) -> ShareStoreFuture<'_, ()> {
        self.verification_calls
            .lock()
            .unwrap()
            .push((secret_id, channel_id, version));
        if let Some(refusal) = *self.verification_refusal.lock().unwrap() {
            return Box::pin(std::future::ready(Err(
                crate::protocol::ShareStoreError::Refused(refusal),
            )));
        }
        if *self.verification_backend_error.lock().unwrap() {
            return Box::pin(std::future::ready(Err(
                crate::protocol::ShareStoreError::Backend(
                    "share store backend unavailable".to_owned().into(),
                ),
            )));
        }
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
    fn remove_many(&mut self, _: u64, _: &[StateKey]) -> StateStoreFuture<'_, ()> {
        Box::pin(std::future::ready(Ok(())))
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
    /// How many times `load_all` was asked for each kind.
    pub(crate) load_all_calls: Arc<Mutex<HashMap<StateKind, usize>>>,
    /// When set, every `save`, `remove` and `remove_many` fails with a
    /// backend error and changes nothing.
    pub(crate) fail_writes: Arc<Mutex<bool>>,
    /// How many times `remove_many` was called.
    pub(crate) remove_many_calls: Arc<Mutex<usize>>,
}
impl InMemPersistedStateStore {
    fn refused<T: Send + 'static>(&self) -> Option<StateStoreFuture<'_, T>> {
        (*self.fail_writes.lock().unwrap()).then(|| -> StateStoreFuture<'_, T> {
            Box::pin(std::future::ready(Err(
                crate::protocol::StateStoreError::Backend("state store backend unavailable".into()),
            )))
        })
    }
}
impl DeRecStateStore for InMemPersistedStateStore {
    fn save(&mut self, sid: u64, item: StateItem) -> StateStoreFuture<'_, ()> {
        if let Some(refused) = self.refused() {
            return refused;
        }
        self.data.lock().unwrap().insert((sid, item.key()), item);
        Box::pin(std::future::ready(Ok(())))
    }
    fn load(&self, sid: u64, key: StateKey) -> StateStoreFuture<'_, Option<StateItem>> {
        let v = self.data.lock().unwrap().get(&(sid, key)).cloned();
        Box::pin(std::future::ready(Ok(v)))
    }
    fn remove(&mut self, sid: u64, key: StateKey) -> StateStoreFuture<'_, bool> {
        if let Some(refused) = self.refused() {
            return refused;
        }
        let removed = self.data.lock().unwrap().remove(&(sid, key)).is_some();
        Box::pin(std::future::ready(Ok(removed)))
    }
    fn remove_many(&mut self, sid: u64, keys: &[StateKey]) -> StateStoreFuture<'_, ()> {
        *self.remove_many_calls.lock().unwrap() += 1;
        if let Some(refused) = self.refused() {
            return refused;
        }
        let mut data = self.data.lock().unwrap();
        for key in keys {
            data.remove(&(sid, key.clone()));
        }
        Box::pin(std::future::ready(Ok(())))
    }
    fn load_all(&self, sid: u64, kind: StateKind) -> StateStoreFuture<'_, Vec<StateItem>> {
        *self.load_all_calls.lock().unwrap().entry(kind).or_default() += 1;
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
    fn send(&self, _: &[TransportProtocol], _: Vec<u8>) -> TransportFuture<'_> {
        Box::pin(std::future::ready(Ok(())))
    }
}

/// Transport double whose every send fails, standing in for a peer that
/// has gone away — the expected condition when a recovering device tears
/// down its ephemeral channels.
#[derive(Default, Clone)]
pub(crate) struct FailingTransport;
impl DeRecTransport for FailingTransport {
    fn send(&self, _: &[TransportProtocol], _: Vec<u8>) -> TransportFuture<'_> {
        Box::pin(std::future::ready(Err(crate::Error::InvalidInput(
            "transport unreachable",
        ))))
    }
}

/// Transport double that records every outbound `(endpoint, envelope)`
/// in send order, so a test can assert both *that* a message went out
/// and *what* it carried.
#[derive(Default, Clone)]
pub(crate) struct RecordingTransport {
    /// Every send, as the library handed it over: the peer's full endpoint
    /// set, in the peer's order, plus the envelope. Recording the whole set
    /// rather than one endpoint is what lets a test tell "the library offered
    /// both" from "the library narrowed to one".
    #[allow(clippy::type_complexity)]
    pub(crate) sent: Arc<Mutex<Vec<(Vec<TransportProtocol>, Vec<u8>)>>>,
}
impl RecordingTransport {
    /// Endpoint URIs of everything sent so far, in send order.
    pub(crate) fn sent_uris(&self) -> Vec<String> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(endpoints, _)| endpoints[0].uri.clone())
            .collect()
    }
    /// Every endpoint offered on each send, in the peer's order.
    pub(crate) fn sent_endpoint_sets(&self) -> Vec<Vec<TransportProtocol>> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(endpoints, _)| endpoints.clone())
            .collect()
    }

    /// Forget every envelope sent so far.
    pub(crate) fn clear(&self) {
        self.sent.lock().unwrap().clear();
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
    fn send(&self, endpoints: &[TransportProtocol], bytes: Vec<u8>) -> TransportFuture<'_> {
        assert!(
            !endpoints.is_empty(),
            "the library must never send to a peer with no endpoints"
        );
        self.sent.lock().unwrap().push((endpoints.to_vec(), bytes));
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

/// Owns one of each store double so a test can hand a handler the whole
/// [`Stores`] bundle while asserting on only the one or two it cares about.
///
/// Handlers take every store regardless of which they use, so a test that
/// exercises one store would otherwise have to spell out five it does not.
/// The type parameters default to the in-memory doubles and are named
/// individually so a test needing a bespoke double — one that fails on
/// demand, or answers a fixed row — substitutes just that slot.
pub(crate) struct StoreRig<
    Ch = InMemChannelStore,
    Sh = InMemShareStore,
    Ss = InMemSecretStore,
    Us = InMemUserSecretStore,
    St = InMemPersistedStateStore,
    T = RecordingTransport,
> {
    pub(crate) channels: Ch,
    pub(crate) shares: Sh,
    pub(crate) secrets: Ss,
    pub(crate) user_secrets: Us,
    pub(crate) state: St,
    pub(crate) transport: T,
}

impl<Ch, Sh, Ss, Us, St, T> Default for StoreRig<Ch, Sh, Ss, Us, St, T>
where
    Ch: Default,
    Sh: Default,
    Ss: Default,
    Us: Default,
    St: Default,
    T: Default,
{
    fn default() -> Self {
        Self {
            channels: Ch::default(),
            shares: Sh::default(),
            secrets: Ss::default(),
            user_secrets: Us::default(),
            state: St::default(),
            transport: T::default(),
        }
    }
}

impl StoreRig {
    /// A rig of the stock doubles.
    ///
    /// `Rig::default()` cannot serve here: a struct's type-parameter defaults
    /// apply in type position only, so inference has nothing to fix the six
    /// slots to. Naming `Rig` as this `impl`'s self type does apply them.
    pub(crate) fn new() -> Self {
        Self::default()
    }
}

impl<T>
    StoreRig<
        InMemChannelStore,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        T,
    >
{
    /// Stock doubles everywhere but the transport, for a test that cares
    /// what the transport does (or refuses to do).
    pub(crate) fn with_transport(transport: T) -> Self {
        Self {
            channels: InMemChannelStore::default(),
            shares: InMemShareStore::default(),
            secrets: InMemSecretStore::default(),
            user_secrets: InMemUserSecretStore::default(),
            state: InMemPersistedStateStore::default(),
            transport,
        }
    }
}

impl<Ch>
    StoreRig<
        Ch,
        InMemShareStore,
        InMemSecretStore,
        InMemUserSecretStore,
        InMemPersistedStateStore,
        RecordingTransport,
    >
{
    /// Stock doubles everywhere but the channel store, for a test that
    /// needs it to answer a fixed row or fail on demand.
    pub(crate) fn with_channels(channels: Ch) -> Self {
        Self {
            channels,
            shares: InMemShareStore::default(),
            secrets: InMemSecretStore::default(),
            user_secrets: InMemUserSecretStore::default(),
            state: InMemPersistedStateStore::default(),
            transport: RecordingTransport::default(),
        }
    }
}

impl<Ch, Sh, Ss, Us, St, T> StoreRig<Ch, Sh, Ss, Us, St, T>
where
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    St: DeRecStateStore,
    T: DeRecTransport,
{
    /// Borrow every slot as the bundle a handler takes.
    pub(crate) fn stores(
        &mut self,
    ) -> crate::protocol::stores::Stores<'_, crate::protocol::stores::Set<Ch, Sh, Ss, Us, St, T>>
    {
        crate::protocol::stores::Stores::new(
            &mut self.channels,
            &mut self.shares,
            &mut self.secrets,
            &mut self.user_secrets,
            &mut self.state,
            &self.transport,
        )
    }
}

/// Owns what a [`Local`] borrows, so a test can hand one to a handler.
///
/// [`Local`] holds `own_transports` by reference, so something has to own the
/// list; a bare `Local` literal in a test would borrow a temporary.
///
/// [`Local`]: crate::protocol::context::Local
pub(crate) struct LocalFixture {
    pub(crate) secret_id: u64,
    pub(crate) replica_id: Option<u64>,
    pub(crate) own_transports: Vec<TransportProtocol>,
    pub(crate) policy: crate::transport::TransportPolicy,
    pub(crate) communication_info: std::collections::HashMap<String, String>,
    pub(crate) parameter_range: Option<derec_proto::ParameterRange>,
}

impl LocalFixture {
    /// A helper-role instance reachable on one stock HTTPS endpoint.
    pub(crate) fn new(secret_id: u64) -> Self {
        Self {
            secret_id,
            replica_id: None,
            own_transports: vec![TransportProtocol {
                uri: "https://self.example".to_owned(),
                protocol: derec_proto::Protocol::Https as i32,
            }],
            policy: crate::transport::TransportPolicy::new(false),
            communication_info: std::collections::HashMap::new(),
            parameter_range: None,
        }
    }

    /// The same, participating in replica flows under `replica_id`.
    pub(crate) fn with_replica(secret_id: u64, replica_id: u64) -> Self {
        Self {
            replica_id: Some(replica_id),
            ..Self::new(secret_id)
        }
    }

    /// The same, enforcing `range` as this device's helper-side share-size
    /// limits.
    pub(crate) fn with_parameter_range(secret_id: u64, range: derec_proto::ParameterRange) -> Self {
        Self {
            parameter_range: Some(range),
            ..Self::new(secret_id)
        }
    }

    pub(crate) fn local(&self) -> crate::protocol::context::Local<'_> {
        crate::protocol::context::Local {
            secret_id: self.secret_id,
            replica_id: self.replica_id,
            own_transports: &self.own_transports,
            policy: self.policy,
            communication_info: &self.communication_info,
            parameter_range: self.parameter_range.as_ref(),
        }
    }
}

/// A `DeRecShare` in the layout used before 0.0.9: `encryptedSecret = 1`,
/// `x = 2`, `y = 3`, `secretId = 4`, `version = 5`. The current schema reads
/// field 3 as `secretId`, a varint, so these bytes no longer decode.
pub(crate) fn pre_0_0_9_derec_share(secret_id: u64, version: u32) -> Vec<u8> {
    use prost::encoding::{bytes, uint32, uint64};
    let mut buf = pre_0_0_9_fields_before_y();
    bytes::encode(3, &vec![0x02_u8; 48], &mut buf);
    uint64::encode(4, &secret_id, &mut buf);
    uint32::encode(5, &version, &mut buf);
    buf
}

/// Fields 1 and 2 of [`pre_0_0_9_derec_share`]. The old `x` (field 2) holds
/// bytes that also parse as a current `Subshare`, so the only field that
/// can fail to decode is the old `y` (field 3).
pub(crate) fn pre_0_0_9_fields_before_y() -> Vec<u8> {
    use prost::encoding::bytes;
    let mut buf = Vec::new();
    bytes::encode(1, &vec![0xAB_u8; 4], &mut buf);
    let x = derec_proto::de_rec_share::Subshare {
        x: vec![0x01; 48],
        y: vec![0x03; 48],
    };
    bytes::encode(2, &prost::Message::encode_to_vec(&x), &mut buf);
    buf
}
