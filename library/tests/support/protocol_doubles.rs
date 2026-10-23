// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! In-memory store and transport doubles for tests that drive a built
//! `DeRecProtocol` through the public API.
//!
//! Every double keeps its inner data behind `Arc<Mutex<...>>` so a test can
//! hold a clone, pre-seed state before the protocol is built (the protocol
//! owns the impl, so the only post-construction mutation path is through the
//! trait), and inspect the persisted state afterwards. Each one can also be
//! told to fail a chosen operation, for exercising backend failures at a
//! chosen step.

#![allow(dead_code)]

use derec_library::protocol::types::{
    ChannelQuery, ChannelRecord, HelperChannel, HelperFilter, MissingPolicy, ReplicaFilter,
    ReplicaMember, SecretKind, SecretValue, Share, UserSecrets,
};
use derec_library::protocol::{
    ChannelStoreError, ChannelStoreFuture, DeRecChannelStore, DeRecSecretStore, DeRecShareStore,
    DeRecStateStore, DeRecTransport, DeRecUserSecretStore, SecretStoreError, SecretStoreFuture,
    ShareStoreError, ShareStoreFuture, StateItem, StateKey, StateKind, StateStoreFuture,
    TransportFuture,
};
use derec_library::types::ChannelId;
use derec_proto::TransportProtocol;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Two maps, mirroring the two primary keys the trait defines, plus the
/// channel-link graph recovery walks.
#[derive(Default, Clone)]
pub struct InMemChannelStore {
    pub helper_rows: Arc<Mutex<HashMap<(u64, u64), HelperChannel>>>,
    pub member_rows: Arc<Mutex<HashMap<(u64, u64), ReplicaMember>>>,
    /// Undirected edges, stored both ways so a walk can start at either end.
    #[allow(clippy::type_complexity)]
    pub links: Arc<Mutex<HashMap<(u64, u64), Vec<u64>>>>,
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
    /// store expresses with a recursive CTE.
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

/// A channel store that can be told to fail its point reads, its writes or
/// its removals.
#[derive(Default, Clone)]
pub struct FlakyChannelStore {
    pub inner: InMemChannelStore,
    fail_load: Arc<Mutex<bool>>,
    fail_save: Arc<Mutex<bool>>,
    fail_remove: Arc<Mutex<bool>>,
    /// Loads left before the one that fails, when set.
    fail_one_load_after: Arc<Mutex<Option<usize>>>,
}

impl FlakyChannelStore {
    /// Let `n` point reads succeed, fail the next one, and succeed again
    /// from then on.
    pub fn fail_one_load_after(&self, n: usize) {
        *self.fail_one_load_after.lock().unwrap() = Some(n);
    }

    pub fn set_fail_load(&self, fail: bool) {
        *self.fail_load.lock().unwrap() = fail;
    }

    pub fn set_fail_save(&self, fail: bool) {
        *self.fail_save.lock().unwrap() = fail;
    }

    pub fn set_fail_remove(&self, fail: bool) {
        *self.fail_remove.lock().unwrap() = fail;
    }
}

fn channel_backend_error<T: Send + 'static>() -> ChannelStoreFuture<'static, T> {
    Box::pin(std::future::ready(Err(ChannelStoreError::Backend(
        "channel store unavailable".into(),
    ))))
}

impl DeRecChannelStore for FlakyChannelStore {
    fn load(&self, sid: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, Option<ChannelRecord>> {
        if *self.fail_load.lock().unwrap() {
            return channel_backend_error();
        }
        {
            let mut countdown = self.fail_one_load_after.lock().unwrap();
            match *countdown {
                Some(0) => {
                    *countdown = None;
                    return channel_backend_error();
                }
                Some(n) => *countdown = Some(n - 1),
                None => {}
            }
        }
        self.inner.load(sid, query)
    }
    fn save(&mut self, sid: u64, record: ChannelRecord) -> ChannelStoreFuture<'_, ()> {
        if *self.fail_save.lock().unwrap() {
            return channel_backend_error();
        }
        self.inner.save(sid, record)
    }
    fn remove(&mut self, sid: u64, query: ChannelQuery) -> ChannelStoreFuture<'_, bool> {
        if *self.fail_remove.lock().unwrap() {
            return channel_backend_error();
        }
        self.inner.remove(sid, query)
    }
    fn helpers(
        &self,
        sid: u64,
        filter: HelperFilter,
    ) -> ChannelStoreFuture<'_, Vec<HelperChannel>> {
        self.inner.helpers(sid, filter)
    }
    fn replicas(
        &self,
        sid: u64,
        filter: ReplicaFilter,
    ) -> ChannelStoreFuture<'_, Vec<ReplicaMember>> {
        self.inner.replicas(sid, filter)
    }
    fn link_channel(&mut self, sid: u64, a: ChannelId, b: ChannelId) -> ChannelStoreFuture<'_, ()> {
        self.inner.link_channel(sid, a, b)
    }
    fn linked_channels(&self, sid: u64, cid: ChannelId) -> ChannelStoreFuture<'_, Vec<ChannelId>> {
        self.inner.linked_channels(sid, cid)
    }
}

#[derive(Default, Clone)]
pub struct InMemSecretStore {
    #[allow(clippy::type_complexity)]
    pub data: Arc<Mutex<HashMap<(u64, u64, u8), SecretValue>>>,
    /// A kind whose removal fails, for exercising a backend failure after a
    /// response was sent.
    fail_remove: Arc<Mutex<Option<SecretKind>>>,
}

impl InMemSecretStore {
    pub fn set_fail_remove(&self, kind: Option<SecretKind>) {
        *self.fail_remove.lock().unwrap() = kind;
    }
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
            return Box::pin(std::future::ready(Err(SecretStoreError::MissingEntries {
                kind,
                channel_ids: missing,
            })));
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
        if *self.fail_remove.lock().unwrap() == Some(kind) {
            return Box::pin(std::future::ready(Err(SecretStoreError::Backend(
                "secret store unavailable".into(),
            ))));
        }
        self.data.lock().unwrap().remove(&(sid, cid.0, kind as u8));
        Box::pin(std::future::ready(Ok(())))
    }
}

#[derive(Default, Clone)]
pub struct InMemShareStore {
    #[allow(clippy::type_complexity)]
    pub data: Arc<Mutex<HashMap<(u64, u64, u32), Share>>>,
    /// What [`DeRecShareStore::keep_list`] answers on every call.
    pub keep: Arc<Mutex<Option<Vec<u32>>>>,
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
    /// Ordered by `(version, channel_id)`, so a caller that depends on which
    /// row arrives first fails reproducibly rather than intermittently.
    fn load_many(
        &self,
        sid: u64,
        cids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        let wanted: Vec<u64> = cids.iter().map(|c| c.0).collect();
        let lock = self.data.lock().unwrap();
        let mut out: Vec<(u64, Share)> = lock
            .iter()
            .filter(|((s, c, v), _)| {
                *s == sid && wanted.contains(c) && (versions.is_empty() || versions.contains(v))
            })
            .map(|((_, c, _), share)| (*c, share.clone()))
            .collect();
        out.sort_by_key(|(c, share)| (share.version, *c));
        Box::pin(std::future::ready(Ok(out
            .into_iter()
            .map(|(_, share)| share)
            .collect())))
    }
    fn load_all(&self, sid: u64, cids: &[ChannelId]) -> ShareStoreFuture<'_, Vec<Share>> {
        self.load_many(sid, cids, &[])
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
    fn keep_list(&self, _: u64, _: u32) -> ShareStoreFuture<'_, Option<Vec<u32>>> {
        let keep = self.keep.lock().unwrap().clone();
        Box::pin(std::future::ready(Ok(keep)))
    }
}

/// An in-memory share store that can be told to fail its reads, its writes,
/// its channel removal or its verification bookkeeping with a backend error.
#[derive(Default, Clone)]
pub struct RefusingShareStore {
    pub inner: InMemShareStore,
    save_backend_error: Arc<Mutex<bool>>,
    load_backend_error: Arc<Mutex<bool>>,
    remove_channel_backend_error: Arc<Mutex<bool>>,
    verification_backend_error: Arc<Mutex<bool>>,
}

impl RefusingShareStore {
    /// Fail every `save` with a backend error.
    pub fn set_backend_error(&self, fail: bool) {
        *self.save_backend_error.lock().unwrap() = fail;
    }

    /// Fail every `load`, `load_many` and `load_all` with a backend error.
    pub fn set_load_backend_error(&self, fail: bool) {
        *self.load_backend_error.lock().unwrap() = fail;
    }

    /// Fail every `remove_channel` with a backend error.
    pub fn set_remove_channel_backend_error(&self, fail: bool) {
        *self.remove_channel_backend_error.lock().unwrap() = fail;
    }

    /// Fail every `record_verification` with a backend error.
    pub fn set_verification_backend_error(&self, fail: bool) {
        *self.verification_backend_error.lock().unwrap() = fail;
    }

    fn backend_error<T: Send + 'static>() -> ShareStoreFuture<'static, T> {
        Box::pin(std::future::ready(Err(ShareStoreError::Backend(
            "share store backend unavailable".to_owned().into(),
        ))))
    }
}

impl DeRecShareStore for RefusingShareStore {
    fn load(
        &self,
        secret_id: u64,
        channel_id: ChannelId,
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        if *self.load_backend_error.lock().unwrap() {
            return Self::backend_error();
        }
        self.inner.load(secret_id, channel_id, versions)
    }
    fn load_many(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
        versions: &[u32],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        if *self.load_backend_error.lock().unwrap() {
            return Self::backend_error();
        }
        self.inner.load_many(secret_id, channel_ids, versions)
    }
    fn load_all(
        &self,
        secret_id: u64,
        channel_ids: &[ChannelId],
    ) -> ShareStoreFuture<'_, Vec<Share>> {
        if *self.load_backend_error.lock().unwrap() {
            return Self::backend_error();
        }
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
        if *self.save_backend_error.lock().unwrap() {
            return Self::backend_error();
        }
        self.inner.save(secret_id, channel_id, share)
    }
    fn remove_channel(
        &mut self,
        secret_id: u64,
        channel_id: ChannelId,
    ) -> ShareStoreFuture<'_, ()> {
        if *self.remove_channel_backend_error.lock().unwrap() {
            return Self::backend_error();
        }
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
    fn keep_list(&self, secret_id: u64, version: u32) -> ShareStoreFuture<'_, Option<Vec<u32>>> {
        self.inner.keep_list(secret_id, version)
    }
    fn record_verification(&mut self, _: u64, _: ChannelId, _: u32) -> ShareStoreFuture<'_, ()> {
        if *self.verification_backend_error.lock().unwrap() {
            return Self::backend_error();
        }
        Box::pin(std::future::ready(Ok(())))
    }
}

#[derive(Default, Clone)]
pub struct InMemUserSecretStore {
    pub data: Arc<Mutex<HashMap<u64, UserSecrets>>>,
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

/// A user-secret store that can be told to fail its reads or its removal.
#[derive(Default, Clone)]
pub struct FlakyUserSecretStore {
    pub inner: InMemUserSecretStore,
    fail_load: Arc<Mutex<bool>>,
    fail_remove: Arc<Mutex<bool>>,
}

impl FlakyUserSecretStore {
    pub fn set_fail_load(&self, fail: bool) {
        *self.fail_load.lock().unwrap() = fail;
    }

    pub fn set_fail_remove(&self, fail: bool) {
        *self.fail_remove.lock().unwrap() = fail;
    }
}

fn user_secret_backend_error<T: Send + 'static>() -> ShareStoreFuture<'static, T> {
    Box::pin(std::future::ready(Err(ShareStoreError::Backend(
        "user secret store unavailable".into(),
    ))))
}

impl DeRecUserSecretStore for FlakyUserSecretStore {
    fn load_latest(&self, sid: u64) -> ShareStoreFuture<'_, Option<UserSecrets>> {
        if *self.fail_load.lock().unwrap() {
            return user_secret_backend_error();
        }
        self.inner.load_latest(sid)
    }
    fn save_latest(&mut self, sid: u64, value: UserSecrets) -> ShareStoreFuture<'_, ()> {
        self.inner.save_latest(sid, value)
    }
    fn remove(&mut self, sid: u64) -> ShareStoreFuture<'_, ()> {
        if *self.fail_remove.lock().unwrap() {
            return user_secret_backend_error();
        }
        self.inner.remove(sid)
    }
}

/// State store double that persists nothing — every load resolves empty.
#[derive(Default, Clone)]
pub struct InMemStateStore;
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

/// Transport double that records every outbound `(endpoints, envelope)` in
/// send order, so a test can assert both *that* a message went out and
/// *what* it carried.
#[derive(Default, Clone)]
pub struct RecordingTransport {
    #[allow(clippy::type_complexity)]
    pub sent: Arc<Mutex<Vec<(Vec<TransportProtocol>, Vec<u8>)>>>,
    /// When set, every send is recorded and then reported as failed: the
    /// peer may have received it, but the transport could not confirm that.
    fail_after_record: Arc<Mutex<bool>>,
}

impl RecordingTransport {
    pub fn set_fail_after_record(&self, fail: bool) {
        *self.fail_after_record.lock().unwrap() = fail;
    }

    /// Endpoint URIs of everything sent so far, in send order.
    pub fn sent_uris(&self) -> Vec<String> {
        self.sent
            .lock()
            .unwrap()
            .iter()
            .map(|(endpoints, _)| endpoints[0].uri.clone())
            .collect()
    }

    /// Raw envelopes sent so far, in send order.
    pub fn sent_envelopes(&self) -> Vec<Vec<u8>> {
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
        if *self.fail_after_record.lock().unwrap() {
            return Box::pin(std::future::ready(Err(derec_library::Error::InvalidInput(
                "transport could not confirm delivery",
            ))));
        }
        Box::pin(std::future::ready(Ok(())))
    }
}

/// Drive an async test body to completion on a fresh current-thread runtime.
pub fn run_async<F: std::future::Future<Output = ()>>(f: F) {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime")
        .block_on(f)
}
