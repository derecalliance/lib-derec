use std::cell::RefCell;
use std::collections::HashMap;

use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_library::protocol::{
    ContactStoreFuture, DeRecContactStore, DeRecEvent, DeRecProtocol, DeRecProtocolBuilder,
    DeRecSecretStore, DeRecShareStore, DeRecTransport, SecretKind, SecretStoreFuture, SecretValue,
    ShareStoreFuture, TransportFuture,
};
use derec_library::types::{ChannelId, Secret, SharedKey};
use derec_proto::{ContactMessage, Protocol, SenderKind, TransportProtocol};

pub fn run_all() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("failed to build tokio runtime");

    rt.block_on(run_pairing_flow());
    rt.block_on(run_sharing_flow());
    rt.block_on(run_discovery_and_recovery_flow());
}

// ── In-memory stores ──────────────────────────────────────────────────────────

struct InMemorySecretStore {
    shared_keys: HashMap<u64, SharedKey>,
    pairing_secrets: HashMap<u64, PairingSecretKeyMaterial>,
}

impl InMemorySecretStore {
    fn new() -> Self {
        Self {
            shared_keys: HashMap::new(),
            pairing_secrets: HashMap::new(),
        }
    }
}

impl DeRecSecretStore for InMemorySecretStore {
    fn load(&self, channel_id: ChannelId, kind: SecretKind) -> SecretStoreFuture<'_, Option<SecretValue>> {
        let value = match kind {
            SecretKind::SharedKey => self
                .shared_keys
                .get(&channel_id.0)
                .copied()
                .map(SecretValue::SharedKey),
            SecretKind::PairingSecret => self
                .pairing_secrets
                .get(&channel_id.0)
                .map(|sk| SecretValue::PairingSecret(sk.clone())),
        };
        Box::pin(std::future::ready(Ok(value)))
    }

    fn save(&mut self, channel_id: ChannelId, value: SecretValue) -> SecretStoreFuture<'_, ()> {
        match value {
            SecretValue::SharedKey(key) => {
                self.shared_keys.insert(channel_id.0, key);
            }
            SecretValue::PairingSecret(secret) => {
                self.pairing_secrets.insert(channel_id.0, secret);
            }
        }
        Box::pin(std::future::ready(Ok(())))
    }

    fn remove(&mut self, channel_id: ChannelId, kind: SecretKind) -> SecretStoreFuture<'_, ()> {
        match kind {
            SecretKind::SharedKey => {
                self.shared_keys.remove(&channel_id.0);
            }
            SecretKind::PairingSecret => {
                self.pairing_secrets.remove(&channel_id.0);
            }
        }
        Box::pin(std::future::ready(Ok(())))
    }
}

struct InMemoryContactStore {
    contacts: HashMap<u64, ContactMessage>,
}

impl InMemoryContactStore {
    fn new() -> Self {
        Self {
            contacts: HashMap::new(),
        }
    }
}

impl DeRecContactStore for InMemoryContactStore {
    fn load(&self, channel_id: ChannelId) -> ContactStoreFuture<'_, Option<ContactMessage>> {
        Box::pin(std::future::ready(Ok(self.contacts.get(&channel_id.0).cloned())))
    }

    fn save(&mut self, channel_id: ChannelId, contact: ContactMessage) -> ContactStoreFuture<'_, ()> {
        self.contacts.insert(channel_id.0, contact);
        Box::pin(std::future::ready(Ok(())))
    }
}

struct InMemoryShareStore {
    shares: HashMap<(u64, Vec<u8>, i32), Vec<u8>>,
}

impl InMemoryShareStore {
    fn new() -> Self {
        Self {
            shares: HashMap::new(),
        }
    }
}

impl DeRecShareStore for InMemoryShareStore {
    fn load(&self, channel_id: ChannelId, secret_id: &[u8], version: i32) -> ShareStoreFuture<'_, Option<Vec<u8>>> {
        Box::pin(std::future::ready(Ok(self
            .shares
            .get(&(channel_id.0, secret_id.to_vec(), version))
            .cloned())))
    }

    fn save(&mut self, channel_id: ChannelId, secret_id: &[u8], version: i32, encoded: Vec<u8>) -> ShareStoreFuture<'_, ()> {
        self.shares.insert((channel_id.0, secret_id.to_vec(), version), encoded);
        Box::pin(std::future::ready(Ok(())))
    }

    fn load_channels_for_secret(&self, secret_id: &[u8], version: i32) -> ShareStoreFuture<'_, Vec<ChannelId>> {
        let channels = self
            .shares
            .keys()
            .filter(|(_, sid, v)| sid.as_slice() == secret_id && *v == version)
            .map(|(cid, _, _)| ChannelId(*cid))
            .collect();
        Box::pin(std::future::ready(Ok(channels)))
    }

    fn load_secrets_for_channel(&self, channel_id: ChannelId) -> ShareStoreFuture<'_, Vec<(Vec<u8>, Vec<i32>)>> {
        let mut map: HashMap<Vec<u8>, Vec<i32>> = HashMap::new();
        for ((cid, secret_id, version), _) in &self.shares {
            if *cid == channel_id.0 {
                map.entry(secret_id.clone()).or_default().push(*version);
            }
        }
        let result = map.into_iter().collect();
        Box::pin(std::future::ready(Ok(result)))
    }
}

// ── Recording transport ───────────────────────────────────────────────────────

/// Collects outbound messages instead of sending them over the network.
/// Call `drain()` to retrieve and clear the pending messages.
struct RecordingTransport {
    outbox: RefCell<Vec<(TransportProtocol, Vec<u8>)>>,
}

impl RecordingTransport {
    fn new() -> Self {
        Self {
            outbox: RefCell::new(Vec::new()),
        }
    }

    fn drain(&self) -> Vec<(TransportProtocol, Vec<u8>)> {
        self.outbox.borrow_mut().drain(..).collect()
    }
}

impl DeRecTransport for RecordingTransport {
    fn send(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> TransportFuture<'_> {
        self.outbox.borrow_mut().push((endpoint.clone(), message));
        Box::pin(std::future::ready(Ok(())))
    }
}

// ── Helper to build a protocol instance ──────────────────────────────────────

fn make_protocol(
    endpoint: &str,
) -> DeRecProtocol<
    InMemoryContactStore,
    InMemoryShareStore,
    InMemorySecretStore,
    RecordingTransport,
> {
    DeRecProtocolBuilder::new()
        .with_contact_store(InMemoryContactStore::new())
        .with_share_store(InMemoryShareStore::new())
        .with_secret_store(InMemorySecretStore::new())
        .with_transport(RecordingTransport::new())
        .with_own_transport(TransportProtocol {
            uri: endpoint.to_owned(),
            protocol: Protocol::Https.into(),
        })
        .build()
}

// ── Smoke tests ───────────────────────────────────────────────────────────────

async fn run_pairing_flow() {
    println!("=== Protocol pairing flow test ===");

    let channel_id = ChannelId(1);
    let mut owner = make_protocol("https://owner.example.com");
    let mut helper = make_protocol("https://helper.example.com");

    // Step 1: Owner creates an out-of-band contact.
    let contact = owner
        .create_contact(Some(channel_id))
        .await
        .expect("create_contact failed");
    println!("Owner created contact for channel {:?}", channel_id);

    // Step 2: Helper scans the contact and sends a PairRequest to the owner.
    helper
        .start_pairing(SenderKind::Helper, contact)
        .await
        .expect("start_pairing failed");

    let (_, pair_request_bytes) = helper
        .transport
        .drain()
        .into_iter()
        .next()
        .expect("expected PairRequest outbound message");
    println!("Helper sent PairRequest ({} bytes)", pair_request_bytes.len());

    // Step 3: Owner processes the PairRequest and sends back a PairResponse.
    let events = owner
        .process(&pair_request_bytes)
        .await
        .expect("owner.process(PairRequest) failed");
    assert!(
        events.iter().any(|e| matches!(e, DeRecEvent::PairingComplete { .. })),
        "expected PairingComplete event on owner side"
    );

    let (_, pair_response_bytes) = owner
        .transport
        .drain()
        .into_iter()
        .next()
        .expect("expected PairResponse outbound message");
    println!(
        "Owner processed PairRequest, sent PairResponse ({} bytes)",
        pair_response_bytes.len()
    );

    // Step 4: Helper processes the PairResponse and derives the shared key.
    let events = helper
        .process(&pair_response_bytes)
        .await
        .expect("helper.process(PairResponse) failed");
    assert!(
        events.iter().any(|e| matches!(e, DeRecEvent::PairingComplete { .. })),
        "expected PairingComplete event on helper side"
    );
    println!("Helper processed PairResponse — pairing complete on both sides");

    println!("Protocol pairing flow test passed.");
}

async fn run_sharing_flow() {
    println!("=== Protocol sharing flow test ===");

    let channel_id_a = ChannelId(1);
    let channel_id_b = ChannelId(2);
    let mut owner = make_protocol("https://owner.example.com");
    let mut helper_a = make_protocol("https://helper-a.example.com");
    let mut helper_b = make_protocol("https://helper-b.example.com");

    // Pair owner with both helpers.
    async fn pair(
        owner: &mut DeRecProtocol<
            InMemoryContactStore,
            InMemoryShareStore,
            InMemorySecretStore,
            RecordingTransport,
        >,
        helper: &mut DeRecProtocol<
            InMemoryContactStore,
            InMemoryShareStore,
            InMemorySecretStore,
            RecordingTransport,
        >,
        channel_id: ChannelId,
    ) {
        let contact = owner.create_contact(Some(channel_id)).await.expect("create_contact failed");
        helper.start_pairing(SenderKind::Helper, contact).await.expect("start_pairing failed");
        let (_, req) = helper.transport.drain().into_iter().next().unwrap();
        owner.process(&req).await.expect("owner.process(PairRequest) failed");
        let (_, resp) = owner.transport.drain().into_iter().next().unwrap();
        helper.process(&resp).await.expect("helper.process(PairResponse) failed");
    }

    pair(&mut owner, &mut helper_a, channel_id_a).await;
    pair(&mut owner, &mut helper_b, channel_id_b).await;
    println!("Pairing complete — proceeding with share distribution (threshold=2, helpers=2)");

    // Owner distributes a secret to both helpers.
    let secret = Secret {
        id: vec![1, 2, 3],
        version: 1,
        data: b"super-secret-value".to_vec(),
        description: "smoke-test secret".to_owned(),
    };
    owner
        .protect_secret(secret, 2, &[channel_id_a, channel_id_b], &[])
        .await
        .expect("protect_secret failed");

    let outbound = owner.transport.drain();
    assert_eq!(outbound.len(), 2, "expected one StoreShareRequest per helper");

    // Route each request to the correct helper and collect responses.
    let helpers: &mut [(&mut DeRecProtocol<_, _, _, _>, ChannelId)] =
        &mut [(&mut helper_a, channel_id_a), (&mut helper_b, channel_id_b)];

    for (store_request_bytes, (helper, _)) in outbound.iter().zip(helpers.iter_mut()) {
        println!("Owner sent StoreShareRequest ({} bytes)", store_request_bytes.1.len());

        let events = helper
            .process(&store_request_bytes.1)
            .await
            .expect("helper.process(StoreShareRequest) failed");
        assert!(
            events.iter().any(|e| matches!(e, DeRecEvent::ShareStored { .. })),
            "expected ShareStored event on helper side"
        );
        println!("Helper stored the share");

        let (_, store_response_bytes) = helper
            .transport
            .drain()
            .into_iter()
            .next()
            .expect("expected StoreShareResponse outbound message");
        println!("Helper sent StoreShareResponse ({} bytes)", store_response_bytes.len());

        let events = owner
            .process(&store_response_bytes)
            .await
            .expect("owner.process(StoreShareResponse) failed");
        assert!(
            events.iter().any(|e| matches!(e, DeRecEvent::ShareConfirmed { .. })),
            "expected ShareConfirmed event on owner side"
        );
        println!("Owner received share confirmation");
    }

    println!("Protocol sharing flow test passed.");
}

async fn run_discovery_and_recovery_flow() {
    println!("=== Protocol discovery & recovery flow test ===");

    let channel_id = ChannelId(1);
    let recovery_channel_id = ChannelId(100);
    let mut owner = make_protocol("https://owner.example.com");
    let mut helper = make_protocol("https://helper.example.com");

    // ── Setup: pair owner with helper ─────────────────────────────────────────

    let contact = owner
        .create_contact(Some(channel_id))
        .await
        .expect("create_contact failed");

    helper
        .start_pairing(SenderKind::Helper, contact)
        .await
        .expect("start_pairing failed");

    let (_, pair_request_bytes) = helper.transport.drain().into_iter().next().unwrap();
    owner
        .process(&pair_request_bytes)
        .await
        .expect("owner.process(PairRequest) failed");

    let (_, pair_response_bytes) = owner.transport.drain().into_iter().next().unwrap();
    helper
        .process(&pair_response_bytes)
        .await
        .expect("helper.process(PairResponse) failed");

    println!("Initial pairing complete.");

    // ── Setup: owner distributes a secret ─────────────────────────────────────

    let secret_id: Vec<u8> = b"my-wallet-seed".to_vec();
    let secret_version: i32 = 1;

    owner
        .protect_secret(
            Secret {
                id: secret_id.clone(),
                version: secret_version,
                data: b"correct horse battery staple".to_vec(),
                description: "wallet seed phrase".to_owned(),
            },
            1,
            &[channel_id],
            &[],
        )
        .await
        .expect("protect_secret failed");

    let (_, store_request_bytes) = owner.transport.drain().into_iter().next().unwrap();
    helper
        .process(&store_request_bytes)
        .await
        .expect("helper.process(StoreShareRequest) failed");

    let (_, store_response_bytes) = helper.transport.drain().into_iter().next().unwrap();
    owner
        .process(&store_response_bytes)
        .await
        .expect("owner.process(StoreShareResponse) failed");

    println!("Secret distributed and confirmed.");

    // ── Recovery: re-pair using a new channel ─────────────────────────────────

    // The Helper creates a contact for the recovery session. In a real system
    // the recovering Owner would receive this contact out-of-band (QR code, etc.)
    // and the Helper would map the new channel to the old one at the app level.
    let helper_recovery_contact = helper
        .create_contact(Some(recovery_channel_id))
        .await
        .expect("helper.create_contact (recovery) failed");

    // Pre-seed the Helper's store with the share under the recovery channel to
    // simulate the app-layer mapping from the old channel to the recovery channel.
    let share_bytes = helper
        .share_store
        .load(channel_id, &secret_id, secret_version)
        .await
        .expect("load share failed")
        .expect("share not found");
    helper
        .share_store
        .save(recovery_channel_id, &secret_id, secret_version, share_bytes)
        .await
        .expect("save share under recovery channel failed");

    // Owner starts recovery pairing toward the Helper.
    owner
        .start_pairing(SenderKind::OwnerRecovery, helper_recovery_contact)
        .await
        .expect("start_pairing (recovery) failed");

    // Route the PairRequest to the Helper.
    let (_, recovery_pair_request_bytes) = owner.transport.drain().into_iter().next().unwrap();
    println!(
        "Owner sent recovery PairRequest ({} bytes)",
        recovery_pair_request_bytes.len()
    );

    let events = helper
        .process(&recovery_pair_request_bytes)
        .await
        .expect("helper.process(recovery PairRequest) failed");
    assert!(
        events.iter().any(|e| matches!(
            e,
            DeRecEvent::PairingComplete { kind: SenderKind::Helper, .. }
        )),
        "expected PairingComplete(Helper) on helper side"
    );

    // Route the PairResponse to the Owner.
    let (_, recovery_pair_response_bytes) = helper.transport.drain().into_iter().next().unwrap();
    println!(
        "Helper sent recovery PairResponse ({} bytes)",
        recovery_pair_response_bytes.len()
    );

    let events = owner
        .process(&recovery_pair_response_bytes)
        .await
        .expect("owner.process(recovery PairResponse) failed");
    assert!(
        events.iter().any(|e| matches!(
            e,
            DeRecEvent::PairingComplete { kind: SenderKind::OwnerRecovery, .. }
        )),
        "expected PairingComplete(OwnerRecovery) on owner side"
    );
    println!("Recovery pairing complete.");

    // ── Discovery: Owner explicitly requests discovery after authentication ────
    //
    // In a real application the Owner would first perform out-of-band
    // authentication with the Helper before calling request_discovery.

    owner
        .request_discovery(recovery_channel_id)
        .await
        .expect("request_discovery failed");

    let (_, discovery_request_bytes) = owner.transport.drain().into_iter().next().unwrap();
    println!(
        "Owner sent discovery request ({} bytes)",
        discovery_request_bytes.len()
    );

    helper
        .process(&discovery_request_bytes)
        .await
        .expect("helper.process(GetSecretIdsVersionsRequest) failed");

    // Route the discovery response to the Owner — emits SecretsDiscovered.
    let (_, discovery_response_bytes) = helper.transport.drain().into_iter().next().unwrap();
    println!(
        "Helper sent discovery response ({} bytes)",
        discovery_response_bytes.len()
    );

    let events = owner
        .process(&discovery_response_bytes)
        .await
        .expect("owner.process(GetSecretIdsVersionsResponse) failed");

    let discovered = events
        .iter()
        .find_map(|e| match e {
            DeRecEvent::SecretsDiscovered { channel_id, secrets } => {
                Some((channel_id, secrets))
            }
            _ => None,
        })
        .expect("expected SecretsDiscovered event");

    assert_eq!(*discovered.0, recovery_channel_id);
    assert!(
        discovered.1.iter().any(|e| e.secret_id == secret_id),
        "discovered list must contain the distributed secret"
    );
    // Verify description was preserved through the round-trip.
    let wallet_entry = discovered.1.iter().find(|e| e.secret_id == secret_id).unwrap();
    assert!(
        wallet_entry.versions.iter().any(|v| v.description == "wallet seed phrase"),
        "version description must be preserved in SecretsDiscovered"
    );
    println!(
        "Owner discovered {} secret(s) on the Helper.",
        discovered.1.len()
    );

    // ── Recovery: request the share and reconstruct the secret ────────────────

    owner
        .recover_secret(secret_id.clone(), secret_version, &[recovery_channel_id])
        .await
        .expect("recover_secret failed");

    let (_, share_request_bytes) = owner.transport.drain().into_iter().next().unwrap();
    println!(
        "Owner sent GetShareRequest ({} bytes)",
        share_request_bytes.len()
    );

    helper
        .process(&share_request_bytes)
        .await
        .expect("helper.process(GetShareRequest) failed");

    let (_, share_response_bytes) = helper.transport.drain().into_iter().next().unwrap();
    println!(
        "Helper sent GetShareResponse ({} bytes)",
        share_response_bytes.len()
    );

    let events = owner
        .process(&share_response_bytes)
        .await
        .expect("owner.process(GetShareResponse) failed");

    assert!(
        events.iter().any(|e| matches!(e, DeRecEvent::SecretRecovered { .. })),
        "expected SecretRecovered event"
    );
    println!("Owner successfully reconstructed the secret.");

    println!("Protocol discovery & recovery flow test passed.");
}
