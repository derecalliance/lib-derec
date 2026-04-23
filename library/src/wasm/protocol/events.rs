// SPDX-License-Identifier: Apache-2.0

//! Converts [`DeRecEvent`] values to plain JS objects for TypeScript consumers.

use crate::protocol::DeRecEvent;
use crate::wasm::ts_bindings_utils::js_error;
use wasm_bindgen::JsValue;

#[derive(serde::Serialize)]
#[serde(tag = "type")]
enum DeRecEventJs {
    PairingComplete {
        channel_id: String,
        kind: u32,
    },
    ShareStored {
        channel_id: String,
        version: i32,
    },
    ShareConfirmed {
        channel_id: String,
        version: i32,
    },
    ShareVerified {
        channel_id: String,
        version: i32,
    },
    SecretsDiscovered {
        channel_id: String,
        secrets: Vec<SecretVersionEntryJs>,
    },
    RecoveryShareReceived {
        channel_id: String,
        shares_received: usize,
    },
    RecoveryShareError {
        channel_id: String,
        shares_received: usize,
        error: String,
    },
    SecretRecovered {
        secret: Vec<u8>,
    },
    ReplicaConfirmationReceived {
        channel_id: String,
        replica_id: i32,
        fingerprint: Vec<u8>,
    },
    ReplicaConfirmed {
        channel_id: String,
        replica_id: i32,
    },
    ChannelsDiscoveryRequested {
        channel_id: String,
        last_batch_index: i32,
    },
    ChannelsDiscovered {
        channel_id: String,
        total_batches: i32,
        current_batch: i32,
        entries: Vec<ChannelEntryJs>,
    },
    NoOp,
}

#[derive(serde::Serialize)]
struct SecretVersionEntryJs {
    secret_id: Vec<u8>,
    versions: Vec<VersionEntryJs>,
}

#[derive(serde::Serialize)]
struct VersionEntryJs {
    version: i32,
    description: String,
}

#[derive(serde::Serialize)]
struct ChannelEntryJs {
    channel_id: String,
    shared_key: Vec<u8>,
}

pub fn event_to_js(event: DeRecEvent) -> Result<JsValue, JsValue> {
    let js_event = match event {
        DeRecEvent::PairingComplete { channel_id, kind } => DeRecEventJs::PairingComplete {
            channel_id: channel_id.0.to_string(),
            kind: kind as u32,
        },
        DeRecEvent::ShareStored { channel_id, version } => DeRecEventJs::ShareStored {
            channel_id: channel_id.0.to_string(),
            version,
        },
        DeRecEvent::ShareConfirmed { channel_id, version } => DeRecEventJs::ShareConfirmed {
            channel_id: channel_id.0.to_string(),
            version,
        },
        DeRecEvent::ShareVerified { channel_id, version } => DeRecEventJs::ShareVerified {
            channel_id: channel_id.0.to_string(),
            version,
        },
        DeRecEvent::SecretsDiscovered { channel_id, secrets } => DeRecEventJs::SecretsDiscovered {
            channel_id: channel_id.0.to_string(),
            secrets: secrets
                .into_iter()
                .map(|e| SecretVersionEntryJs {
                    secret_id: e.secret_id,
                    versions: e
                        .versions
                        .into_iter()
                        .map(|v| VersionEntryJs {
                            version: v.version,
                            description: v.description,
                        })
                        .collect(),
                })
                .collect(),
        },
        DeRecEvent::RecoveryShareReceived { channel_id, shares_received } => {
            DeRecEventJs::RecoveryShareReceived {
                channel_id: channel_id.0.to_string(),
                shares_received,
            }
        }
        DeRecEvent::RecoveryShareError { channel_id, shares_received, error } => {
            DeRecEventJs::RecoveryShareError {
                channel_id: channel_id.0.to_string(),
                shares_received,
                error,
            }
        }
        DeRecEvent::SecretRecovered { secret } => DeRecEventJs::SecretRecovered { secret },
        DeRecEvent::ReplicaConfirmationReceived { channel_id, replica_id, fingerprint } => {
            DeRecEventJs::ReplicaConfirmationReceived {
                channel_id: channel_id.0.to_string(),
                replica_id,
                fingerprint: fingerprint.to_vec(),
            }
        }
        DeRecEvent::ReplicaConfirmed { channel_id, replica_id } => {
            DeRecEventJs::ReplicaConfirmed {
                channel_id: channel_id.0.to_string(),
                replica_id,
            }
        }
        DeRecEvent::ChannelsDiscoveryRequested { channel_id, last_batch_index } => {
            DeRecEventJs::ChannelsDiscoveryRequested {
                channel_id: channel_id.0.to_string(),
                last_batch_index,
            }
        }
        DeRecEvent::ChannelsDiscovered { channel_id, total_batches, current_batch, entries } => {
            DeRecEventJs::ChannelsDiscovered {
                channel_id: channel_id.0.to_string(),
                total_batches,
                current_batch,
                entries: entries
                    .into_iter()
                    .map(|e| ChannelEntryJs {
                        channel_id: e.channel_id.0.to_string(),
                        shared_key: e.shared_key.to_vec(),
                    })
                    .collect(),
            }
        }
        DeRecEvent::NoOp => DeRecEventJs::NoOp,
        // `#[non_exhaustive]` — future variants become NoOp so bindings don't break.
        #[allow(unreachable_patterns)]
        _ => DeRecEventJs::NoOp,
    };
    serde_wasm_bindgen::to_value(&js_event)
        .map_err(|e| js_error("WASM_SERIALIZE_ERROR", e.to_string()))
}
