// SPDX-License-Identifier: Apache-2.0

//! State machines for the DeRec protocol.
//!
//! This module contains two pure state machines:
//!
//! - [`PairingStateMachine`] — cryptographic transitions for the pairing flow
//! - [`ChannelStateMachine`] — cryptographic transitions for all post-pairing
//!   (symmetric-key-encrypted) protocol messages
//!
//! Both are pure: no I/O is performed. Storage reads/writes and transport sends
//! remain the responsibility of the caller.

use crate::{
    Error,
    primitives::pairing::response,
    types::SharedKey,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{ContactMessage, PairRequestMessage, PairResponseMessage, SenderKind, TransportProtocol};

// ─────────────────────────────────────────────────────────────────────────────
// PairingStateMachine output types
// ─────────────────────────────────────────────────────────────────────────────

/// Output of [`PairingStateMachine::on_pair_request`].
pub struct OnPairRequestOutput {
    /// Derived shared key. Persist before forwarding any subsequent channel messages.
    pub shared_key: SharedKey,

    /// Serialized pairing response envelope, ready to send over transport.
    pub response_envelope: Vec<u8>,

    /// Peer's transport endpoint, extracted from the incoming request.
    pub peer_endpoint: TransportProtocol,
}

/// Output of [`PairingStateMachine::on_pair_response`].
pub struct OnPairResponseOutput {
    /// Derived shared key.
    pub shared_key: SharedKey,
}

// ─────────────────────────────────────────────────────────────────────────────
// PairingStateMachine
// ─────────────────────────────────────────────────────────────────────────────

/// Pure pairing protocol state machine.
///
/// Encapsulates the two cryptographic transitions of the pairing flow:
///
/// ```text
/// Contact created  ──►  PairRequest received  ──►  on_pair_request()  ──►  PairingComplete
/// PairRequest sent ──►  PairResponse received ──►  on_pair_response() ──►  PairingComplete
/// ```
///
/// Both methods are pure: given the same inputs they produce the same outputs.
/// No storage is read or written; no messages are sent. The caller applies the
/// outputs after the call returns.
///
/// # Protocol roles
///
/// | Method             | Who calls it                                  |
/// |--------------------|-----------------------------------------------|
/// | `on_pair_request`  | The party that created the contact (Owner)    |
/// | `on_pair_response` | The party that scanned the contact (Helper)   |
pub struct PairingStateMachine;

impl PairingStateMachine {
    /// Processes an incoming [`PairRequestMessage`] on the contact-creator side.
    pub fn on_pair_request(
        request: &PairRequestMessage,
        pairing_secret: &PairingSecretKeyMaterial,
    ) -> std::result::Result<OnPairRequestOutput, Error> {
        let resp = response::produce(SenderKind::OwnerNonRecovery, request, pairing_secret)?;

        Ok(OnPairRequestOutput {
            shared_key: resp.shared_key,
            response_envelope: resp.envelope,
            peer_endpoint: resp.responder_transport_protocol,
        })
    }

    /// Processes an incoming [`PairResponseMessage`] on the pairing-initiator side.
    pub fn on_pair_response(
        contact: &ContactMessage,
        response_msg: &PairResponseMessage,
        pairing_secret: &PairingSecretKeyMaterial,
    ) -> std::result::Result<OnPairResponseOutput, Error> {
        let result = response::process(contact, response_msg, pairing_secret)?;

        Ok(OnPairResponseOutput {
            shared_key: result.shared_key,
        })
    }
}

use crate::{
    Result,
    types::ChannelId,
};
use crate::primitives::recovery::response::{RecoveryResponseInput, produce as produce_get_share_response_message, recover as recover_from_share_responses};
use crate::primitives::sharing::response::{produce as produce_store_share_response_message, process as process_store_share_response_message};
use crate::primitives::verification::response::{produce as produce_verify_share_response_message, process as process_verify_share_response_message};
use derec_proto::{
    GetShareRequestMessage, GetShareResponseMessage, StoreShareRequestMessage,
    StoreShareResponseMessage, VerifyShareRequestMessage, VerifyShareResponseMessage,
};
use prost::Message;

// ─────────────────────────────────────────────────────────────────────────────
// Output types
// ─────────────────────────────────────────────────────────────────────────────

/// Output of [`ChannelStateMachine::on_store_share_request`].
pub struct OnStoreShareRequestOutput {
    /// Share version requested by the Owner.
    pub version: i32,

    /// Secret identifier extracted from the request.
    ///
    /// Used as part of the composite store key `(channel_id, secret_id, version)`.
    pub secret_id: Vec<u8>,

    /// Raw encoded `StoreShareRequestMessage` bytes.
    ///
    /// Persist this in the share store under `(channel_id, secret_id, version)`. The full
    /// request is stored rather than just the share bytes because both
    /// verification and recovery need to reconstruct the original message.
    pub encoded_request: Vec<u8>,

    /// Serialized response envelope, ready to send over transport.
    pub response_envelope: Vec<u8>,
}

/// Output of [`ChannelStateMachine::on_store_share_response`].
pub struct OnStoreShareResponseOutput {
    /// Confirmed share version.
    pub version: i32,
}

/// Output of [`ChannelStateMachine::on_verify_share_request`].
pub struct OnVerifyShareRequestOutput {
    /// Serialized response envelope containing the share proof, ready to send
    /// over transport.
    pub response_envelope: Vec<u8>,
}

/// Output of [`ChannelStateMachine::on_verify_share_response`].
pub struct OnVerifyShareResponseOutput {
    /// Verified share version.
    pub version: i32,
}

/// Output of [`ChannelStateMachine::on_get_share_request`].
pub struct OnGetShareRequestOutput {
    /// Serialized response envelope containing the requested share, ready to
    /// send over transport.
    pub response_envelope: Vec<u8>,
}

/// Output of [`ChannelStateMachine::on_get_share_response`] when enough shares
/// have been collected to reconstruct the secret.
pub struct OnGetShareResponseOutput {
    /// Reconstructed plaintext secret.
    pub secret: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// State machine
// ─────────────────────────────────────────────────────────────────────────────

/// Pure channel message state machine.
///
/// Encapsulates the cryptographic transitions for all post-pairing protocol
/// messages. All methods are pure: no storage is read or written, no messages
/// are sent. The caller supplies the data that would otherwise come from stores
/// and applies the outputs after the call returns.
///
/// # Protocol transitions
///
/// | Method                    | Who calls it  | Flow          |
/// |---------------------------|---------------|---------------|
/// | `on_store_share_request`  | Helper        | Sharing       |
/// | `on_store_share_response` | Owner         | Sharing       |
/// | `on_verify_share_request` | Helper        | Verification  |
/// | `on_verify_share_response`| Owner         | Verification  |
/// | `on_get_share_request`    | Helper        | Recovery      |
/// | `on_get_share_response`   | Owner         | Recovery      |
pub struct ChannelStateMachine;

impl ChannelStateMachine {
    // ── Sharing ───────────────────────────────────────────────────────────────

    /// Processes an incoming [`StoreShareRequestMessage`] on the Helper side.
    ///
    /// Produces the acknowledgement response and packages the request bytes for
    /// storage. The caller must persist [`OnStoreShareRequestOutput::encoded_request`]
    /// in the share store and send [`OnStoreShareRequestOutput::response_envelope`]
    /// over transport.
    pub fn on_store_share_request(
        channel_id: ChannelId,
        request: &StoreShareRequestMessage,
        shared_key: &SharedKey,
    ) -> Result<OnStoreShareRequestOutput> {
        let version = request.version;
        let secret_id = request.secret_id.clone();
        let encoded_request = request.encode_to_vec();
        let resp = produce_store_share_response_message(channel_id, request, shared_key)?;

        Ok(OnStoreShareRequestOutput {
            version,
            secret_id,
            encoded_request,
            response_envelope: resp.envelope,
        })
    }

    /// Processes an incoming [`StoreShareResponseMessage`] on the Owner side.
    ///
    /// Validates the response. Returns the confirmed version on success.
    pub fn on_store_share_response(
        response: &StoreShareResponseMessage,
    ) -> Result<OnStoreShareResponseOutput> {
        let version = response.version;
        process_store_share_response_message(version, response)?;

        Ok(OnStoreShareResponseOutput { version })
    }

    // ── Verification ──────────────────────────────────────────────────────────

    /// Processes an incoming [`VerifyShareRequestMessage`] on the Helper side.
    ///
    /// Produces a proof response from the stored share bytes. The caller must
    /// load the share bytes from the share store before calling this method and
    /// send [`OnVerifyShareRequestOutput::response_envelope`] over transport
    /// after it returns.
    ///
    /// # Arguments
    ///
    /// * `share` — raw share bytes from the stored `StoreShareRequestMessage.share`
    ///   field, loaded by the caller from the share store.
    pub fn on_verify_share_request(
        channel_id: ChannelId,
        request: &VerifyShareRequestMessage,
        shared_key: &SharedKey,
        share: &[u8],
    ) -> Result<OnVerifyShareRequestOutput> {
        let resp = produce_verify_share_response_message(channel_id, request, shared_key, share)?;

        Ok(OnVerifyShareRequestOutput {
            response_envelope: resp.envelope,
        })
    }

    /// Processes an incoming [`VerifyShareResponseMessage`] on the Owner side.
    ///
    /// Validates the share proof. Returns the verified version on success, or
    /// an error if the proof is invalid.
    pub fn on_verify_share_response(
        response: &VerifyShareResponseMessage,
    ) -> Result<OnVerifyShareResponseOutput> {
        let version = response.version;
        let valid = process_verify_share_response_message(response, response.hash.as_slice())?;
        if !valid {
            return Err(Error::Invariant("verification proof is invalid"));
        }

        Ok(OnVerifyShareResponseOutput { version })
    }

    // ── Recovery ──────────────────────────────────────────────────────────────

    /// Processes an incoming [`GetShareRequestMessage`] on the Helper side.
    ///
    /// Produces a share response from the stored share request. The caller must
    /// load and decode the stored `StoreShareRequestMessage` from the share store
    /// before calling this method and send
    /// [`OnGetShareRequestOutput::response_envelope`] over transport after it
    /// returns.
    ///
    /// # Arguments
    ///
    /// * `stored` — the `StoreShareRequestMessage` previously persisted in the
    ///   share store, loaded and decoded by the caller.
    pub fn on_get_share_request(
        channel_id: ChannelId,
        request: &GetShareRequestMessage,
        stored: &StoreShareRequestMessage,
        shared_key: &SharedKey,
    ) -> Result<OnGetShareRequestOutput> {
        let resp = produce_get_share_response_message(
            channel_id,
            &request.secret_id,
            request,
            stored,
            shared_key,
        )?;

        Ok(OnGetShareRequestOutput {
            response_envelope: resp.envelope,
        })
    }

    /// Attempts to reconstruct the secret from accumulated share responses.
    ///
    /// Called on the Owner side after a new [`GetShareResponseMessage`] arrives.
    /// The caller is responsible for appending the new response to the
    /// accumulation bucket before calling this method.
    ///
    /// Returns `Ok(Some(...))` when enough shares have been collected for
    /// reconstruction, `Ok(None)` when more shares are still needed, and
    /// `Err(...)` when reconstruction fails due to invalid or inconsistent shares.
    ///
    /// # Arguments
    ///
    /// * `accumulated` — all share responses collected so far for `(secret_id,
    ///   version)`, **including the newly arrived response** appended by the caller.
    pub fn on_get_share_response(
        secret_id: &[u8],
        version: i32,
        accumulated: &[(GetShareResponseMessage, SharedKey)],
    ) -> Result<Option<OnGetShareResponseOutput>> {
        let inputs: Vec<RecoveryResponseInput<'_>> = accumulated
            .iter()
            .map(|(r, k)| RecoveryResponseInput {
                share_response: r,
                shared_key: k,
            })
            .collect();

        match recover_from_share_responses(secret_id, version, &inputs) {
            Ok(result) => Ok(Some(OnGetShareResponseOutput {
                secret: result.secret_data,
            })),
            Err(_) => Ok(None),
        }
    }
}
