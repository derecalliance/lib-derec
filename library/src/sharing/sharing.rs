use prost::Message;
use rand::RngCore;
use std::collections::HashMap;
use derec_cryptography::vss;
use crate::protos::derec_proto::{StoreShareRequestMessage, DeRecShare, CommittedDeRecShare, committed_de_rec_share::SiblingHash};
use crate::types::*;

/// Protects a secret by splitting it into verifiable secret shares and preparing messages for distribution.
///
/// This function uses verifiable secret sharing (VSS) to split the provided secret data into multiple shares,
/// each associated with a communication channel. Each share is committed and encoded into a message suitable
/// for secure distribution. The function supports optional metadata such as a keep list and a version description.
///
/// # Arguments
///
/// * `secret_id` - An identifier for the secret, used to associate shares with the original secret.
/// * `secret_data` - The secret data to be protected and shared.
/// * `channels` - A slice of identifiers (e.g., public keys or addresses) representing the recipients of each share.
/// * `threshold` - The minimum number of shares required to reconstruct the secret.
/// * `version` - The version number of the secret or sharing scheme.
/// * `keep_list` - An optional slice of integers specifying which shares should be retained or prioritized.
/// * `description` - An optional description of the version or sharing context.
///
/// # Returns
///
/// Returns a `Result` containing a `SharingMulticastMessage`, which maps each channel to its corresponding
/// `StoreShareRequestMessage`. Returns an error string if share generation fails.
///
/// # Errors
///
/// Returns an error if the verifiable secret sharing (VSS) process fails to generate shares.
///
/// # Example
///
/// ```rust
/// use crate::derec_library::sharing::protect_secret;
/// let secret_id = b"my_password";
/// let secret_data = b"password";
/// let channels = vec![1, 2, 3]; // from pairing
/// let threshold = 2;
/// let version = 1;
/// let result = protect_secret(secret_id, secret_data, &channels, threshold, version, None, None);
/// ```
pub fn protect_secret(
    secret_id: impl AsRef<[u8]>,
    secret_data: impl AsRef<[u8]>,
    channels: impl AsRef<[ChannelId]>,
    threshold: usize,
    version: i32,
    keep_list: Option<&[i32]>,
    description: Option<&str>,
) -> Result<HashMap<ChannelId, StoreShareRequestMessage>, &'static str> {
    // our secret sharing scheme requires some entropy
    let mut rng = rand::rngs::OsRng;
    let mut entropy: [u8; 32] = [0; 32];
    rng.fill_bytes(&mut entropy);

    let (t, n) = (threshold as u64, channels.as_ref().len() as u64);
    let vss_shares = vss::share((t,n), secret_data.as_ref(), &entropy)
        .map_err(|_| "VSS failed to generate shares")?;

    // let's iterate over all shares and prepare DeRec protocol messages
    let mut output = HashMap::new();
    for (channel, share) in channels.as_ref().iter().zip(vss_shares.iter()) {
        let derec_share = DeRecShare {
            encrypted_secret: share.encrypted_secret.to_owned(),
            x: share.x.to_owned(),
            y: share.y.to_owned(),
            secret_id: secret_id.as_ref().to_vec(),
            version: version,
        };

        let committed_derec_share = CommittedDeRecShare {
            de_rec_share: derec_share.encode_to_vec(),
            commitment: share.commitment.to_owned(),
            merkle_path: share.merkle_path
                .iter()
                .map(|(b,h)| SiblingHash { is_left: *b, hash: h.to_owned() } )
                .collect(),
        };

        let outbound_msg = StoreShareRequestMessage {
            share: committed_derec_share.encode_to_vec(),
            share_algorithm: 0,
            version: version,
            keep_list: keep_list.map(|lst| lst.to_vec()).unwrap_or_default(),
            version_description: description.map(|d| d.to_string()).unwrap_or_default(),
        };

        output.insert(*channel, outbound_msg);
    }

    Ok(output)
}