pub mod recovery;
pub use recovery::generate_share_request;
pub use recovery::generate_share_response;
pub use recovery::recover_from_share_responses;

use prost::Message;
use crate::protos::derec_proto::{GetShareRequestMessage, GetShareResponseMessage, StoreShareRequestMessage};

use wasm_bindgen::prelude::*;

#[derive(serde::Serialize, serde::Deserialize)]
struct TsRecoverShareResponses {
    value: std::collections::HashMap<u64, Vec<u8>>,
}

#[wasm_bindgen]
pub fn ts_generate_share_request(
    channel_id: u64,
    secret_id: &[u8],
    version: i32,
) -> Vec<u8> {
    recovery::generate_share_request(&channel_id, secret_id, version).encode_to_vec()
}

#[wasm_bindgen]
pub fn ts_generate_share_response(
    secret_id: &[u8],
    channel_id: u64,
    share_content: &[u8],
    request: &[u8],
) -> Vec<u8> {
    let request = GetShareRequestMessage::decode(request).unwrap();
    let share_content = StoreShareRequestMessage::decode(share_content).unwrap();
    recovery::generate_share_response(&channel_id, secret_id, &request, &share_content).encode_to_vec()
}

#[wasm_bindgen]
pub fn ts_recover_from_share_responses(
    responses: JsValue,
    secret_id: &[u8],
    version: i32
) -> Result<Vec<u8>, String> {
    let responses: TsRecoverShareResponses = serde_wasm_bindgen::from_value(responses).unwrap();
    let mut parsed_responses = Vec::new();
    for (_channel_id, bytes) in responses.value {
        let response = GetShareResponseMessage::decode(&*bytes);
        if response.is_err() {
            return Err(response.unwrap_err().to_string());
        } else {
            parsed_responses.push(response.unwrap());
        }
    }
    let secret = recovery::recover_from_share_responses(&parsed_responses, secret_id, version);
    if secret.is_err() {
        return Err(secret.unwrap_err().to_string());
    }
    return Ok(secret.unwrap());
}

#[cfg(test)]
mod test;