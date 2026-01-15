pub mod verification;
pub use verification::generate_verification_request;
pub use verification::generate_verification_response;
pub use verification::verify_share_response;

use prost::Message;
use crate::protos::derec_proto::{VerifyShareRequestMessage, VerifyShareResponseMessage};
use crate::Error;

use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn ts_generate_verification_request(
    secret_id: &[u8],
    version: u32,
) -> Vec<u8> {
    verification::generate_verification_request(secret_id, version as i32).encode_to_vec()
}

fn to_js_error(err: Error) -> JsValue {
    JsValue::from_str(&err.to_string())
}

#[wasm_bindgen]
pub fn ts_generate_verification_response(
    secret_id: &[u8],
    channel_id: u64,
    share_content: &[u8],
    request: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let request = VerifyShareRequestMessage::decode(request)
        .map_err(|err| to_js_error(Error::Decode(err.to_string())))?;
    Ok(verification::generate_verification_response(secret_id, &channel_id, share_content, &request).encode_to_vec())
}

#[wasm_bindgen]
pub fn ts_verify_share_response(
    secret_id: &[u8],
    channel_id: u64,
    share_content: &[u8],
    response: &[u8],
) -> Result<bool, JsValue> {
    let response = VerifyShareResponseMessage::decode(response)
        .map_err(|err| to_js_error(Error::Decode(err.to_string())))?;
    Ok(verification::verify_share_response(secret_id, &channel_id, share_content, &response))
}

#[cfg(test)]
mod test;
