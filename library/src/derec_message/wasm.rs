// use super::builder::{DeRecMessageBuilder, DeRecMessageBuilderError};
// use super::codec::{
//     DeRecMessageCodec, DeRecMessageCodecError, DeRecMessageDecrypter, DeRecMessageEncrypter,
//     DeRecMessageSigner, DeRecMessageVerifier, VerifiedPayload, WireMessage,
// };
// use derec_proto::{
//     DeRecMessage, ErrorResponseMessage, GetSecretIdsVersionsRequestMessage,
//     GetSecretIdsVersionsResponseMessage, GetShareRequestMessage, GetShareResponseMessage,
//     PairRequestMessage, PairResponseMessage, StoreShareRequestMessage, StoreShareResponseMessage,
//     UnpairRequestMessage, UnpairResponseMessage, VerifyShareRequestMessage,
//     VerifyShareResponseMessage,
// };
// use js_sys::{Array, Function, Reflect, Uint8Array};
// use prost::Message;
// use prost_types::Timestamp;
// use serde::Serialize;
// use serde_wasm_bindgen::to_value;
// use wasm_bindgen::prelude::*;
//
// #[derive(Serialize)]
// #[serde(rename_all = "camelCase")]
// struct WireMessageJs {
//     recipient_key_id: i32,
//     payload: Vec<u8>,
// }
//
// struct JsSigner {
//     inner: JsValue,
//     sender_key_hash: Vec<u8>,
// }
//
// impl JsSigner {
//     fn new(inner: JsValue) -> Result<Self, JsValue> {
//         let sender_key_hash =
//             js_method_bytes(&inner, "senderKeyHash").map_err(|e| JsValue::from_str(&e))?;
//
//         Ok(Self {
//             inner,
//             sender_key_hash,
//         })
//     }
// }
//
// impl DeRecMessageSigner for JsSigner {
//     fn sender_key_hash(&self) -> &[u8] {
//         &self.sender_key_hash
//     }
//
//     fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError> {
//         js_call_bytes(&self.inner, "sign", payload).map_err(DeRecMessageCodecError::Signing)
//     }
// }
//
// struct JsVerifier {
//     inner: JsValue,
// }
//
// impl JsVerifier {
//     fn new(inner: JsValue) -> Self {
//         Self { inner }
//     }
// }
//
// impl DeRecMessageVerifier for JsVerifier {
//     fn verify(&self, signed_payload: &[u8]) -> Result<VerifiedPayload, DeRecMessageCodecError> {
//         js_call_verify(&self.inner, signed_payload).map_err(DeRecMessageCodecError::Verification)
//     }
// }
//
// struct JsEncrypter {
//     inner: JsValue,
//     recipient_key_id: i32,
//     recipient_key_hash: Vec<u8>,
// }
//
// impl JsEncrypter {
//     fn new(inner: JsValue) -> Result<Self, JsValue> {
//         let recipient_key_id =
//             js_method_i32(&inner, "recipientKeyId").map_err(|e| JsValue::from_str(&e))?;
//         let recipient_key_hash =
//             js_method_bytes(&inner, "recipientKeyHash").map_err(|e| JsValue::from_str(&e))?;
//
//         Ok(Self {
//             inner,
//             recipient_key_id,
//             recipient_key_hash,
//         })
//     }
// }
//
// impl DeRecMessageEncrypter for JsEncrypter {
//     fn recipient_key_id(&self) -> i32 {
//         self.recipient_key_id
//     }
//
//     fn recipient_key_hash(&self) -> &[u8] {
//         &self.recipient_key_hash
//     }
//
//     fn encrypt(&self, signed_payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError> {
//         js_call_bytes(&self.inner, "encrypt", signed_payload)
//             .map_err(DeRecMessageCodecError::Encryption)
//     }
// }
//
// struct JsDecrypter {
//     inner: JsValue,
//     recipient_key_id: i32,
//     recipient_key_hash: Vec<u8>,
// }
//
// impl JsDecrypter {
//     fn new(inner: JsValue) -> Result<Self, JsValue> {
//         let recipient_key_id =
//             js_method_i32(&inner, "recipientKeyId").map_err(|e| JsValue::from_str(&e))?;
//         let recipient_key_hash =
//             js_method_bytes(&inner, "recipientKeyHash").map_err(|e| JsValue::from_str(&e))?;
//
//         Ok(Self {
//             inner,
//             recipient_key_id,
//             recipient_key_hash,
//         })
//     }
// }
//
// impl DeRecMessageDecrypter for JsDecrypter {
//     fn recipient_key_id(&self) -> i32 {
//         self.recipient_key_id
//     }
//
//     fn recipient_key_hash(&self) -> &[u8] {
//         &self.recipient_key_hash
//     }
//
//     fn decrypt(&self, encrypted_payload: &[u8]) -> Result<Vec<u8>, DeRecMessageCodecError> {
//         js_call_bytes(&self.inner, "decrypt", encrypted_payload)
//             .map_err(DeRecMessageCodecError::Decryption)
//     }
// }
//
// #[wasm_bindgen]
// pub fn build_derec_message(
//     sender: &[u8],
//     receiver: &[u8],
//     secret_id: &[u8],
//     owner_messages: JsValue,
//     helper_messages: JsValue,
//     timestamp_ms: Option<i64>,
// ) -> Result<Vec<u8>, JsValue> {
//     let owner_messages = js_array_of_uint8arrays(owner_messages)?;
//     let helper_messages = js_array_of_uint8arrays(helper_messages)?;
//
//     let mut builder = DeRecMessageBuilder::new()
//         .sender(sender)
//         .receiver(receiver)
//         .secret_id(secret_id)
//         .map_err(builder_err_to_js)?;
//
//     if let Some(ms) = timestamp_ms {
//         builder = builder.timestamp(timestamp_from_millis(ms));
//     } else {
//         builder = builder.timestamp(current_js_timestamp());
//     }
//
//     for message in owner_messages {
//         builder = add_owner_message(builder, &message)?;
//     }
//
//     for message in helper_messages {
//         builder = add_helper_message(builder, &message)?;
//     }
//
//     let derec_message = builder.build().map_err(builder_err_to_js)?;
//     Ok(derec_message.encode_to_vec())
// }
//
// #[wasm_bindgen]
// pub fn serialize_derec_message(message_bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
//     let message = DeRecMessage::decode(message_bytes)
//         .map_err(|e| JsValue::from_str(&format!("invalid DeRecMessage protobuf: {e}")))?;
//
//     Ok(message.encode_to_vec())
// }
//
// #[wasm_bindgen]
// pub fn deserialize_derec_message(bytes: &[u8]) -> Result<Vec<u8>, JsValue> {
//     let message = DeRecMessage::decode(bytes)
//         .map_err(|e| JsValue::from_str(&format!("invalid DeRecMessage protobuf: {e}")))?;
//
//     Ok(message.encode_to_vec())
// }
//
// #[wasm_bindgen]
// pub fn encode_derec_message(
//     message_bytes: &[u8],
//     signer: JsValue,
//     encrypter: JsValue,
// ) -> Result<Vec<u8>, JsValue> {
//     let message = DeRecMessage::decode(message_bytes)
//         .map_err(|e| JsValue::from_str(&format!("invalid DeRecMessage protobuf: {e}")))?;
//
//     let signer = JsSigner::new(signer)?;
//     let encrypter = JsEncrypter::new(encrypter)?;
//
//     DeRecMessageCodec::encode_to_bytes(&message, &signer, &encrypter).map_err(codec_err_to_js)
// }
//
// #[wasm_bindgen]
// pub fn decode_derec_message(
//     wire_bytes: &[u8],
//     decrypter: JsValue,
//     verifier: JsValue,
// ) -> Result<Vec<u8>, JsValue> {
//     let decrypter = JsDecrypter::new(decrypter)?;
//     let verifier = JsVerifier::new(verifier);
//
//     let message = DeRecMessageCodec::decode_from_bytes(wire_bytes, &decrypter, &verifier)
//         .map_err(codec_err_to_js)?;
//
//     Ok(message.encode_to_vec())
// }
//
// #[wasm_bindgen]
// pub fn wire_message_to_bytes(recipient_key_id: i32, payload: &[u8]) -> Vec<u8> {
//     let wire = WireMessage {
//         recipient_key_id,
//         payload: payload.to_vec(),
//     };
//
//     wire.to_bytes()
// }
//
// #[wasm_bindgen]
// pub fn wire_message_from_bytes(bytes: &[u8]) -> Result<JsValue, JsValue> {
//     let wire = WireMessage::from_bytes(bytes).map_err(codec_err_to_js)?;
//
//     to_value(&WireMessageJs {
//         recipient_key_id: wire.recipient_key_id,
//         payload: wire.payload,
//     })
//     .map_err(|e| JsValue::from_str(&e.to_string()))
// }
//
// fn js_array_of_uint8arrays(value: JsValue) -> Result<Vec<Vec<u8>>, JsValue> {
//     let array = Array::from(&value);
//
//     array
//         .iter()
//         .map(|item| {
//             if !item.is_object() {
//                 return Err(JsValue::from_str("expected an array of Uint8Array values"));
//             }
//
//             Ok(Uint8Array::new(&item).to_vec())
//         })
//         .collect()
// }
//
// fn builder_err_to_js(err: DeRecMessageBuilderError) -> JsValue {
//     JsValue::from_str(&err.to_string())
// }
//
// fn codec_err_to_js(err: DeRecMessageCodecError) -> JsValue {
//     JsValue::from_str(&err.to_string())
// }
//
// fn get_method(obj: &JsValue, name: &str) -> Result<Function, String> {
//     let value = Reflect::get(obj, &JsValue::from_str(name))
//         .map_err(|_| format!("failed to get method `{name}` from JS object"))?;
//
//     value
//         .dyn_into::<Function>()
//         .map_err(|_| format!("property `{name}` is not a function"))
// }
//
// fn js_method_bytes(obj: &JsValue, name: &str) -> Result<Vec<u8>, String> {
//     let method = get_method(obj, name)?;
//     let value = method
//         .call0(obj)
//         .map_err(|_| format!("JS method `{name}` failed"))?;
//
//     Ok(Uint8Array::new(&value).to_vec())
// }
//
// fn js_method_i32(obj: &JsValue, name: &str) -> Result<i32, String> {
//     let method = get_method(obj, name)?;
//     let value = method
//         .call0(obj)
//         .map_err(|_| format!("JS method `{name}` failed"))?;
//
//     let number = value
//         .as_f64()
//         .ok_or_else(|| format!("JS method `{name}` did not return a number"))?;
//
//     Ok(number as i32)
// }
//
// fn js_call_bytes(obj: &JsValue, name: &str, input: &[u8]) -> Result<Vec<u8>, String> {
//     let method = get_method(obj, name)?;
//     let arg = Uint8Array::from(input);
//
//     let value = method
//         .call1(obj, &arg.into())
//         .map_err(|_| format!("JS method `{name}` failed"))?;
//
//     Ok(Uint8Array::new(&value).to_vec())
// }
//
// fn js_call_verify(obj: &JsValue, signed_payload: &[u8]) -> Result<VerifiedPayload, String> {
//     let method = get_method(obj, "verify")?;
//     let arg = Uint8Array::from(signed_payload);
//
//     let value = method
//         .call1(obj, &arg.into())
//         .map_err(|_| "JS method `verify` failed".to_string())?;
//
//     let payload = Reflect::get(&value, &JsValue::from_str("payload"))
//         .map_err(|_| "missing `payload` in verify result".to_string())?;
//     let signer_key_hash = Reflect::get(&value, &JsValue::from_str("signerKeyHash"))
//         .map_err(|_| "missing `signerKeyHash` in verify result".to_string())?;
//
//     Ok(VerifiedPayload {
//         payload: Uint8Array::new(&payload).to_vec(),
//         signer_key_hash: Uint8Array::new(&signer_key_hash).to_vec(),
//     })
// }
//
// fn current_js_timestamp() -> Timestamp {
//     let now_ms = js_sys::Date::now() as i64;
//
//     let seconds = now_ms / 1000;
//     let nanos = ((now_ms % 1000) * 1_000_000) as i32;
//
//     Timestamp { seconds, nanos }
// }
//
// fn timestamp_from_millis(ms: i64) -> Timestamp {
//     let seconds = ms / 1000;
//     let nanos = ((ms % 1000) * 1_000_000) as i32;
//
//     Timestamp { seconds, nanos }
// }
//
// fn add_owner_message(
//     builder: DeRecMessageBuilder,
//     message_bytes: &[u8],
// ) -> Result<DeRecMessageBuilder, JsValue> {
//     if let Ok(msg) = PairRequestMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//     if let Ok(msg) = UnpairRequestMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//     if let Ok(msg) = StoreShareRequestMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//     if let Ok(msg) = VerifyShareRequestMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//     if let Ok(msg) = GetSecretIdsVersionsRequestMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//     if let Ok(msg) = GetShareRequestMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//
//     Err(JsValue::from_str(
//         "unsupported or invalid owner message protobuf",
//     ))
// }
//
// fn add_helper_message(
//     builder: DeRecMessageBuilder,
//     message_bytes: &[u8],
// ) -> Result<DeRecMessageBuilder, JsValue> {
//     if let Ok(msg) = PairResponseMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//     if let Ok(msg) = UnpairResponseMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//     if let Ok(msg) = StoreShareResponseMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//     if let Ok(msg) = VerifyShareResponseMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//     if let Ok(msg) = GetSecretIdsVersionsResponseMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//     if let Ok(msg) = GetShareResponseMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//     if let Ok(msg) = ErrorResponseMessage::decode(message_bytes) {
//         return builder.message(msg).map_err(builder_err_to_js);
//     }
//
//     Err(JsValue::from_str(
//         "unsupported or invalid helper message protobuf",
//     ))
// }
