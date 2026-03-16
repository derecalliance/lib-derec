use crate::ffi::common::{
    DeRecBuffer, DeRecStatus, empty_buffer, err_status, ok_status, read_len_prefixed_vec,
    read_optional_len_prefixed_vec, vec_into_buffer, write_len_prefixed,
    write_optional_len_prefixed,
};
use derec_cryptography::pairing::PairingSecretKeyMaterial;
use derec_proto::{ContactMessage, SenderKind};
use prost::Message;

#[repr(C)]
pub struct CreateContactMessageResult {
    pub status: DeRecStatus,
    pub contact_message: DeRecBuffer,
    pub secret_key_material: DeRecBuffer,
}

#[repr(C)]
pub struct ProducePairingRequestMessageResult {
    pub status: DeRecStatus,
    pub pair_request_message: DeRecBuffer,
    pub secret_key_material: DeRecBuffer,
}

#[repr(C)]
pub struct ProducePairingResponseMessageResult {
    pub status: DeRecStatus,
    pub pair_response_message: DeRecBuffer,
    pub shared_key: DeRecBuffer,
}

#[repr(C)]
pub struct ProcessPairingResponseMessageResult {
    pub status: DeRecStatus,
    pub shared_key: DeRecBuffer,
}

#[unsafe(no_mangle)]
pub extern "C" fn create_contact_message(
    channel_id: u64,
    transport_uri_ptr: *const u8,
    transport_uri_len: usize,
) -> CreateContactMessageResult {
    if transport_uri_ptr.is_null() {
        return CreateContactMessageResult {
            status: err_status("transport_uri_ptr is null"),
            contact_message: empty_buffer(),
            secret_key_material: empty_buffer(),
        };
    }

    let transport_uri_bytes =
        unsafe { std::slice::from_raw_parts(transport_uri_ptr, transport_uri_len) };

    let transport_uri = match std::str::from_utf8(transport_uri_bytes) {
        Ok(value) => value,
        Err(_) => {
            return CreateContactMessageResult {
                status: err_status("transport_uri is not valid UTF-8"),
                contact_message: empty_buffer(),
                secret_key_material: empty_buffer(),
            };
        }
    };

    let result = match crate::pairing::create_contact_message(channel_id.into(), transport_uri) {
        Ok(value) => value,
        Err(err) => {
            return CreateContactMessageResult {
                status: err_status(err.to_string()),
                contact_message: empty_buffer(),
                secret_key_material: empty_buffer(),
            };
        }
    };

    let contact_message_bytes = result.contact_message.encode_to_vec();
    let secret_key_material_bytes = serialize_pairing_secret_key_material(&result.secret_key);

    CreateContactMessageResult {
        status: ok_status(),
        contact_message: vec_into_buffer(contact_message_bytes),
        secret_key_material: vec_into_buffer(secret_key_material_bytes),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn produce_pairing_request_message(
    channel_id: u64,
    peer_status: i32,
    contact_message_ptr: *const u8,
    contact_message_len: usize,
) -> ProducePairingRequestMessageResult {
    if contact_message_ptr.is_null() {
        return ProducePairingRequestMessageResult {
            status: err_status("contact_message_ptr is null"),
            pair_request_message: empty_buffer(),
            secret_key_material: empty_buffer(),
        };
    }

    let contact_message_bytes =
        unsafe { std::slice::from_raw_parts(contact_message_ptr, contact_message_len) };

    let contact_message = match ContactMessage::decode(contact_message_bytes) {
        Ok(value) => value,
        Err(err) => {
            return ProducePairingRequestMessageResult {
                status: err_status(format!("invalid ContactMessage protobuf: {err}")),
                pair_request_message: empty_buffer(),
                secret_key_material: empty_buffer(),
            };
        }
    };

    let sender_kind = match SenderKind::try_from(peer_status) {
        Ok(v) => v,
        Err(_) => {
            return ProducePairingRequestMessageResult {
                status: err_status(format!("invalid SenderKind value: {peer_status}")),
                pair_request_message: empty_buffer(),
                secret_key_material: empty_buffer(),
            };
        }
    };

    let result = match crate::pairing::produce_pairing_request_message(
        channel_id.into(),
        sender_kind,
        &contact_message,
    ) {
        Ok(value) => value,
        Err(err) => {
            return ProducePairingRequestMessageResult {
                status: err_status(err.to_string()),
                pair_request_message: empty_buffer(),
                secret_key_material: empty_buffer(),
            };
        }
    };

    let pair_request_message_bytes = result.pair_request_message.encode_to_vec();
    let secret_key_material_bytes = serialize_pairing_secret_key_material(&result.secret_key);

    ProducePairingRequestMessageResult {
        status: ok_status(),
        pair_request_message: vec_into_buffer(pair_request_message_bytes),
        secret_key_material: vec_into_buffer(secret_key_material_bytes),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn produce_pairing_response_message(
    peer_status: i32,
    pair_request_message_ptr: *const u8,
    pair_request_message_len: usize,
    secret_key_material_ptr: *const u8,
    secret_key_material_len: usize,
) -> ProducePairingResponseMessageResult {
    if pair_request_message_ptr.is_null() {
        return ProducePairingResponseMessageResult {
            status: err_status("pair_request_message_ptr is null"),
            pair_response_message: empty_buffer(),
            shared_key: empty_buffer(),
        };
    }

    if secret_key_material_ptr.is_null() {
        return ProducePairingResponseMessageResult {
            status: err_status("secret_key_material_ptr is null"),
            pair_response_message: empty_buffer(),
            shared_key: empty_buffer(),
        };
    }

    let sender_kind = match SenderKind::try_from(peer_status) {
        Ok(v) => v,
        Err(_) => {
            return ProducePairingResponseMessageResult {
                status: err_status(format!("invalid SenderKind value: {peer_status}")),
                pair_response_message: empty_buffer(),
                shared_key: empty_buffer(),
            };
        }
    };

    let pair_request_message_bytes =
        unsafe { std::slice::from_raw_parts(pair_request_message_ptr, pair_request_message_len) };

    let pair_request_message =
        match derec_proto::PairRequestMessage::decode(pair_request_message_bytes) {
            Ok(value) => value,
            Err(err) => {
                return ProducePairingResponseMessageResult {
                    status: err_status(format!("invalid PairRequestMessage protobuf: {err}")),
                    pair_response_message: empty_buffer(),
                    shared_key: empty_buffer(),
                };
            }
        };

    let secret_key_material_bytes =
        unsafe { std::slice::from_raw_parts(secret_key_material_ptr, secret_key_material_len) };

    let pairing_secret_key_material =
        match deserialize_pairing_secret_key_material(secret_key_material_bytes) {
            Ok(value) => value,
            Err(err) => {
                return ProducePairingResponseMessageResult {
                    status: err_status(format!("invalid secret key material: {err}")),
                    pair_response_message: empty_buffer(),
                    shared_key: empty_buffer(),
                };
            }
        };

    let result = match crate::pairing::produce_pairing_response_message(
        sender_kind,
        &pair_request_message,
        &pairing_secret_key_material,
    ) {
        Ok(value) => value,
        Err(err) => {
            return ProducePairingResponseMessageResult {
                status: err_status(err.to_string()),
                pair_response_message: empty_buffer(),
                shared_key: empty_buffer(),
            };
        }
    };

    let pair_response_message_bytes = result.pair_response_message.encode_to_vec();
    let shared_key_bytes = serialize_pairing_shared_key(&result.shared_key);

    ProducePairingResponseMessageResult {
        status: ok_status(),
        pair_response_message: vec_into_buffer(pair_response_message_bytes),
        shared_key: vec_into_buffer(shared_key_bytes),
    }
}

#[unsafe(no_mangle)]
pub extern "C" fn process_pairing_response_message(
    contact_message_ptr: *const u8,
    contact_message_len: usize,
    pair_response_message_ptr: *const u8,
    pair_response_message_len: usize,
    secret_key_material_ptr: *const u8,
    secret_key_material_len: usize,
) -> ProcessPairingResponseMessageResult {
    if contact_message_ptr.is_null() {
        return ProcessPairingResponseMessageResult {
            status: err_status("contact_message_ptr is null"),
            shared_key: empty_buffer(),
        };
    }

    if pair_response_message_ptr.is_null() {
        return ProcessPairingResponseMessageResult {
            status: err_status("pair_response_message_ptr is null"),
            shared_key: empty_buffer(),
        };
    }

    if secret_key_material_ptr.is_null() {
        return ProcessPairingResponseMessageResult {
            status: err_status("secret_key_material_ptr is null"),
            shared_key: empty_buffer(),
        };
    }

    let contact_message_bytes =
        unsafe { std::slice::from_raw_parts(contact_message_ptr, contact_message_len) };

    let contact_message = match derec_proto::ContactMessage::decode(contact_message_bytes) {
        Ok(value) => value,
        Err(err) => {
            return ProcessPairingResponseMessageResult {
                status: err_status(format!("invalid ContactMessage protobuf: {err}")),
                shared_key: empty_buffer(),
            };
        }
    };

    let pair_response_message_bytes =
        unsafe { std::slice::from_raw_parts(pair_response_message_ptr, pair_response_message_len) };

    let pair_response_message =
        match derec_proto::PairResponseMessage::decode(pair_response_message_bytes) {
            Ok(value) => value,
            Err(err) => {
                return ProcessPairingResponseMessageResult {
                    status: err_status(format!("invalid PairResponseMessage protobuf: {err}")),
                    shared_key: empty_buffer(),
                };
            }
        };

    let secret_key_material_bytes =
        unsafe { std::slice::from_raw_parts(secret_key_material_ptr, secret_key_material_len) };

    let pairing_secret_key_material =
        match deserialize_pairing_secret_key_material(secret_key_material_bytes) {
            Ok(value) => value,
            Err(err) => {
                return ProcessPairingResponseMessageResult {
                    status: err_status(format!("invalid secret key material: {err}")),
                    shared_key: empty_buffer(),
                };
            }
        };

    let result = match crate::pairing::process_pairing_response_message(
        &contact_message,
        &pair_response_message,
        &pairing_secret_key_material,
    ) {
        Ok(value) => value,
        Err(err) => {
            return ProcessPairingResponseMessageResult {
                status: err_status(err.to_string()),
                shared_key: empty_buffer(),
            };
        }
    };

    let shared_key_bytes = serialize_pairing_shared_key(&result.shared_key);

    ProcessPairingResponseMessageResult {
        status: ok_status(),
        shared_key: vec_into_buffer(shared_key_bytes),
    }
}

fn serialize_pairing_secret_key_material(sk: &PairingSecretKeyMaterial) -> Vec<u8> {
    let mut out = Vec::new();

    write_optional_len_prefixed(&mut out, sk.mlkem_decapsulation_key.as_deref());

    write_optional_len_prefixed(
        &mut out,
        sk.mlkem_shared_secret.as_ref().map(|x| x.as_slice()),
    );

    write_len_prefixed(&mut out, &sk.ecies_secret_key);

    out
}

fn deserialize_pairing_secret_key_material(
    bytes: &[u8],
) -> Result<PairingSecretKeyMaterial, String> {
    let mut input = bytes;

    let mlkem_decapsulation_key = read_optional_len_prefixed_vec(&mut input)?;

    let mlkem_shared_secret = match read_optional_len_prefixed_vec(&mut input)? {
        Some(vec) => {
            let array: [u8; 32] = vec
                .try_into()
                .map_err(|_| "mlkem_shared_secret must be exactly 32 bytes".to_string())?;
            Some(array)
        }
        None => None,
    };

    let ecies_secret_key = read_len_prefixed_vec(&mut input)?;

    if !input.is_empty() {
        return Err("unexpected trailing bytes in secret key material".to_string());
    }

    Ok(PairingSecretKeyMaterial {
        mlkem_decapsulation_key,
        mlkem_shared_secret,
        ecies_secret_key,
    })
}

fn serialize_pairing_shared_key(
    shared_key: &derec_cryptography::pairing::PairingSharedKey,
) -> Vec<u8> {
    shared_key.to_vec()
}
