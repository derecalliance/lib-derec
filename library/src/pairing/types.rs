use derec_cryptography::pairing::{self as cryptography_pairing, PairingSecretKeyMaterial};
use derec_proto;

pub struct CreateContactMessageResult {
    pub contact_message: derec_proto::ContactMessage,
    pub secret_key: PairingSecretKeyMaterial,
}

pub struct ProducePairingRequestMessageResult {
    pub pair_request_message: derec_proto::PairRequestMessage,
    pub secret_key: PairingSecretKeyMaterial,
}

pub struct ProducePairingResponseMessageResult {
    pub pair_response_message: derec_proto::PairResponseMessage,
    pub shared_key: cryptography_pairing::PairingSharedKey,
}

pub struct ProcessPairingResponseMessageResult {
    pub shared_key: cryptography_pairing::PairingSharedKey,
}
