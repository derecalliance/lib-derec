use crate::types::ChannelId;
use derec_proto::StoreShareRequestMessage;
use std::collections::HashMap;

pub struct ProtectSecretResult {
    pub shares: HashMap<ChannelId, StoreShareRequestMessage>,
}
