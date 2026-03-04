use crate::{protos::derec_proto::StoreShareRequestMessage, types::ChannelId};
use std::collections::HashMap;

pub struct ProtectSecretResult {
    pub shares: HashMap<ChannelId, StoreShareRequestMessage>,
}
