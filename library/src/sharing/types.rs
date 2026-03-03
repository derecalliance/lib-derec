use std::collections::HashMap;

use crate::{protos::derec_proto::StoreShareRequestMessage, types::ChannelId};

pub struct ProtectSecretResult {
    pub shares: HashMap<ChannelId, StoreShareRequestMessage>,
}
