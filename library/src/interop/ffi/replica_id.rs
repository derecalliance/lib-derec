// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

/// A fresh replica identity. See [`crate::generate_replica_id`]: the caller
/// persists it once per device and passes the same value on every protocol
/// init. Never `0`.
#[unsafe(no_mangle)]
pub extern "C" fn derec_generate_replica_id() -> u64 {
    crate::generate_replica_id()
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_generated_id_is_a_valid_replica_id() {
        for _ in 0..64 {
            let id = super::derec_generate_replica_id();
            assert!(
                crate::types::ReplicaId::try_from(id).is_ok(),
                "{id} is not a valid replica id"
            );
        }
    }
}
