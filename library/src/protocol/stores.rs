// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! The set of stores a protocol instance was built with, bundled into one
//! type parameter and one value.
//!
//! Handlers differ widely in which stores they touch — across the flow
//! entry points there is no combination shared by more than a handful, and
//! the transport trait is needed by roughly half. Threading each store
//! individually made every signature a bespoke subset, so adding a store to
//! one handler rewrote its callers up the chain.
//!
//! [`Stores`] carries all of them. A handler that needs one reads one and
//! ignores the rest; the shape of a handler signature no longer encodes
//! which stores it happens to use today.

use super::{
    DeRecChannelStore, DeRecSecretStore, DeRecShareStore, DeRecStateStore, DeRecTransport,
    DeRecUserSecretStore,
};
use std::marker::PhantomData;

/// The six store and transport types a [`DeRecProtocol`] was built with,
/// named as associated types so handlers spell one type parameter instead
/// of six.
///
/// [`DeRecProtocol`]: crate::protocol::DeRecProtocol
pub(crate) trait StoreSet {
    type Channels: DeRecChannelStore;
    type Shares: DeRecShareStore;
    type Secrets: DeRecSecretStore;
    type UserSecrets: DeRecUserSecretStore;
    type State: DeRecStateStore;
    type Transport: DeRecTransport;
}

/// Uninhabited carrier that binds six concrete store types into one
/// [`StoreSet`]. Never constructed — it exists only to be named as a type
/// argument.
pub(crate) struct Set<Ch, Sh, Ss, Us, St, T>(PhantomData<(Ch, Sh, Ss, Us, St, T)>);

impl<Ch, Sh, Ss, Us, St, T> StoreSet for Set<Ch, Sh, Ss, Us, St, T>
where
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    St: DeRecStateStore,
    T: DeRecTransport,
{
    type Channels = Ch;
    type Shares = Sh;
    type Secrets = Ss;
    type UserSecrets = Us;
    type State = St;
    type Transport = T;
}

/// Borrowed handle onto every store a handler could need.
///
/// The fields are reached directly rather than through accessors so that
/// two stores can be borrowed at once: `stores.channels` and
/// `stores.secrets` are disjoint field borrows, whereas a `channels(&mut
/// self)` method would borrow the whole struct and make the many handlers
/// that use two stores together fail to compile.
///
/// `transport` is shared rather than exclusive because
/// [`DeRecTransport::send`](crate::protocol::DeRecTransport) takes `&self`;
/// holding it exclusively would conflict with a store borrow for no reason.
pub(crate) struct Stores<'a, S: StoreSet> {
    pub(crate) channels: &'a mut S::Channels,
    pub(crate) shares: &'a mut S::Shares,
    pub(crate) secrets: &'a mut S::Secrets,
    pub(crate) user_secrets: &'a mut S::UserSecrets,
    pub(crate) state: &'a mut S::State,
    pub(crate) transport: &'a S::Transport,
}

impl<'a, Ch, Sh, Ss, Us, St, T> Stores<'a, Set<Ch, Sh, Ss, Us, St, T>>
where
    Ch: DeRecChannelStore,
    Sh: DeRecShareStore,
    Ss: DeRecSecretStore,
    Us: DeRecUserSecretStore,
    St: DeRecStateStore,
    T: DeRecTransport,
{
    /// Bundle six borrowed stores.
    ///
    /// The struct literal cannot be written directly at a call site:
    /// `Stores`' fields are spelled through `S`'s associated types, and an
    /// associated type does not determine its owner, so the compiler cannot
    /// work back from six concrete stores to the `S` that names them. This
    /// constructor states `Set<Ch, ..>` in its return type, which lets
    /// inference flow from the arguments instead.
    pub(crate) fn new(
        channels: &'a mut Ch,
        shares: &'a mut Sh,
        secrets: &'a mut Ss,
        user_secrets: &'a mut Us,
        state: &'a mut St,
        transport: &'a T,
    ) -> Self {
        Self {
            channels,
            shares,
            secrets,
            user_secrets,
            state,
            transport,
        }
    }
}

/// Borrow a [`DeRecProtocol`]'s six store fields into a [`Stores`].
///
/// A `fn stores(&mut self)` cannot serve here: it would borrow the whole
/// protocol for as long as the result lives, colliding with the
/// `&self.own_transports` and `&self.communication_info` that most handler
/// calls pass alongside. Expanding to a struct literal keeps the six field
/// borrows disjoint from the rest of the protocol, so both can be live at
/// the same call.
///
/// [`DeRecProtocol`]: crate::protocol::DeRecProtocol
macro_rules! borrow_stores {
    ($protocol:expr) => {
        $crate::protocol::stores::Stores::new(
            &mut $protocol.channel_store,
            &mut $protocol.share_store,
            &mut $protocol.secret_store,
            &mut $protocol.user_secret_store,
            &mut $protocol.state_store,
            &$protocol.transport,
        )
    };
}

pub(crate) use borrow_stores;
