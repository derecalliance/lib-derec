// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Behaviour attached to types this crate does not own.
//!
//! Almost everything the protocol reads off the wire is a `derec-proto` type,
//! and every one of them is generated. An inherent `impl` on a foreign type is
//! impossible, so the behaviour that belongs *to* a message — validating it,
//! reading what it advertises, converting it to the shape the core protocol
//! uses — is attached through an extension trait instead.
//!
//! One file per trait, named for the type it extends. Bring a trait into scope
//! at the call site (`use crate::extensions::contact_message::ContactMessageExt
//! as _;`) and call the methods on the value itself.
//!
//! # Why these are traits and not free functions
//!
//! A free `validate(&contact)` is a function a new call site can forget to
//! call. `contact.validate()?` reads as part of handling the message, sits in
//! autocomplete next to the type's own fields, and puts the rule in one place
//! rather than once per reader — which is what each of these replaced.
//!
//! # The one trait here that does not extend a proto type
//!
//! `channel_store` extends [`DeRecChannelStore`](crate::protocol::DeRecChannelStore),
//! a trait this crate defines and applications implement. It is here because
//! it is the same pattern for the same reason — behaviour that cannot be an
//! inherent `impl`, since the implementing type belongs to the application.

pub mod advertised_endpoints;
pub(crate) mod channel_store;
pub(crate) mod committed_derec_share;
pub(crate) mod communication_info;
pub(crate) mod contact_message;
pub(crate) mod derec_result;
pub(crate) mod derec_share;
pub(crate) mod message_body;
pub(crate) mod pair_request;
pub(crate) mod pre_pair_request;
pub(crate) mod sender_kind;
pub mod transport_protocol;
pub(crate) mod verify_share_response;
