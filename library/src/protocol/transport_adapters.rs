// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! Ready-made [`DeRecTransport`] implementations over a one-endpoint dialer.
//!
//! [`DeRecTransport::send`] receives every endpoint a peer advertised and
//! leaves the choice among them to the application, because only the
//! application knows which of its transports are healthy, cheap, or currently
//! reachable. That is the right place for the decision and it does not move.
//!
//! What moves here is the *bookkeeping* around it. The contract on `send` has
//! four rules — try the endpoints, stop at the first success, fail only when
//! none worked, never deliver twice — and none of them is about dialing. An
//! application that writes them by hand writes them once per binding, in code
//! nothing tests, to reach behaviour that is identical everywhere. Worse, the
//! shortest thing that compiles is `endpoints[0]`, which passes every test and
//! silently forfeits failover altogether.
//!
//! So implement [`SendOne`] — deliver to *one* endpoint — and wrap it:
//!
//! - [`SequentialFailover`] tries each endpoint in the order the peer offered,
//!   returning as soon as one succeeds.
//! - [`SingleEndpointTransport`] uses only the first and ignores the rest.
//!   That is what `endpoints[0]` does; the difference is that choosing this
//!   type is a decision a reader can see, and reviewing it asks a question
//!   that `endpoints[0]` does not.
//!
//! # Delivering to every endpoint is not an option
//!
//! Neither adapter fans out, and an application writing `send` by hand should
//! not either. Every endpoint in the list belongs to the same peer, so sending
//! to all of them delivers the same authenticated message N times. The
//! protocol's own handlers are idempotent, but a duplicate is still a
//! duplicate to anything counting them, and a peer that treats re-delivery as
//! a replay is entitled to.

use super::traits::{DeRecTransport, TransportFuture};
use derec_proto::TransportProtocol;

/// Deliver one message to one endpoint.
///
/// The narrow half of a transport: everything that is genuinely about dialing,
/// and nothing that is about which endpoint to dial. Implement this, then wrap
/// it in [`SequentialFailover`] or [`SingleEndpointTransport`] to get a
/// [`DeRecTransport`].
///
/// An `Err` means this endpoint did not receive the message. It is not
/// required to distinguish "unreachable" from "rejected" — [`SequentialFailover`]
/// treats both as a reason to try the next endpoint, which is the safe reading:
/// trying an endpoint that would have refused costs a round trip, while
/// skipping one that would have worked costs the delivery.
pub trait SendOne {
    /// Deliver `message` to `endpoint`, or report that it did not arrive.
    fn send_one(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> TransportFuture<'_>;
}

/// Try each endpoint in turn; the first success wins.
///
/// Implements the [`DeRecTransport::send`] contract over a [`SendOne`]:
/// endpoints are attempted in the order the peer offered them, delivery stops
/// at the first success, and an error is returned only when every endpoint
/// failed. The message is delivered at most once.
///
/// This is the right default. A peer that advertises several endpoints is
/// saying it can be reached at any of them, and the whole reason 0.0.3 records
/// the full list is so that one being down does not end the conversation.
///
/// ```no_run
/// # use derec_library::protocol::{DeRecTransport, SendOne, SequentialFailover, TransportFuture};
/// # use derec_proto::TransportProtocol;
/// struct MyDialer;
///
/// impl SendOne for MyDialer {
///     fn send_one(&self, endpoint: &TransportProtocol, message: Vec<u8>) -> TransportFuture<'_> {
///         let uri = endpoint.uri.clone();
///         Box::pin(async move {
///             // POST `message` to `uri`, or return Err if it did not arrive.
///             let _ = (uri, message);
///             Ok(())
///         })
///     }
/// }
///
/// let transport = SequentialFailover::new(MyDialer);
/// # fn assert_is_transport<T: DeRecTransport>(_: T) {}
/// # assert_is_transport(transport);
/// ```
#[derive(Clone, Copy, Debug, Default)]
pub struct SequentialFailover<T>(T);

impl<T> SequentialFailover<T> {
    /// Wrap a one-endpoint dialer.
    pub fn new(dialer: T) -> Self {
        Self(dialer)
    }

    /// The wrapped dialer.
    pub fn inner(&self) -> &T {
        &self.0
    }

    /// Unwrap, returning the dialer.
    pub fn into_inner(self) -> T {
        self.0
    }
}

/// Emit the two adapter `DeRecTransport` impls under the thread-safety bound
/// the target's [`TransportFuture`] requires.
///
/// Native futures are `Send`, so the wrapped dialer must be `Send + Sync` to
/// be held across an await. The WASM alias drops `Send` because the browser
/// is single-threaded, and requiring it there would reject dialers built on
/// `JsValue`, which is neither.
macro_rules! impl_adapters {
    ($($bound:tt)*) => {
        impl<T: SendOne $($bound)*> DeRecTransport for SequentialFailover<T> {
            fn send(
                &self,
                endpoints: &[TransportProtocol],
                message: Vec<u8>,
            ) -> TransportFuture<'_> {
                // Cloned up front because the returned future outlives this
                // borrow of `endpoints`, which belongs to the caller's
                // message-dispatch frame.
                let endpoints = endpoints.to_vec();
                Box::pin(async move {
                    let mut last: Option<crate::Error> = None;
                    for endpoint in &endpoints {
                        match self.0.send_one(endpoint, message.clone()).await {
                            Ok(()) => return Ok(()),
                            Err(e) => last = Some(e),
                        }
                    }
                    // `endpoints` is never empty — the library refuses to
                    // record a peer whose endpoints were all filtered away —
                    // so reaching here means at least one attempt was made
                    // and `last` is populated.
                    Err(last.unwrap_or(crate::Error::NoUsableEndpoint { offered: 0 }))
                })
            }
        }

        impl<T: SendOne $($bound)*> DeRecTransport for SingleEndpointTransport<T> {
            fn send(
                &self,
                endpoints: &[TransportProtocol],
                message: Vec<u8>,
            ) -> TransportFuture<'_> {
                let first = endpoints.first().cloned();
                Box::pin(async move {
                    match first {
                        Some(endpoint) => self.0.send_one(&endpoint, message).await,
                        // Unreachable through the protocol, which never calls
                        // `send` with an empty list. Reported rather than
                        // panicking because this type is also constructible
                        // in application tests.
                        None => Err(crate::Error::NoUsableEndpoint { offered: 0 }),
                    }
                })
            }
        }
    };
}

#[cfg(not(target_arch = "wasm32"))]
impl_adapters!(+ Send + Sync);
#[cfg(target_arch = "wasm32")]
impl_adapters!();

/// Use the first endpoint only.
///
/// Reproduces the pre-0.0.3 behaviour exactly, for an application that
/// genuinely serves one endpoint or has a reason not to fail over.
///
/// It exists so that choosing it is visible. `endpoints[0]` written inline
/// looks like an implementation detail and reads as finished; naming this type
/// records that failover was considered and declined, which is a claim a
/// reviewer can disagree with.
///
/// If the peers this application talks to advertise more than one endpoint,
/// prefer [`SequentialFailover`] — every endpoint after the first is
/// reachability this is throwing away.
#[derive(Clone, Copy, Debug, Default)]
pub struct SingleEndpointTransport<T>(T);

impl<T> SingleEndpointTransport<T> {
    /// Wrap a one-endpoint dialer.
    pub fn new(dialer: T) -> Self {
        Self(dialer)
    }

    /// The wrapped dialer.
    pub fn inner(&self) -> &T {
        &self.0
    }

    /// Unwrap, returning the dialer.
    pub fn into_inner(self) -> T {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use derec_proto::Protocol;
    use std::sync::Mutex;

    fn endpoint(uri: &str) -> TransportProtocol {
        TransportProtocol {
            uri: uri.to_owned(),
            protocol: Protocol::Https as i32,
        }
    }

    /// Records every endpoint it was asked to dial, and fails the ones named.
    #[derive(Default)]
    struct Recorder {
        attempted: Mutex<Vec<String>>,
        fail: Vec<String>,
    }

    impl Recorder {
        fn failing(fail: &[&str]) -> Self {
            Self {
                attempted: Mutex::new(Vec::new()),
                fail: fail.iter().map(|s| (*s).to_owned()).collect(),
            }
        }

        fn attempted(&self) -> Vec<String> {
            self.attempted.lock().unwrap().clone()
        }
    }

    impl SendOne for Recorder {
        fn send_one(&self, endpoint: &TransportProtocol, _message: Vec<u8>) -> TransportFuture<'_> {
            self.attempted.lock().unwrap().push(endpoint.uri.clone());
            let refused = self.fail.contains(&endpoint.uri);
            Box::pin(async move {
                if refused {
                    Err(crate::Error::InvalidInput("endpoint refused"))
                } else {
                    Ok(())
                }
            })
        }
    }

    /// Polls to completion with the stdlib no-op waker.
    ///
    /// Sound here because nothing under test ever returns `Pending` for an
    /// external reason: the adapters await only the dialer, and the test
    /// dialers are immediate. Keeps these tests free of a runtime dependency.
    fn block_on<F: Future>(mut f: F) -> F::Output {
        use std::task::{Context, Poll, Waker};

        let waker = Waker::noop();
        let mut cx = Context::from_waker(waker);
        // SAFETY: `f` is owned by this frame and never moved after pinning.
        let mut f = unsafe { std::pin::Pin::new_unchecked(&mut f) };
        loop {
            match f.as_mut().poll(&mut cx) {
                Poll::Ready(v) => return v,
                Poll::Pending => continue,
            }
        }
    }

    #[test]
    fn failover_stops_at_the_first_success() {
        let t = SequentialFailover::new(Recorder::default());
        let endpoints = [endpoint("https://a.example"), endpoint("https://b.example")];

        block_on(t.send(&endpoints, vec![1])).expect("the first endpoint answers");

        assert_eq!(
            t.inner().attempted(),
            ["https://a.example"],
            "a message delivered to the first endpoint must not also go to the second"
        );
    }

    #[test]
    fn failover_advances_past_a_failing_endpoint() {
        let t = SequentialFailover::new(Recorder::failing(&["https://a.example"]));
        let endpoints = [endpoint("https://a.example"), endpoint("https://b.example")];

        block_on(t.send(&endpoints, vec![1])).expect("the second endpoint answers");

        assert_eq!(
            t.inner().attempted(),
            ["https://a.example", "https://b.example"],
            "the peer offered a working endpoint and it has to be tried"
        );
    }

    #[test]
    fn failover_tries_the_peers_order_not_its_own() {
        let t = SequentialFailover::new(Recorder::failing(&["https://first.example"]));
        let endpoints = [
            endpoint("https://first.example"),
            endpoint("https://second.example"),
            endpoint("https://third.example"),
        ];

        block_on(t.send(&endpoints, vec![1])).expect("the second endpoint answers");

        assert_eq!(
            t.inner().attempted(),
            ["https://first.example", "https://second.example"],
            "the order is the peer's and is not reinterpreted"
        );
    }

    #[test]
    fn failover_fails_only_when_every_endpoint_did() {
        let t = SequentialFailover::new(Recorder::failing(&[
            "https://a.example",
            "https://b.example",
        ]));
        let endpoints = [endpoint("https://a.example"), endpoint("https://b.example")];

        block_on(t.send(&endpoints, vec![1])).expect_err("no endpoint accepted the message");

        assert_eq!(
            t.inner().attempted(),
            ["https://a.example", "https://b.example"],
            "every endpoint must be tried before the send is called a failure"
        );
    }

    #[test]
    fn single_endpoint_ignores_the_rest() {
        let t = SingleEndpointTransport::new(Recorder::default());
        let endpoints = [endpoint("https://a.example"), endpoint("https://b.example")];

        block_on(t.send(&endpoints, vec![1])).expect("the first endpoint answers");

        assert_eq!(t.inner().attempted(), ["https://a.example"]);
    }

    /// The distinguishing property: where `SequentialFailover` would recover,
    /// this reports the failure. That is the cost of choosing it, made
    /// observable so a test can state it.
    #[test]
    fn single_endpoint_does_not_fall_back() {
        let t = SingleEndpointTransport::new(Recorder::failing(&["https://a.example"]));
        let endpoints = [endpoint("https://a.example"), endpoint("https://b.example")];

        block_on(t.send(&endpoints, vec![1])).expect_err("the only endpoint tried was refused");

        assert_eq!(
            t.inner().attempted(),
            ["https://a.example"],
            "the second endpoint is deliberately never tried"
        );
    }
}
