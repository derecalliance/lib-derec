// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

/// The `status`/`memo` check every response carries, attached as a method
/// the same way [`ContactMessageExt`] attaches structural validation to
/// [`ContactMessage`].
///
/// Every flow answers with a [`DeRecResult`](derec_proto::DeRecResult) and
/// every flow rejected the same way: compare `status` against
/// [`StatusEnum::Ok`], log, and return that flow's `NonOkStatus`. Five
/// copies of that block drifted apart only in which error enum they named,
/// which is why the constructor is a parameter rather than the check being
/// duplicated per flow.
///
/// Bring the trait into scope (`use crate::extensions::derec_result::DeRecResultExt as _;`)
/// and call `result.validate(..)?` before reading any other field of a
/// response — a non-Ok answer means the rest is not meaningful.
pub(crate) trait DeRecResultExt {
    /// `Ok(())` when the peer answered [`StatusEnum::Ok`], otherwise the
    /// error `non_ok` builds from the reported status and memo.
    ///
    /// `non_ok` takes the pair rather than the trait naming a single error
    /// type: each flow reports its own `NonOkStatus`, and collapsing them
    /// would lose which exchange failed.
    ///
    /// The warning logged on rejection does not name the flow: the enclosing
    /// `process` span already does, and the handler span above it carries the
    /// `trace_id` that attributes it to an exchange.
    fn validate<E>(&self, non_ok: impl FnOnce(i32, String) -> E) -> Result<(), E>;
}

impl DeRecResultExt for derec_proto::DeRecResult {
    fn validate<E>(&self, non_ok: impl FnOnce(i32, String) -> E) -> Result<(), E> {
        if self.status == derec_proto::StatusEnum::Ok as i32 {
            return Ok(());
        }
        #[cfg(feature = "logging")]
        tracing::warn!(
            status = self.status,
            memo = %self.memo,
            "peer answered with a non-Ok status"
        );
        Err(non_ok(self.status, self.memo.clone()))
    }
}

/// [`DeRecResultExt::validate`] logs without taking a `trace_id`: the
/// primitives they run inside are public API reached from every SDK, so
/// threading the token through them would change that surface for a logging
/// field. Instead the handler records `trace_id` on its span, and these
/// events inherit it as span context.
///
/// That is only true as long as the handler spans keep recording it, which
/// is what this asserts.
#[cfg(all(test, feature = "logging"))]
mod trace_id_span_tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};

    /// Collects everything the subscriber writes, so a test can read it back.
    #[derive(Clone, Default)]
    struct Captured(Arc<Mutex<Vec<u8>>>);

    impl io::Write for Captured {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl Captured {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).expect("utf-8")
        }
    }

    #[test]
    fn a_rejected_result_is_logged_under_the_enclosing_trace_id() {
        const TRACE_ID: u64 = 0xDEC0_DE15;

        let captured = Captured::default();
        let sink = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(move || sink.clone())
            .with_ansi(false)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            // Stands in for a handler span, which records `trace_id` the
            // same way.
            let span = tracing::info_span!("handle", trace_id = TRACE_ID);
            let _entered = span.enter();

            let result = derec_proto::DeRecResult {
                status: derec_proto::StatusEnum::Fail as i32,
                memo: "helper refused".to_owned(),
            };
            let outcome = result.validate(|status, memo| {
                crate::primitives::discovery::DiscoveryError::NonOkStatus { status, memo }
            });
            assert!(outcome.is_err(), "a non-Ok status must be rejected");
        });

        let text = captured.text();
        assert!(
            text.contains("peer answered with a non-Ok status"),
            "the validator must log the rejection; got: {text}"
        );
        assert!(
            text.contains(&TRACE_ID.to_string()),
            "the rejection must be attributable to the exchange that caused \
             it, via the enclosing span's trace_id; got: {text}"
        );
    }
}
