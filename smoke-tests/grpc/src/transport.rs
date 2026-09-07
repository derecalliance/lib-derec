// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 DeRec Alliance. All rights reserved.

//! A `DeRecTransport` that delivers envelopes as unary gRPC calls.

use derec_library::protocol::{DeRecTransport, TransportFuture};
use derec_proto::{DeRecMessage, TransportProtocol};
use prost::Message as _;

pub mod pb {
    tonic::include_proto!("org.derecalliance.derec.protobuf");
}

use pb::de_rec_transport_client::DeRecTransportClient;

/// Rewrite a DeRec endpoint URI into the http-family URL a gRPC client dials.
///
/// `grpc://` and `grpcs://` are the spellings the protocol validates and
/// advertises in contacts and pairing messages; the wire underneath is
/// ordinary HTTP/2, so the client needs `http://` / `https://`.
///
/// The two branches are not symmetric in practice. `grpcs://` produces an
/// `https://` URL, and a default-features `tonic` cannot dial one — it is
/// built without a TLS backend, so the connection fails at runtime rather
/// than at compile time. Enable a TLS feature on the `tonic` dependency
/// (`tls-ring` or `tls-aws-lc`, plus `tls-native-roots` or
/// `tls-webpki-roots` for a trust anchor set) and configure the channel
/// with `ClientTlsConfig` before advertising a `grpcs://` endpoint. This
/// smoke test is plaintext-only and does not enable them.
pub fn dial_uri(uri: &str) -> String {
    uri.replacen("grpcs://", "https://", 1)
        .replacen("grpc://", "http://", 1)
}

/// Delivers each envelope as one unary `DeRecTransport.Send` call.
///
/// Delivery is push-only: `Send` resolves to `google.protobuf.Empty`, so a
/// protocol response is never carried back on this call. The peer answers by
/// opening its own `Send` against this node's advertised endpoint, which is
/// why every participant must also run a server.
#[derive(Clone, Default)]
pub struct GrpcTransport;

impl DeRecTransport for GrpcTransport {
    fn send(&self, endpoints: &[TransportProtocol], message: Vec<u8>) -> TransportFuture<'_> {
        // The library hands over every endpoint the peer advertised, in the
        // peer's order, and takes no view on which to use. Choosing — and
        // failing over when one is unreachable — is this transport's job.
        //
        // Trying them in order is the simplest useful policy. A real
        // deployment might prefer by cost, pin to one it knows is healthy, or
        // race them; none of that is the library's business.
        let dials: Vec<String> = endpoints.iter().map(|e| dial_uri(&e.uri)).collect();

        Box::pin(async move {
            let envelope = DeRecMessage::decode(message.as_slice())
                .map_err(derec_library::Error::ProtobufDecode)?;

            let mut last_failure = None;

            for dial in &dials {
                let mut client = match DeRecTransportClient::connect(dial.clone()).await {
                    Ok(client) => client,
                    Err(error) => {
                        last_failure = Some(format!("connect {dial}: {error}"));
                        continue;
                    }
                };

                match client.send(envelope.clone()).await {
                    Ok(_) => return Ok(()),
                    Err(error) => last_failure = Some(format!("send {dial}: {error}")),
                }
            }

            // Delivery to any one endpoint is success, so an error here means
            // every one of them failed.
            let _detail = last_failure.unwrap_or_else(|| "no endpoints offered".to_owned());
            #[cfg(feature = "logging")]
            tracing::warn!(error = %_detail, "grpc delivery failed on every endpoint");
            Err(derec_library::Error::InvalidInput(
                "grpc transport unreachable on every advertised endpoint",
            ))
        })
    }
}
