// SPDX-License-Identifier: Apache-2.0

namespace DeRec.Library;

/// <summary>
/// Selects how the initiator's public encryption material is delivered in a
/// <see cref="ContactMessage"/>.
/// </summary>
/// <remarks>
/// <para>
/// <see cref="InlineKeys"/> (the default) embeds the ML-KEM encapsulation key
/// and the ECIES public key directly in the contact. The recipient can build
/// a normal pairing request immediately.
/// </para>
/// <para>
/// <see cref="HashedKeys"/> embeds only a SHA-384 commitment to those keys.
/// The recipient must fetch the actual keys over the wire via the plaintext
/// <c>PrePair</c> round-trip and verify them against the commitment before
/// constructing the pairing request. The transport endpoint used during this
/// flow MUST be ephemeral — the <c>PrePair</c> messages are plaintext.
/// </para>
/// <para>
/// <see cref="NoKeys"/> carries no key material and no commitment — only
/// <c>channelId</c>, <c>nonce</c>, and <c>transportProtocol</c>. Small enough
/// to be hand-typed or dictated. Keys are generated on the fly by the contact
/// creator when the corresponding <c>PrePairRequest</c> arrives; the scanner
/// accepts them without cryptographic verification. Trust rests entirely on
/// the out-of-band delivery channel being fully trusted (e.g. a verified
/// email from an already-KYC-authenticated institution). Applications MUST
/// rate-limit inbound <c>PrePairRequest</c>s per channel and expire
/// outstanding NoKeys contacts on a short timer.
/// </para>
/// </remarks>
public enum ContactMode
{
    /// <summary>Keys are embedded inline in the contact (current behavior).</summary>
    InlineKeys = 0,

    /// <summary>
    /// Only the SHA-384 binding hash is embedded; keys are obtained via
    /// <c>PrePair</c>.
    /// </summary>
    HashedKeys = 1,

    /// <summary>
    /// No key material or binding hash embedded. Keys are generated on the
    /// fly by the contact creator when the <c>PrePairRequest</c> arrives;
    /// trust rests entirely on a fully-trusted out-of-band delivery channel.
    /// </summary>
    NoKeys = 2,
}
