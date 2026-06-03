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
}
