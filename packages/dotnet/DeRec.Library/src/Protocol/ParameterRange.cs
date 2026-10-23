namespace DeRec.Library;

/// <summary>
/// The bounds a node advertises during pair negotiation, mirroring the
/// <c>ParameterRange</c> proto field for field.
/// </summary>
/// <remarks>
/// Every bound is optional and defaults to <c>0</c>, which the proto reads as
/// "no constraint on this dimension". A pairing is refused when any field's
/// range fails to intersect the peer's — for example when the local
/// <see cref="MinShareSize"/> exceeds the peer's <see cref="MaxShareSize"/>:
/// a responder reports a
/// <see cref="DeRec.Library.Orchestrator.PairingRefusedEvent"/>, and an
/// initiator fails, with <see cref="DeRecCode.IncompatibleParameterRange"/>
/// when it finds the mismatch itself.
/// </remarks>
public sealed record ParameterRange
{
    public long MinShareSize { get; init; }
    public long MaxShareSize { get; init; }
    public long MinTimeBetweenVerifications { get; init; }
    public long MaxTimeBetweenVerifications { get; init; }
    public long MinTimeBetweenShareUpdates { get; init; }
    public long MaxTimeBetweenShareUpdates { get; init; }
    public long MinUnresponsiveDeletionTimeout { get; init; }
    public long MaxUnresponsiveDeletionTimeout { get; init; }
    public long MinUnresponsiveDeactivationTimeout { get; init; }
    public long MaxUnresponsiveDeactivationTimeout { get; init; }
}
