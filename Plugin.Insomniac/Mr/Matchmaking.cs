using System.Net;

namespace Plugin.Insomniac.Mr;

/// <summary>A session a hosting console created, offered to searchers until it is replaced or goes stale.</summary>
public sealed class HostedSession
{
    public required MrPeer Host { get; init; }
    public required ushort SessionId { get; init; }
    /// <summary>The server's key for it, unique among live sessions and never 0xffff (the client refuses that).</summary>
    public required ushort Key { get; init; }
    public required byte[] Details { get; init; }
    public required DateTime Created { get; init; }
}

/// <summary>
/// The Universe side of quick match for one title (<see cref="MatchmakingDefinition"/>): keeps the sessions hosts
/// create, introduces each host to the Galaxy, and answers quick-match requests with the other live sessions.
/// </summary>
/// <remarks>
/// [C R3 1.05] Host: lobby 0x3ca4a0 state 5 -> 0x3c6fc4 -> MR client 0x8f6730 with no target address -> create
/// message (0x21, session id = client counter +0x7a24) and the session waits in state 1; an introduction with that
/// id (handler 0x8faa94) moves it to state 2 and ENet-connects it to the given address (network-thread command 9,
/// 0x8f77d0). Search: request 0x26 kind 10 (0x8f7360), records 0x11 into the client's list (0x8f95a8), introduction
/// id 0 -> lobby callback 0x3caa2c with the count; joining (0x3c7364 -> 0x8f6b8c) ENet-connects to the record's
/// address and port. Both sides therefore meet at the address the server gives them, which the client's lobby options
/// call the Galaxy (LOBBY_MR_GALAXY_DOMAIN/PORT). No Galaxy runs yet, so connects fail there for now.
/// </remarks>
public sealed class Matchmaking(InsomniacTitle title, Func<MrPeer, IPEndPoint?> galaxyFor)
{
    private readonly MatchmakingDefinition _def = title.Matchmaking;
    private readonly Dictionary<IPEndPoint, HostedSession> _sessions = [];
    private readonly object _lock = new();
    private ushort _nextKey;

    public void Register(UniverseService universe)
    {
        universe.Register(title, _def.SessionCreate.Id, m => SessionCreated(m, DateTime.UtcNow));
        universe.Register(title, _def.Request.Id, m => Requested(m, DateTime.UtcNow));
    }

    public IReadOnlyList<HostedSession> Live(DateTime now)
    {
        lock (_lock)
        {
            foreach (IPEndPoint stale in _sessions.Where(s => now - s.Value.Created > TimeSpan.FromSeconds(_def.SessionSeconds)).Select(s => s.Key).ToList())
                _sessions.Remove(stale);
            return [.. _sessions.Values.OrderBy(s => s.Created)];
        }
    }

    internal void SessionCreated(UniverseMessage message, DateTime now)
    {
        SessionCreateLayout layout = _def.SessionCreate;
        ushort sessionId = UniverseMessages.U16(message.Payload, layout.SessionIdAt);
        byte[] details = [.. Enumerable.Range(layout.DetailsAt, layout.DetailCount).Select(i => UniverseMessages.U8(message.Payload, i))];
        HostedSession session;
        lock (_lock)
        {
            // A host creates a new session each time it falls back to hosting; only its latest one is offered.
            session = new HostedSession { Host = message.Peer, SessionId = sessionId, Key = NextKey(), Details = details, Created = now };
            _sessions[message.Peer.Remote] = session;
        }
        Log.Information("[insomniac/match] {Remote} ({Title}): hosts session {Session} (key {Key}, details {Details})",
            message.Peer.Remote, title, sessionId, session.Key, Convert.ToHexString(details));

        if (!_def.IntroduceHosts)
            return;
        if (galaxyFor(message.Peer) is not { } galaxy)
        {
            Log.Warning("[insomniac/match] {Remote}: no Galaxy address to introduce session {Session} to (no GALAXY listener)", message.Peer.Remote, sessionId);
            return;
        }
        message.Reply(UniverseMessages.Introduction(_def.Introduction, sessionId, 0, UniverseMessages.Ipv4(galaxy.Address), (ushort)galaxy.Port), reliable: false);
        Log.Information("[insomniac/match] {Remote}: session {Session} introduced to the Galaxy at {Galaxy}", message.Peer.Remote, sessionId, galaxy);
    }

    internal void Requested(UniverseMessage message, DateTime now)
    {
        int kind = UniverseMessages.U16(message.Payload, _def.Request.KindAt);
        if (!_def.Request.QuickMatchKinds.Contains(kind))
        {
            Log.Information("[insomniac/match] {Remote}: request kind {Kind} is not a quick-match search; not answered yet ({Length}B: {Payload})",
                message.Peer.Remote, kind, message.Payload.Length, Convert.ToHexString(message.Payload));
            return;
        }
        if (galaxyFor(message.Peer) is not { } galaxy)
        {
            Log.Warning("[insomniac/match] {Remote}: quick match not answered: no Galaxy address (no GALAXY listener)", message.Peer.Remote);
            return;
        }
        uint galaxyIp = UniverseMessages.Ipv4(galaxy.Address);
        List<HostedSession> candidates = [.. Live(now).Where(s => !s.Host.Remote.Equals(message.Peer.Remote)).Take(_def.MaxResults)];
        foreach (HostedSession session in candidates)
            message.Reply(UniverseMessages.Record(_def.Record, new CandidateRecord
            {
                Identity = Identity(session.Host.Remote),
                Ipv4 = galaxyIp,
                Port = (ushort)galaxy.Port,
                Key = session.Key,
                Mode = (byte)_def.Record.ModeBase,
            }), reliable: false);
        message.Reply(UniverseMessages.Introduction(_def.Introduction, 0, (uint)candidates.Count, galaxyIp, (ushort)galaxy.Port), reliable: false);
        Log.Information("[insomniac/match] {Remote}: quick match (kind {Kind}) answered with {Count} session(s){Hosts}", message.Peer.Remote, kind,
            candidates.Count, candidates.Count > 0 ? $" from {string.Join(", ", candidates.Select(c => c.Host.Remote))}" : "");
    }

    /// <summary>A stable 64-bit identity for a host until accounts are known (record +0x00; the client's meaning is not known).</summary>
    private static ulong Identity(IPEndPoint remote) =>
        (ulong)UniverseMessages.Ipv4(remote.Address) << 16 | (ushort)remote.Port;

    private ushort NextKey()
    {
        do
            _nextKey++;
        while (_nextKey == 0xffff || _nextKey == 0 || _sessions.Values.Any(s => s.Key == _nextKey));
        return _nextKey;
    }
}
