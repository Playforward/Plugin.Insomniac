using System.Collections.Concurrent;
using System.Net;

namespace Plugin.Insomniac.Mr;

/// <summary>A message from a client's Universe channel, ready for a handler.</summary>
public sealed class UniverseMessage(UniverseService service, InsomniacTitle title, MrPeer peer, MrPacket packet)
{
    public InsomniacTitle Title { get; } = title;
    public MrPeer Peer { get; } = peer;
    public MrPacket Packet { get; } = packet;
    public byte Id => Packet.MessageId ?? 0;
    public byte[] Payload => Packet.Payload;
    public bool Reliable => (Packet.Flags & MrFlags.Sequenced) != 0;

    /// <summary>Sends a message back to this client (reliable = queued, resent until acked).</summary>
    public void Reply(byte[] payload, bool reliable) => service.Push(Peer, payload, reliable);
}

/// <summary>Answers one message id. Registered with <see cref="UniverseService.Register"/>.</summary>
public delegate void UniverseHandler(UniverseMessage message);

/// <summary>
/// The MR Universe server: the central server of Insomniac's message router, which every console's
/// network thread talks to over one UDP channel [C R3 1.02: channel object 0x140ed68, send 0x901cc4,
/// receive loop 0x902d18]. Datagrams are deciphered, matched to a title by their header id, put through
/// the channel's reliability (<see cref="MrPeer"/>), then handed to the handler of their message id.
/// </summary>
/// <remarks>
/// On the client, a Universe message with id 0x25 goes to the network thread itself (0x906404: it then sends
/// the Universe a record per local client, 0x8f966c); every other id is passed whole to the game's main
/// thread (0x9065b8). So message meanings live in the game's lobby code. Unhandled messages are logged with
/// their bytes, which is how the next revisions learn them.
/// </remarks>
public sealed class UniverseService : IDisposable
{
    private readonly IReadOnlyList<UniverseTitle> _titles;
    private readonly bool _logTraffic;
    private readonly ConcurrentDictionary<IPEndPoint, PeerState> _peers = new();
    private readonly Dictionary<(InsomniacTitle, byte), UniverseHandler> _handlers = [];
    private readonly Timer _ticker;
    private readonly object _lock = new();

    public UniverseService(IEnumerable<(InsomniacTitle Title, MrCipher Cipher)> titles, bool logTraffic)
    {
        _titles = [.. titles.Select(t => new UniverseTitle(t.Title, t.Cipher))];
        _logTraffic = logTraffic;
        _ticker = new Timer(_ => Tick(DateTime.UtcNow), null, TimeSpan.FromSeconds(1), TimeSpan.FromSeconds(1));
    }

    public IReadOnlyList<InsomniacTitle> Titles => [.. _titles.Select(t => t.Title)];

    public int PeerCount => _peers.Count;

    public void Register(InsomniacTitle title, byte id, UniverseHandler handler)
    {
        lock (_lock)
            _handlers[(title, id)] = handler;
    }

    /// <summary>A datagram arrived; <paramref name="send"/> sends one back to <paramref name="remote"/>.</summary>
    public void Received(IPEndPoint remote, ReadOnlySpan<byte> wire, Action<byte[]> send) => Received(remote, wire, send, DateTime.UtcNow);

    internal void Received(IPEndPoint remote, ReadOnlySpan<byte> wire, Action<byte[]> send, DateTime now)
    {
        if (wire.Length < MrPacket.HeaderSize)
        {
            Log.Warning("[insomniac/universe] {Remote}: {Length}-byte datagram, shorter than the MR header: {Data}",
                remote, wire.Length, Convert.ToHexString(wire));
            return;
        }

        _peers.TryGetValue(remote, out PeerState? known);
        if (Open(wire, known?.Title) is not ({ } title, { } packet))
        {
            Log.Warning("[insomniac/universe] {Remote}: {Length}-byte datagram opens with no title's cipher and header id: {Data}",
                remote, wire.Length, Convert.ToHexString(wire[..Math.Min(wire.Length, 64)]));
            return;
        }
        if ((packet.Flags & MrFlags.Rejected) != 0)
            Log.Warning("[insomniac/universe] {Remote}: flags 0x{Flags:X2} have bits the client itself rejects", remote, (byte)packet.Flags);

        PeerState state = known ?? AddPeer(remote, title, send, now);
        MrReceipt receipt;
        lock (state)
            receipt = state.Peer.Accept(wire, packet, now);

        if (_logTraffic)
            Log.Debug("[insomniac/universe] {Remote} -> {Packet}: {Receipt}{Payload}", remote, packet, receipt,
                packet.Payload.Length > 0 ? $" {Convert.ToHexString(packet.Payload)}" : "");
        switch (receipt)
        {
            case MrReceipt.Repeated when state.Peer.Repeats == MrPeer.RepeatsBeforeWarning:
                Log.Warning("[insomniac/universe] {Remote}: the same reliable send came {Repeats} times after its ack (ack {Ack}); " +
                            "the client counts differently, most likely because the server restarted while the game ran: restart the game",
                    remote, state.Peer.Repeats, (ushort)(state.Peer.AckCount - 1));
                return;
            case MrReceipt.Unexpected:
                Log.Warning("[insomniac/universe] {Remote}: sequenced packet without the request flag ({Packet}); not delivered", remote, packet);
                return;
            case MrReceipt.Delivered:
                Dispatch(new UniverseMessage(this, title.Title, state.Peer, packet));
                return;
        }
    }

    /// <summary>Sends a message to a client.</summary>
    public void Push(MrPeer peer, byte[] payload, bool reliable)
    {
        lock (_peers.GetValueOrDefault(peer.Remote) ?? (object)peer)
            peer.Push(payload, reliable, DateTime.UtcNow);
        if (_logTraffic)
            Log.Debug("[insomniac/universe] {Remote} <- {Kind} message 0x{Id:X2} ({Length}B) {Payload}", peer.Remote,
                reliable ? "reliable" : "unreliable", payload.Length > 1 ? payload[1] : 0, payload.Length, Convert.ToHexString(payload));
    }

    internal void Tick(DateTime now)
    {
        foreach ((IPEndPoint remote, PeerState state) in _peers)
        {
            byte[]? dropped;
            lock (state)
                dropped = state.Peer.Tick(now);
            if (dropped is not null)
                Log.Warning("[insomniac/universe] {Remote}: gave up on a reliable message 0x{Id:X2} ({Length}B) after {Seconds} s unacked",
                    remote, dropped.Length > 1 ? dropped[1] : 0, dropped.Length, state.Peer.Options.GiveUpAfter.TotalSeconds);
            if (now - state.Peer.LastHeard > TimeSpan.FromSeconds(state.Title.Title.Universe.IdleSeconds) && _peers.TryRemove(remote, out _))
                Log.Information("[insomniac/universe] {Remote}: forgotten after {Seconds} s without a datagram", remote, state.Title.Title.Universe.IdleSeconds);
        }
    }

    private void Dispatch(UniverseMessage message)
    {
        UniverseHandler? handler;
        lock (_lock)
            handler = _handlers.GetValueOrDefault((message.Title, message.Id));
        if (handler is null)
        {
            Log.Information("[insomniac/universe] {Remote} ({Title}): unhandled {Kind} message 0x{Id:X2} {Name} ({Length}B): {Payload}",
                message.Peer.Remote, message.Title, message.Reliable ? "reliable" : "unreliable", message.Id,
                message.Title.Universe.NameOf(message.Id), message.Payload.Length, Convert.ToHexString(message.Payload));
            return;
        }
        try
        {
            handler(message);
        }
        catch (Exception exception)
        {
            Log.Error(exception, "[insomniac/universe] {Remote}: message 0x{Id:X2} could not be handled", message.Peer.Remote, message.Id);
        }
    }

    /// <summary>
    /// Deciphers with the known title's cipher first, then every other title's, and takes the first whose
    /// result carries the MR magic and (for anything but a plain ack, which has no header id) its header id.
    /// </summary>
    private (UniverseTitle?, MrPacket?) Open(ReadOnlySpan<byte> wire, UniverseTitle? known)
    {
        foreach (UniverseTitle candidate in known is null ? _titles : _titles.Where(t => t != known).Prepend(known))
        {
            byte[] plain = wire.ToArray();
            candidate.Cipher.Decrypt(plain);
            if (MrPacket.Parse(plain) is not { HasMagic: true } packet)
                continue;
            if (packet.IsPlainAck ? candidate == known : packet.HeaderId.AsSpan().SequenceEqual(candidate.HeaderId))
                return (candidate, packet);
        }
        return (null, null);
    }

    /// <summary>
    /// A new peer; when the same address had one under another port, the client reopened its socket
    /// (0x901cc4 reopens it whenever the Universe address changes) and keeps its counters, so they move over.
    /// </summary>
    private PeerState AddPeer(IPEndPoint remote, UniverseTitle title, Action<byte[]> send, DateTime now)
    {
        UniverseDefinition definition = title.Title.Universe;
        MrPeerOptions options = new()
        {
            Cipher = title.Cipher,
            HeaderId = title.HeaderId,
            Version = definition.Version,
            MaxDatagram = definition.MaxDatagram,
            Retransmit = TimeSpan.FromSeconds(definition.RetransmitSeconds),
            GiveUpAfter = TimeSpan.FromSeconds(definition.GiveUpSeconds),
        };
        PeerState state = new(title, new MrPeer(remote, options, send));
        PeerState? previous = _peers.FirstOrDefault(p => p.Key.Address.Equals(remote.Address) && p.Value.Title == title).Value;
        if (previous is not null && _peers.TryRemove(previous.Peer.Remote, out _))
        {
            lock (previous)
                state.Peer.Inherit(previous.Peer);
            Log.Information("[insomniac/universe] {Remote} ({Title}): same client as {Previous} (new socket); counters kept", remote, title.Title, previous.Peer.Remote);
        }
        else
            Log.Information("[insomniac/universe] {Remote} ({Title}): new client", remote, title.Title);
        _peers[remote] = state;
        return state;
    }

    public void Dispose() => _ticker.Dispose();

    private sealed class UniverseTitle(InsomniacTitle title, MrCipher cipher)
    {
        public InsomniacTitle Title { get; } = title;
        public MrCipher Cipher { get; } = cipher;
        public byte[] HeaderId { get; } = title.Universe.HeaderIdBytes();
    }

    private sealed class PeerState(UniverseTitle title, MrPeer peer)
    {
        public UniverseTitle Title { get; } = title;
        public MrPeer Peer { get; } = peer;
    }
}
