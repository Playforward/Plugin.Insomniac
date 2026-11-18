using System.Net;

namespace Plugin.Insomniac.Mr;

/// <summary>What became of one datagram from a peer (<see cref="MrPeer.Accept"/>).</summary>
public enum MrReceipt
{
    /// <summary>A new message, to be handled.</summary>
    Delivered,
    /// <summary>A reliable send seen before (the ack was lost): acked again, not delivered.</summary>
    Repeated,
    /// <summary>The client acked the push at the head of the queue.</summary>
    PushAcked,
    /// <summary>An ack for nothing pending (late or duplicate).</summary>
    StrayAck,
    /// <summary>Sequenced without Request from the client: not something the client sends [C 0x473044 always sets both].</summary>
    Unexpected,
}

/// <summary>
/// The server's end of one client's Universe channel: the mirror of the client's stop-and-wait reliability
/// [C R3 1.02 0x473044 send, 0x4733bc retransmit, 0x4736dc receive; initial state 0x90672c].
/// </summary>
/// <remarks>
/// <para>Client to server. The client queues reliable sends and has one in flight; it resends it every
/// channel+0xe seconds (1 [C 0x90672c]) and gives up after 30 (state 100002, [C 0x901cc4 passes 0x1e]). Its
/// packets carry sequence 0: it moves on when an ack (Sequenced|Ack, no payload) carries the sequence it is
/// counting itself (channel+0x1a, from 0, +1 per acked send, 16-bit compare). So the server counts the client's
/// new reliable sends and acks each with that count. A resend is byte-for-byte the same datagram (enciphered
/// once, at queue time), which is how a repeat is told from a new send.</para>
/// <para>Server to client. A Sequenced push is delivered when its sequence is (last + 1) &amp; 0xff, the last
/// starting at 0xffff (so the first is 0), and the client answers with an ack of that sequence. Unsequenced
/// packets are delivered as they come.</para>
/// <para>The client's counters live for the whole game process, not per socket [guess: nothing but the static
/// initialiser 0x90672c writes them], so a server restart while the game runs leaves the ack count wrong; the
/// client then resends until it gives up (logged as <see cref="RepeatsBeforeWarning"/> repeats).</para>
/// </remarks>
public sealed class MrPeer(IPEndPoint remote, MrPeerOptions options, Action<byte[]> send)
{
    /// <summary>Resends of one datagram after which the ack count is reported as probably wrong.</summary>
    public const int RepeatsBeforeWarning = 3;

    private readonly Queue<PendingPush> _pending = new();
    private byte[]? _lastReliable;
    private ushort _lastAck;
    private int _pushed;

    public IPEndPoint Remote { get; private set; } = remote;
    public MrPeerOptions Options { get; } = options;
    public DateTime LastHeard { get; private set; }

    /// <summary>The ack the client's next new reliable send gets (its own count of acked sends).</summary>
    public ushort AckCount { get; private set; }

    /// <summary>How many times in a row the last reliable send came again after it was acked.</summary>
    public int Repeats { get; private set; }

    public int PendingPushes => _pending.Count;

    /// <summary>Takes over the counters of the peer this client used before it reopened its socket.</summary>
    public void Inherit(MrPeer previous)
    {
        AckCount = previous.AckCount;
        _lastReliable = previous._lastReliable;
        _lastAck = previous._lastAck;
        _pushed = previous._pushed;
        foreach (PendingPush push in previous._pending)
            _pending.Enqueue(push);
    }

    /// <summary>The bookkeeping for a datagram from this peer: <paramref name="wire"/> as received, <paramref name="packet"/> deciphered.</summary>
    public MrReceipt Accept(ReadOnlySpan<byte> wire, MrPacket packet, DateTime now)
    {
        LastHeard = now;
        MrFlags flags = packet.Flags;
        if ((flags & MrFlags.Sequenced) == 0)
            return MrReceipt.Delivered;

        if ((flags & MrFlags.Ack) != 0 && packet.Payload.Length == 0)
        {
            if (_pending.TryPeek(out PendingPush? head) && head.Sequence == packet.Sequence)
            {
                _pending.Dequeue();
                if (_pending.TryPeek(out PendingPush? next))
                    Transmit(next, now);
                return MrReceipt.PushAcked;
            }
            return MrReceipt.StrayAck;
        }

        if ((flags & MrFlags.Request) == 0)
            return MrReceipt.Unexpected;

        if (_lastReliable is not null && wire.SequenceEqual(_lastReliable))
        {
            Repeats++;
            SendAck(_lastAck);
            return MrReceipt.Repeated;
        }
        Repeats = 0;
        _lastReliable = wire.ToArray();
        _lastAck = AckCount;
        AckCount++;
        SendAck(_lastAck);
        return MrReceipt.Delivered;
    }

    /// <summary>Sends a message: reliable ones are queued and resent until acked, one at a time.</summary>
    public void Push(byte[] payload, bool reliable, DateTime now)
    {
        if (MrPacket.HeaderSize + payload.Length > Options.MaxDatagram)
            throw new ArgumentException($"a {payload.Length}-byte message does not fit the client's {Options.MaxDatagram}-byte datagram");
        if (!reliable)
        {
            send(Seal(new MrPacket { Flags = MrFlags.None, Payload = payload }));
            return;
        }
        PendingPush push = new((ushort)(_pushed++ & 0xff), payload, now);
        _pending.Enqueue(push);
        if (_pending.Count == 1)
            Transmit(push, now);
    }

    /// <summary>Resends the head push when it is due; drops it after <see cref="MrPeerOptions.GiveUpAfter"/>. Returns a dropped push, if any.</summary>
    public byte[]? Tick(DateTime now)
    {
        if (!_pending.TryPeek(out PendingPush? head) || now < head.NextSend)
            return null;
        if (now - head.Queued >= Options.GiveUpAfter)
        {
            _pending.Dequeue();
            if (_pending.TryPeek(out PendingPush? next))
                Transmit(next, now);
            return head.Payload;
        }
        Transmit(head, now);
        return null;
    }

    /// <summary>The client's datagrams now come from <paramref name="remote"/> (same client, new socket).</summary>
    public void MovedTo(IPEndPoint remote) => Remote = remote;

    private void Transmit(PendingPush push, DateTime now)
    {
        push.NextSend = now + Options.Retransmit;
        send(Seal(new MrPacket { Sequence = push.Sequence, Flags = MrFlags.Sequenced, Payload = push.Payload }));
    }

    private void SendAck(ushort sequence) =>
        send(Seal(new MrPacket { Sequence = sequence, Flags = MrFlags.Sequenced | MrFlags.Ack }));

    /// <summary>Fills in the fixed header fields and enciphers.</summary>
    private byte[] Seal(MrPacket packet)
    {
        packet.Salt = (byte)Random.Shared.Next(256);
        packet.Version = Options.Version;
        packet.HeaderId = Options.HeaderId;
        byte[] bytes = packet.Serialize();
        Options.Cipher.Encrypt(bytes);
        return bytes;
    }

    private sealed class PendingPush(ushort sequence, byte[] payload, DateTime queued)
    {
        public ushort Sequence { get; } = sequence;
        public byte[] Payload { get; } = payload;
        public DateTime Queued { get; } = queued;
        public DateTime NextSend { get; set; }
    }
}

/// <summary>What a peer's channel needs from its title.</summary>
public sealed class MrPeerOptions
{
    public required MrCipher Cipher { get; init; }
    public required byte[] HeaderId { get; init; }
    public byte Version { get; init; } = 1;
    public int MaxDatagram { get; init; } = 0x290;
    public TimeSpan Retransmit { get; init; } = TimeSpan.FromSeconds(1);
    public TimeSpan GiveUpAfter { get; init; } = TimeSpan.FromSeconds(30);
}
