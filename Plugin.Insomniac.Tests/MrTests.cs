using Plugin.Insomniac.Mr;
using System.Net;
using System.Text.Json;

namespace Plugin.Insomniac.Tests;

public class MrCipherTests
{
    // A datagram as the client builds it: reliable send (flags 3), salt 0, "i1", version 1, R3's header id, message 0x25.
    private const string Plain = "00000300693101690e960a00000000000025aabbccddeeff00112233";

    [Fact]
    public void MatchesTheReferenceImplementation()
    {
        // Synthetic tables, vector from the same algorithm as RE-Work/r3/tools/mrcrypt.py.
        byte[] data = Convert.FromHexString(Plain);
        TestData.SyntheticCipher().Encrypt(data);
        Assert.Equal("e15e514529901f3bab216bd06461862b70e3b98ef6095eec56d9dfe4", Convert.ToHexString(data).ToLowerInvariant());
    }

    [Fact]
    public void DecryptUndoesEncrypt()
    {
        MrCipher cipher = TestData.SyntheticCipher();
        for (int length = 0; length < 40; length++)
        {
            byte[] original = [.. Enumerable.Range(0, length).Select(i => (byte)(i * 37 + length))];
            byte[] data = [.. original];
            cipher.Encrypt(data);
            if (length >= 4)
                Assert.NotEqual(original, data);
            cipher.Decrypt(data);
            Assert.Equal(original, data);
        }
    }

    [Fact]
    public void RefusesTablesThatCannotBeRight()
    {
        Assert.Throws<ArgumentException>(() => new MrCipher([1, 2], new byte[256], 2));
        Assert.Throws<ArgumentException>(() => new MrCipher([1], Enumerable.Range(0, 256).Select(i => (byte)i).ToArray(), 2));
    }

    /// <summary>The game's own tables (tools/re/r3keys.py output in $INSOMNIAC_KEYS) against mrcrypt.py's output for them.</summary>
    [Fact]
    public void MatchesTheGameTables()
    {
        if (TestData.RealCipher() is not { } cipher)
            return;
        byte[] data = Convert.FromHexString(Plain);
        cipher.Encrypt(data);
        Assert.Equal("ea2ec9571c696087cc6f58cf5c1547efb26800c39b4300d09f7c5d46", Convert.ToHexString(data).ToLowerInvariant());
    }
}

public class MrPacketTests
{
    [Fact]
    public void ParsesTheClientHeader()
    {
        MrPacket packet = MrPacket.Parse(Convert.FromHexString("00000300693101690e960a00000000000025aabb"))!;
        Assert.Equal(0, packet.Sequence);
        Assert.Equal(MrFlags.Sequenced | MrFlags.Request, packet.Flags);
        Assert.True(packet.HasMagic);
        Assert.Equal(1, packet.Version);
        Assert.Equal(TestData.HeaderId, packet.HeaderId);
        Assert.Equal((byte)0x25, packet.MessageId);
        Assert.Equal("00000300693101690E960A00000000000025AABB", Convert.ToHexString(packet.Serialize()));
    }

    [Fact]
    public void ShorterThanTheHeaderIsNotAPacket() => Assert.Null(MrPacket.Parse(new byte[15]));
}

public class MrPeerTests
{
    private static readonly IPEndPoint Remote = new(IPAddress.Loopback, 40000);

    private static (MrPeer Peer, List<MrPacket> Sent) NewPeer()
    {
        List<MrPacket> sent = [];
        MrCipher cipher = TestData.SyntheticCipher();
        MrPeer peer = new(Remote, new MrPeerOptions { Cipher = cipher, HeaderId = TestData.HeaderId }, bytes =>
        {
            cipher.Decrypt(bytes);
            sent.Add(MrPacket.Parse(bytes)!);
        });
        return (peer, sent);
    }

    [Fact]
    public void AcksEachNewReliableSendWithTheClientsOwnCount()
    {
        var (peer, sent) = NewPeer();
        DateTime now = DateTime.UtcNow;
        for (int i = 0; i < 3; i++)
        {
            (byte[] wire, MrPacket packet) = TestData.ClientSend([0, 0x10, (byte)i]);
            Assert.Equal(MrReceipt.Delivered, peer.Accept(wire, packet, now));
        }
        Assert.Equal([0, 1, 2], sent.Select(p => (int)p.Sequence));
        Assert.All(sent, p =>
        {
            Assert.Equal(MrFlags.Sequenced | MrFlags.Ack, p.Flags);
            Assert.Empty(p.Payload);
            Assert.True(p.HasMagic);
            Assert.Equal(TestData.HeaderId, p.HeaderId);
            Assert.Equal(1, p.Version);
        });
    }

    [Fact]
    public void AResendIsAckedAgainButNotDelivered()
    {
        var (peer, sent) = NewPeer();
        (byte[] wire, MrPacket packet) = TestData.ClientSend([0, 0x10]);
        Assert.Equal(MrReceipt.Delivered, peer.Accept(wire, packet, DateTime.UtcNow));
        Assert.Equal(MrReceipt.Repeated, peer.Accept(wire, packet, DateTime.UtcNow));
        Assert.Equal([0, 0], sent.Select(p => (int)p.Sequence));
        Assert.Equal(1, peer.Repeats);
        Assert.Equal(1, peer.AckCount);
    }

    [Fact]
    public void UnsequencedPacketsAreDeliveredWithoutAck()
    {
        var (peer, sent) = NewPeer();
        (byte[] wire, MrPacket packet) = TestData.ClientSend([0, 0x11], MrFlags.None);
        Assert.Equal(MrReceipt.Delivered, peer.Accept(wire, packet, DateTime.UtcNow));
        Assert.Empty(sent);
    }

    [Fact]
    public void PushesGoOneAtATimeFromSequenceZeroAndAdvanceOnAck()
    {
        var (peer, sent) = NewPeer();
        DateTime now = DateTime.UtcNow;
        peer.Push([0, 0x30], reliable: true, now);
        peer.Push([0, 0x31], reliable: true, now);
        Assert.Single(sent);
        Assert.Equal(0, sent[0].Sequence);
        Assert.Equal(MrFlags.Sequenced, sent[0].Flags);

        Assert.Equal(MrReceipt.StrayAck, peer.Accept([], TestData.ClientAck(1), now));
        Assert.Equal(MrReceipt.PushAcked, peer.Accept([], TestData.ClientAck(0), now));
        Assert.Equal(2, sent.Count);
        Assert.Equal(1, sent[1].Sequence);
        Assert.Equal((byte)0x31, sent[1].MessageId);
        Assert.Equal(MrReceipt.PushAcked, peer.Accept([], TestData.ClientAck(1), now));
        Assert.Equal(0, peer.PendingPushes);
    }

    [Fact]
    public void PushSequencesWrapAt256()
    {
        var (peer, sent) = NewPeer();
        DateTime now = DateTime.UtcNow;
        for (int i = 0; i < 257; i++)
        {
            peer.Push([0, 0x30], reliable: true, now);
            peer.Accept([], TestData.ClientAck(sent[^1].Sequence), now);
        }
        Assert.Equal(255, sent[255].Sequence);
        Assert.Equal(0, sent[256].Sequence);
    }

    [Fact]
    public void UnackedPushesAreResentThenDropped()
    {
        var (peer, sent) = NewPeer();
        DateTime start = DateTime.UtcNow;
        peer.Push([0, 0x30], reliable: true, start);
        Assert.Null(peer.Tick(start.AddMilliseconds(500)));
        Assert.Single(sent);
        Assert.Null(peer.Tick(start.AddSeconds(1)));
        Assert.Equal(2, sent.Count);
        Assert.NotNull(peer.Tick(start.AddSeconds(31)));
        Assert.Equal(0, peer.PendingPushes);
    }

    [Fact]
    public void UnreliablePushesAreNotSequenced()
    {
        var (peer, sent) = NewPeer();
        peer.Push([0, 0x30, 1], reliable: false, DateTime.UtcNow);
        Assert.Equal(MrFlags.None, Assert.Single(sent).Flags);
        Assert.Equal(0, peer.PendingPushes);
    }

    [Fact]
    public void ANewSocketKeepsTheCounters()
    {
        var (first, _) = NewPeer();
        (byte[] wire, MrPacket packet) = TestData.ClientSend([0, 0x10]);
        first.Accept(wire, packet, DateTime.UtcNow);
        var (second, sent) = NewPeer();
        second.Inherit(first);
        (wire, packet) = TestData.ClientSend([0, 0x11]);
        second.Accept(wire, packet, DateTime.UtcNow);
        Assert.Equal(1, sent.Single().Sequence);
    }
}

public class UniverseServiceTests
{
    [Fact]
    public void AcksAndDispatchesByTitleAndMessageId()
    {
        InsomniacTitle title = TestData.Title();
        using UniverseService service = new([(title, TestData.SyntheticCipher())], logTraffic: true);
        List<UniverseMessage> handled = [];
        service.Register(title, 0x10, handled.Add);
        List<byte[]> sent = [];
        IPEndPoint remote = new(IPAddress.Loopback, 40001);

        (byte[] wire, _) = TestData.ClientSend([0, 0x10, 0xaa]);
        service.Received(remote, wire, sent.Add);
        (wire, _) = TestData.ClientSend([0, 0x11]);
        service.Received(remote, wire, sent.Add);

        UniverseMessage message = Assert.Single(handled);
        Assert.Same(title, message.Title);
        Assert.Equal(0x10, message.Id);
        Assert.Equal(2, sent.Count);
        Assert.Equal(1, service.PeerCount);

        message.Reply([0, 0x40], reliable: true);
        byte[] reply = sent[^1];
        TestData.SyntheticCipher().Decrypt(reply);
        MrPacket packet = MrPacket.Parse(reply)!;
        Assert.Equal((byte)0x40, packet.MessageId);
        Assert.Equal(TestData.HeaderId, packet.HeaderId);
    }

    [Fact]
    public void ADatagramForNoTitleIsDropped()
    {
        InsomniacTitle title = TestData.Title();
        using UniverseService service = new([(title, TestData.SyntheticCipher())], logTraffic: false);
        List<byte[]> sent = [];
        (byte[] wire, _) = TestData.ClientSend([0, 0x10], headerId: [1, 2, 3, 4]);
        service.Received(new IPEndPoint(IPAddress.Loopback, 40002), wire, sent.Add);
        Assert.Empty(sent);
        Assert.Equal(0, service.PeerCount);
    }

    [Fact]
    public void TheShippedTitleDataParses()
    {
        string? path = TestData.FindTitleJson();
        if (path is null)
            return;
        InsomniacTitle title = InsomniacTitle.Parse(File.ReadAllText(path))!;
        Assert.Equal(TestData.HeaderId, title.Universe.HeaderIdBytes());
        Assert.Equal(11, title.Universe.Cipher.Passes);
        Assert.NotEmpty(title.Igloo.Hosts);
        Assert.NotEmpty(title.LiveData.Hosts);
        Assert.Equal("?", title.Universe.NameOf(0xfe));
    }
}

internal static class TestData
{
    public static readonly byte[] HeaderId = [0x69, 0x0e, 0x96, 0x0a];

    public static MrCipher SyntheticCipher() =>
        new([.. Enumerable.Range(1, 12).Select(i => unchecked(0x9E3779B9u * (uint)i))],
            [.. Enumerable.Range(0, 256).Select(i => (byte)(i * 167 + 13))], 11);

    /// <summary>The game's tables from tools/re/r3keys.py output, when $INSOMNIAC_KEYS names that file.</summary>
    public static MrCipher? RealCipher()
    {
        string? path = Environment.GetEnvironmentVariable("INSOMNIAC_KEYS");
        if (string.IsNullOrEmpty(path) || !File.Exists(path))
            return null;
        using JsonDocument json = JsonDocument.Parse(File.ReadAllText(path));
        JsonElement keys = json.RootElement.GetProperty("Keys");
        return MrCipher.FromHex(keys.GetProperty("r3-mr-keys").GetString()!, keys.GetProperty("r3-mr-sbox").GetString()!,
            json.RootElement.GetProperty("Passes").GetInt32());
    }

    public static InsomniacTitle Title() => new()
    {
        Descriptor = new() { TitleId = "test", Name = "Test" },
        Universe = new UniverseDefinition { HeaderId = "690e960a", Cipher = new MrCipherDefinition { Passes = 11 } },
    };

    /// <summary>A datagram as the client's reliable send (0x473044) makes it, enciphered, with its parsed form.</summary>
    public static (byte[] Wire, MrPacket Packet) ClientSend(byte[] payload, MrFlags flags = MrFlags.Sequenced | MrFlags.Request, byte[]? headerId = null)
    {
        MrPacket packet = new()
        {
            Flags = flags,
            Salt = (byte)Random.Shared.Next(256),
            Version = 1,
            HeaderId = headerId ?? HeaderId,
            Payload = payload,
        };
        byte[] wire = packet.Serialize();
        SyntheticCipher().Encrypt(wire);
        return (wire, packet);
    }

    /// <summary>The client's ack of a push (0x4738dc): only bytes 0..5 are set.</summary>
    public static MrPacket ClientAck(ushort sequence) => new()
    {
        Sequence = sequence,
        Flags = MrFlags.Sequenced | MrFlags.Ack,
        HeaderId = [0xde, 0xad, 0xbe, 0xef],
        Version = 0x55,
    };

    /// <summary>ServerApp-Titles/Resistance3/insomniac/title.json beside this repository, if it is there.</summary>
    public static string? FindTitleJson()
    {
        for (DirectoryInfo? dir = new(AppContext.BaseDirectory); dir is not null; dir = dir.Parent)
        {
            string candidate = Path.Combine(dir.FullName, "ServerApp-Titles", "Resistance3", "insomniac", "title.json");
            if (File.Exists(candidate))
                return candidate;
        }
        return null;
    }
}
