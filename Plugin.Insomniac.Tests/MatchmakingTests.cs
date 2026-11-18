using Plugin.Insomniac.Mr;
using System.Buffers.Binary;
using System.Net;

namespace Plugin.Insomniac.Tests;

public class MatchmakingTests
{
    private static readonly IPEndPoint Galaxy = new(IPAddress.Parse("192.168.1.179"), 12351);

    /// <summary>The shipped title data when it is beside the repo, else the same values typed here.</summary>
    private static InsomniacTitle Title()
    {
        InsomniacTitle title = TestData.FindTitleJson() is { } path ? InsomniacTitle.Parse(File.ReadAllText(path))! : TestData.Title();
        title.Descriptor = new() { TitleId = "test", Name = "Test" };
        if (!title.Matchmaking.Enabled)
            title.Matchmaking = new MatchmakingDefinition
            {
                Enabled = true,
                SessionCreate = new() { Id = 0x21, SessionIdAt = 2, DetailsAt = 0x11, DetailCount = 2 },
                Request = new() { Id = 0x26, KindAt = 0x11, QuickMatchKinds = [10] },
                Record = new()
                {
                    Id = 0x11, Size = 0x36, IdentityAt = 4, Word0At = 0x0c, AddressAt = 0x10, PortAt = 0x14, KeyAt = 0x16, Word1At = 0x18,
                    Short0At = 0x1c, BytesAt = 0x2e, ByteCount = 6, ModeByte = 3, ModeBase = 9, StringsAt = 0x34,
                },
                Introduction = new() { Id = 0x23, Size = 0x0e, SessionIdAt = 2, CountAt = 4, AddressAt = 8, PortAt = 0x0c },
            };
        return title;
    }

    private sealed class Console(UniverseService universe, int port)
    {
        public IPEndPoint Remote { get; } = new(IPAddress.Loopback, port);
        public List<MrPacket> Got { get; } = [];

        public void Send(byte[] payload)
        {
            (byte[] wire, _) = TestData.ClientSend(payload, MrFlags.None);
            universe.Received(Remote, wire, bytes =>
            {
                TestData.SyntheticCipher().Decrypt(bytes);
                Got.Add(MrPacket.Parse(bytes)!);
            });
        }
    }

    /// <summary>0x21 as 0x8f6500 builds it: class 1, id, session id @2, the two detail bytes @0x11, 0x1a bytes.</summary>
    private static byte[] Create(ushort session)
    {
        byte[] m = new byte[0x1a];
        m[0] = 1; m[1] = 0x21;
        BinaryPrimitives.WriteUInt16BigEndian(m.AsSpan(2), session);
        m[0x11] = 1; m[0x12] = 1;
        return m;
    }

    /// <summary>0x26 as 0x8f7360 builds it (kind @0x11), 0x52 bytes.</summary>
    private static byte[] Search(ushort kind = 10)
    {
        byte[] m = new byte[0x52];
        m[0] = 1; m[1] = 0x26;
        BinaryPrimitives.WriteUInt16BigEndian(m.AsSpan(0x11), kind);
        BinaryPrimitives.WriteUInt16BigEndian(m.AsSpan(0x25), 0x96);
        return m;
    }

    private static (UniverseService, Matchmaking) Start(InsomniacTitle title)
    {
        UniverseService universe = new([(title, TestData.SyntheticCipher())], logTraffic: false);
        Matchmaking match = new(title, _ => Galaxy);
        match.Register(universe);
        return (universe, match);
    }

    [Fact]
    public void AHostIsIntroducedToTheGalaxyWithItsOwnSessionId()
    {
        InsomniacTitle title = Title();
        (UniverseService universe, Matchmaking match) = Start(title);
        using (universe)
        {
            Console host = new(universe, 40100);
            host.Send(Create(7));
            byte[] intro = Assert.Single(host.Got).Payload;
            // Read as the client's getters do (0x8fdd10, 0x900468, 0x9048f4, 0x90492c).
            Assert.Equal(0x23, intro[1]);
            Assert.True(intro.Length >= 0x0e);
            Assert.Equal(7, BinaryPrimitives.ReadUInt16BigEndian(intro.AsSpan(2)));
            Assert.Equal(new byte[] { 192, 168, 1, 179 }, intro[8..12]);
            Assert.Equal(12351, BinaryPrimitives.ReadUInt16BigEndian(intro.AsSpan(0x0c)));
            Assert.Single(match.Live(DateTime.UtcNow));
        }
    }

    [Fact]
    public void ASearchGetsTheOtherHostsThenTheCount()
    {
        InsomniacTitle title = Title();
        (UniverseService universe, Matchmaking match) = Start(title);
        using (universe)
        {
            Console host = new(universe, 40101), searcher = new(universe, 40102);
            host.Send(Create(1));
            host.Send(Create(2));   // the host re-created: only its latest session is offered
            searcher.Send(Search());

            Assert.Equal(2, searcher.Got.Count);
            byte[] record = searcher.Got[0].Payload;
            Assert.Equal(0x11, record[1]);
            Assert.True(record.Length >= 0x36);
            Assert.Equal(new byte[] { 192, 168, 1, 179 }, record[0x10..0x14]);
            Assert.Equal(12351, BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(0x14)));
            ushort key = BinaryPrimitives.ReadUInt16BigEndian(record.AsSpan(0x16));
            Assert.NotEqual(0xffff, key);
            Assert.NotEqual(0, key);
            Assert.True(record[0x31] > 8, "the lobby skips records whose mode byte is not above 8");
            Assert.Equal(0, record[0x34]);   // empty strings
            Assert.Equal(0, record[0x35]);

            byte[] done = searcher.Got[1].Payload;
            Assert.Equal(0x23, done[1]);
            Assert.Equal(0, BinaryPrimitives.ReadUInt16BigEndian(done.AsSpan(2)));
            Assert.Equal(1u, BinaryPrimitives.ReadUInt32BigEndian(done.AsSpan(4)));
            Assert.Single(match.Live(DateTime.UtcNow));
        }
    }

    [Fact]
    public void AHostDoesNotFindItselfAndOtherKindsAreNotAnswered()
    {
        InsomniacTitle title = Title();
        (UniverseService universe, _) = Start(title);
        using (universe)
        {
            Console host = new(universe, 40103);
            host.Send(Create(1));
            host.Got.Clear();
            host.Send(Search());
            byte[] done = Assert.Single(host.Got).Payload;
            Assert.Equal(0u, BinaryPrimitives.ReadUInt32BigEndian(done.AsSpan(4)));
            host.Got.Clear();
            host.Send(Search(0x28));
            Assert.Empty(host.Got);
        }
    }

    [Fact]
    public void StaleSessionsAreNotOffered()
    {
        InsomniacTitle title = Title();
        (UniverseService universe, Matchmaking match) = Start(title);
        using (universe)
        {
            new Console(universe, 40104).Send(Create(1));
            Assert.Empty(match.Live(DateTime.UtcNow.AddSeconds(title.Matchmaking.SessionSeconds + 1)));
        }
    }

    [Fact]
    public void RecordStringsAreLengthPrefixed()
    {
        RecordLayout layout = Title().Matchmaking.Record;
        byte[] m = UniverseMessages.Record(layout, new CandidateRecord { FirstName = "host", SecondName = "game", Key = 1 });
        Assert.Equal(layout.Size + 8, m.Length);
        Assert.Equal(4, m[layout.StringsAt]);
        Assert.Equal("host"u8.ToArray(), m[(layout.StringsAt + 1)..(layout.StringsAt + 5)]);
        Assert.Equal(4, m[layout.StringsAt + 5]);
    }
}
