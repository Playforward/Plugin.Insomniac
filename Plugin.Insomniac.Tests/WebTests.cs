using Org.BouncyCastle.Security;
using Org.BouncyCastle.Tls;
using Org.BouncyCastle.Tls.Crypto.Impl.BC;
using Plugin.Insomniac.Web;
using System.Net;
using System.Text;

namespace Plugin.Insomniac.Tests;

public class WebTests
{
    private static InsomniacTitle Title(string root) => new()
    {
        Descriptor = new() { TitleId = "test", Name = "Test", ResourceDir = root },
        Igloo = new IglooDefinition
        {
            Hosts = ["igloo.example"],
            Answers = new() { ["/game/setInfo.py"] = new WebAnswer { Body = "ok" } },
        },
        LiveData = new LiveDataDefinition { Hosts = ["livedata.example"] },
    };

    private static WebServiceRequest Get(string host, string target) => new()
    {
        Method = "GET",
        Target = target,
        Headers = new Dictionary<string, string> { ["host"] = $"{host}:10091" },
    };

    [Fact]
    public void IglooAnswersWhatTitleDataSaysAndNothingElse()
    {
        InsomniacTitle title = Title(Path.GetTempPath());
        IglooService igloo = new(title, logTraffic: true);
        WebServiceResponse answer = WebComponent.Answer([igloo], Get("igloo.example", "/game/SETINFO.py?x=1"));
        Assert.Equal(200, answer.Status);
        Assert.Equal("ok", Encoding.UTF8.GetString(answer.Body));
        Assert.Equal(404, WebComponent.Answer([igloo], Get("igloo.example", "/game/getLeaderboards.py")).Status);
    }

    private static readonly TocDefinition Toc105 = new() { Path = "/encrypted/toc.bin", FilesPath = "/encrypted/", Enciphered = true, CipherPasses = 11 };

    private static InsomniacTitle LiveTitle(string root)
    {
        InsomniacTitle title = Title(root);
        title.LiveData.Tocs = [Toc105];
        title.Universe.Cipher.Passes = 11;
        return title;
    }

    [Fact]
    public void AnEmptyDirectoryGivesAnEmptyTocTheClientAccepts()
    {
        string root = Directory.CreateTempSubdirectory("insomniac-test").FullName;
        try
        {
            LiveDataService live = new(LiveTitle(root), TestData.SyntheticCipher());
            byte[] toc = live.Handle(Get("livedata.example", "/encrypted/toc.bin"))!.Body;
            Assert.Equal(16, toc.Length);
            ClientToc parsed = ClientToc.Read(toc, TestData.SyntheticCipher(), Toc105);
            Assert.Empty(parsed.Entries);
            Assert.Equal(11, parsed.Passes);
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void LiveDataListsAndServesItsFilesOnly()
    {
        string root = Directory.CreateTempSubdirectory("insomniac-test").FullName;
        try
        {
            string dir = Path.Combine(root, "insomniac", "livedata");
            Directory.CreateDirectory(dir);
            File.WriteAllBytes(Path.Combine(dir, "motd.ldbc"), [1, 2, 3]);
            File.WriteAllText(Path.Combine(dir, "notes.txt"), "hello");
            File.WriteAllBytes(Path.Combine(dir, "a-name-far-too-long-for-it.bin"), [9]);
            File.WriteAllBytes(Path.Combine(dir, "big.bin"), new byte[0x10000]);
            File.WriteAllText(Path.Combine(root, "secret.txt"), "no");
            LiveDataService live = new(LiveTitle(root), TestData.SyntheticCipher());

            ClientToc toc = ClientToc.Read(live.Handle(Get("livedata.example", "/encrypted/toc.bin"))!.Body, TestData.SyntheticCipher(), Toc105);
            Assert.Equal(["motd.ldbc", "notes.txt"], toc.Entries.Select(e => e.Name));
            Assert.Equal(3u, toc.Entries[0].Size);
            Assert.Equal(System.Security.Cryptography.MD5.HashData(new byte[] { 1, 2, 3 }), toc.Entries[0].Md5);

            Assert.Equal([1, 2, 3], live.Handle(Get("livedata.example", "/encrypted/motd.ldbc"))!.Body);
            Assert.Null(live.Handle(Get("livedata.example", "/encrypted/big.bin")));
            Assert.Null(live.Handle(Get("livedata.example", "/motd.ldbc")));
            Assert.Null(live.Handle(Get("livedata.example", "/encrypted/../../secret.txt")));
            Assert.Null(live.Handle(Get("livedata.example", "/encrypted/%2e%2e/%2e%2e/secret.txt")));
        }
        finally
        {
            Directory.Delete(root, recursive: true);
        }
    }

    [Fact]
    public void TheTocSumSkipsTxtEntries()
    {
        TocDefinition plain = new() { Path = "/toc.bin", CipherPasses = 11 };
        byte[] withTxt = LiveDataToc.Build([new("a.bin", [1]), new("b.txt", [2])], plain, 11, null);
        byte[] without = LiveDataToc.Build([new("a.bin", [1])], plain, 11, null);
        Assert.Equal(without.AsSpan(8, 8).ToArray(), withTxt.AsSpan(8, 8).ToArray());
        ClientToc.Read(withTxt, null, plain);
    }

    /// <summary>The checks of the client's TOC parser [C R3 1.05 0x46d138], each failure as its error.</summary>
    private sealed record ClientToc(int Passes, List<(string Name, uint Size, byte[] Md5)> Entries)
    {
        public static ClientToc Read(byte[] wire, Plugin.Insomniac.Mr.MrCipher? cipher, TocDefinition toc)
        {
            byte[] b = [.. wire];
            Assert.True(b.Length >= 16, "error 0x17: under 16 bytes");
            cipher?.Decrypt(b, toc.CipherPasses);
            Assert.True(System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(b) == b.Length, "error 0x18: length");
            Assert.True((b.Length - 16) % 0x28 == 0, "error 0x19: entry size");
            int count = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(6));
            Assert.True(count == (b.Length - 16) / 0x28, "error 0x1a: count");
            Assert.True(count <= 0x40, "error 0x1b: too many");
            int passes = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(b.AsSpan(4));
            ulong sum = (ulong)passes;
            List<(string, uint, byte[])> entries = [];
            for (int i = 0; i < count; i++)
            {
                Span<byte> e = b.AsSpan(16 + 0x28 * i, 0x28);
                string name = Encoding.ASCII.GetString(e[..20]).TrimEnd('\0');
                if (!name.Contains(".txt"))
                    for (int w = 0; w < 5; w++)
                        sum += System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(e[(w * 8)..]);
                entries.Add((name, System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(e[20..]), e[24..].ToArray()));
            }
            Assert.True(System.Buffers.Binary.BinaryPrimitives.ReadUInt64BigEndian(b.AsSpan(8)) == sum, "error 0x1c: checksum");
            return new ClientToc(passes, entries);
        }
    }

    [Fact]
    public void ServesHttpsToATls10Client()
    {
        InsomniacTitle title = Title(Path.GetTempPath());
        WebComponent web = new(new Dictionary<int, IReadOnlyList<IWebService>> { [10091] = [new IglooService(title, logTraffic: true)] },
            LegacyTlsCredentials.Create("igloo.example", 1024), logTraffic: true);

        TlsClientProtocol client = new();
        client.Connect(new Tls10Client());
        Guid id = Guid.NewGuid();
        List<byte[]> toClient = [];
        void Pump()
        {
            while (client.GetAvailableOutputBytes() > 0)
            {
                byte[] bytes = new byte[client.GetAvailableOutputBytes()];
                client.ReadOutput(bytes, 0, bytes.Length);
                web.Received(id, 10091, new IPEndPoint(IPAddress.Loopback, 5000), bytes, toClient.Add, () => { });
                foreach (byte[] reply in toClient)
                    client.OfferInput(reply);
                toClient.Clear();
            }
        }
        Pump();
        byte[] request = Encoding.ASCII.GetBytes("GET /game/setInfo.py HTTP/1.1\r\nHost: igloo.example:10091\r\n\r\n");
        client.WriteApplicationData(request, 0, request.Length);
        Pump();

        byte[] plain = new byte[client.GetAvailableInputBytes()];
        client.ReadInput(plain, 0, plain.Length);
        string response = Encoding.ASCII.GetString(plain);
        Assert.StartsWith("HTTP/1.1 200 OK", response);
        Assert.EndsWith("\r\n\r\nok", response);
    }

    /// <summary>A client like the PS3's (TLS 1.0, RSA key exchange, CBC-SHA) that trusts any certificate.</summary>
    private sealed class Tls10Client() : DefaultTlsClient(new BcTlsCrypto(new SecureRandom()))
    {
        protected override ProtocolVersion[] GetSupportedVersions() => [ProtocolVersion.TLSv10];
        protected override int[] GetSupportedCipherSuites() => [CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA];
        public override TlsAuthentication GetAuthentication() => new AnyServer();

        private sealed class AnyServer : TlsAuthentication
        {
            public void NotifyServerCertificate(TlsServerCertificate serverCertificate) { }
            public TlsCredentials? GetClientCredentials(CertificateRequest certificateRequest) => null;
        }
    }
}
