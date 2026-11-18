using ServerShared.Titles;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Plugin.Insomniac;

/// <summary>
/// One Insomniac Games title, read from <c>&lt;ResourceDir&gt;/insomniac/title.json</c> of a title whose
/// <c>ProtocolFamily</c> is <c>insomniac</c>. Insomniac's PS3 online stack (Resistance 3 first) is its own:
/// the message router (MR) "Universe" server over UDP, SCEA's "Igloo" web service for stats, and a
/// "live data" file host. Matches are player-hosted over ENet, peer to peer.
/// </summary>
public sealed class InsomniacTitle
{
    public const string ProtocolFamily = "insomniac";
    public const string FileName = "insomniac/title.json";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
        Converters = { new JsonStringEnumConverter(), new HexNumberConverter<int>(), new HexNumberConverter<byte>(), new HexNumberConverter<ushort>() },
    };

    [JsonIgnore]
    public TitleDescriptor Descriptor { get; set; } = new();

    /// <summary>The title's insomniac/ directory, where its relative paths start.</summary>
    [JsonIgnore]
    public string Directory => Path.Combine(Descriptor.ResourceDir, "insomniac");

    public UniverseDefinition Universe { get; set; } = new();
    public IglooDefinition Igloo { get; set; } = new();
    public LiveDataDefinition LiveData { get; set; } = new();
    public MatchmakingDefinition Matchmaking { get; set; } = new();

    public override string ToString() => Descriptor.ToString();

    public static List<InsomniacTitle> LoadAll(IEnumerable<TitleDescriptor> titles, List<string> problems)
    {
        List<InsomniacTitle> loaded = [];
        foreach (TitleDescriptor descriptor in titles.Where(t =>
                     string.Equals(t.ProtocolFamily, ProtocolFamily, StringComparison.OrdinalIgnoreCase)))
        {
            string path = Path.Combine(descriptor.ResourceDir, FileName);
            if (!File.Exists(path))
            {
                problems.Add($"{descriptor}: {path} not found");
                continue;
            }
            try
            {
                InsomniacTitle? title = Parse(File.ReadAllText(path));
                if (title is null)
                {
                    problems.Add($"{descriptor}: {path} is empty");
                    continue;
                }
                title.Descriptor = descriptor;
                loaded.Add(title);
            }
            catch (Exception exception) when (exception is JsonException or FormatException)
            {
                problems.Add($"{descriptor}: {path} is not valid: {exception.Message}");
            }
        }
        return loaded;
    }

    /// <summary>A title.json's contents (comments allowed).</summary>
    public static InsomniacTitle? Parse(string json) => JsonSerializer.Deserialize<InsomniacTitle>(json, JsonOptions);
}

/// <summary>The MR Universe server: what the client's UDP channel to it expects.</summary>
public sealed class UniverseDefinition
{
    /// <summary>
    /// Header bytes 7..10 (hex), which the client checks on every data packet. A datagram is matched to its
    /// title by them, so they must differ between titles sharing a listener.
    /// </summary>
    public string HeaderId { get; set; } = "";

    /// <summary>Header byte 6 on data packets (the client drops others).</summary>
    public byte Version { get; set; } = 1;

    public MrCipherDefinition Cipher { get; set; } = new();

    /// <summary>The client's receive buffer: the largest datagram it takes.</summary>
    public int MaxDatagram { get; set; } = 0x290;

    /// <summary>How often an unacked push to the client is sent again.</summary>
    public double RetransmitSeconds { get; set; } = 1;

    /// <summary>How long a push is resent before it is dropped.</summary>
    public double GiveUpSeconds { get; set; } = 30;

    /// <summary>How long a client that sends nothing is remembered.</summary>
    public double IdleSeconds { get; set; } = 600;

    /// <summary>Names for message ids (hex keys, "0x25"), for logs only; filled in as messages are identified.</summary>
    public Dictionary<string, string> MessageNames { get; set; } = [];

    public byte[] HeaderIdBytes()
    {
        byte[] bytes = Convert.FromHexString(HeaderId.Replace(" ", ""));
        if (bytes.Length != 4)
            throw new FormatException($"Universe.HeaderId \"{HeaderId}\" is not 4 bytes of hex");
        return bytes;
    }

    public string NameOf(byte id) =>
        MessageNames.FirstOrDefault(n => ParseId(n.Key) == id).Value ?? "?";

    private static int ParseId(string key) =>
        key.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? Convert.ToInt32(key[2..], 16) : int.Parse(key);
}

/// <summary>Names of the cipher's secrets in the plugin config's <c>Keys</c>, and the pass count.</summary>
public sealed class MrCipherDefinition
{
    /// <summary>Key of the round keys (big-endian u32s back to back, hex).</summary>
    public string Keys { get; set; } = "";

    /// <summary>Key of the 256-byte S-box (hex).</summary>
    public string SBox { get; set; } = "";

    /// <summary>
    /// Passes per window position. The game's default, unless lobby option LOBBY_MR_ENCRYPTION_NUM_PASSES or
    /// -mr_encryption sets another.
    /// </summary>
    public int Passes { get; set; }
}

/// <summary>SCEA's Igloo web service (stats, leaderboards, player data), HTTPS.</summary>
public sealed class IglooDefinition
{
    /// <summary>Host names it answers for (the game's own, redirected here).</summary>
    public List<string> Hosts { get; set; } = [];

    /// <summary>Fixed answers by path, until a path gets a real implementation.</summary>
    public Dictionary<string, WebAnswer> Answers { get; set; } = new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>The live data host: a table of contents and the files it lists, HTTPS.</summary>
public sealed class LiveDataDefinition
{
    public List<string> Hosts { get; set; } = [];

    /// <summary>
    /// Directory (under the title's insomniac/ directory) of the files to list: every file directly in it goes into
    /// each TOC and is served under that TOC's <see cref="TocDefinition.FilesPath"/>. Empty is a valid live data set.
    /// </summary>
    public string Directory { get; set; } = "livedata";

    /// <summary>The TOC forms the title's builds ask for (they differ by path and cipher).</summary>
    public List<TocDefinition> Tocs { get; set; } = [];
}

/// <summary>One TOC form (<see cref="Web.LiveDataToc"/>): where a build asks for it and how it reads it.</summary>
public sealed class TocDefinition
{
    /// <summary>The request path (lobby option LOBBY_LIVE_DATA_TOC_URI).</summary>
    public string Path { get; set; } = "";

    /// <summary>Where the listed files are fetched (LOBBY_LIVE_DATA_BASE_URI; the file name is appended).</summary>
    public string FilesPath { get; set; } = "/";

    /// <summary>Whether the TOC is enciphered with the title's MR cipher.</summary>
    public bool Enciphered { get; set; }

    /// <summary>Passes the client deciphers the TOC with (it sets them before, whatever the shared count is).</summary>
    public int CipherPasses { get; set; }

    public int MaxEntries { get; set; } = 64;
    public int MaxFileSize { get; set; } = 0xffff;
    public string Note { get; set; } = "";
}

/// <summary>A fixed HTTP answer.</summary>
public sealed class WebAnswer
{
    public int Status { get; set; } = 200;
    public string ContentType { get; set; } = "text/plain";
    public string Body { get; set; } = "";
    public string Note { get; set; } = "";
}

/// <summary>
/// Quick match over the Universe [C R3 1.05; docs/RESISTANCE3.md "Matchmaking"]. A console that finds nothing hosts:
/// it creates a session (<see cref="SessionCreate"/>) and waits for an introduction (<see cref="Introduction"/>) naming
/// the address to ENet-connect the session to (the Galaxy). A searching console sends a request
/// (<see cref="Request"/>), takes the candidate records (<see cref="Record"/>) that arrive within 5 s, and a closing
/// introduction with session id 0 hands the lobby the count; it then ENet-connects to each candidate's address in turn.
/// </summary>
public sealed class MatchmakingDefinition
{
    public bool Enabled { get; set; }
    public SessionCreateLayout SessionCreate { get; set; } = new();
    public RequestLayout Request { get; set; } = new();
    public RecordLayout Record { get; set; } = new();
    public IntroductionLayout Introduction { get; set; } = new();

    /// <summary>Records the lobby reads per answer (0x3caa2c stops at 20).</summary>
    public int MaxResults { get; set; } = 20;

    /// <summary>How long a created session is offered without being created again.</summary>
    public double SessionSeconds { get; set; } = 120;

    /// <summary>Answer a session create with an introduction to the Galaxy (no Galaxy runs yet: the ENet connect fails).</summary>
    public bool IntroduceHosts { get; set; } = true;
}

/// <summary>The message a hosting console sends to create a session [C 1.05 0x8f6500 via 0x8f6730].</summary>
public sealed class SessionCreateLayout
{
    public byte Id { get; set; }
    /// <summary>The u16 the client numbers its sessions with (its +0x7a24 counter; the introduction echoes it).</summary>
    public int SessionIdAt { get; set; }
    /// <summary>Bytes kept with the session (from client +0x7a28/+0x7a29; meaning not known).</summary>
    public int DetailsAt { get; set; }
    public int DetailCount { get; set; }
}

/// <summary>The typed request (0x26) and which kinds are quick-match searches.</summary>
public sealed class RequestLayout
{
    public byte Id { get; set; }
    public int KindAt { get; set; }
    public List<int> QuickMatchKinds { get; set; } = [];
}

/// <summary>Offsets of one candidate record (0x11).</summary>
public sealed class RecordLayout
{
    public byte Class { get; set; } = 2;
    public byte Id { get; set; }
    /// <summary>The fixed part (both strings empty).</summary>
    public int Size { get; set; }
    public int IdentityAt { get; set; }
    public int Word0At { get; set; }
    public int AddressAt { get; set; }
    public int PortAt { get; set; }
    public int KeyAt { get; set; }
    public int Word1At { get; set; }
    public int Short0At { get; set; }
    public int BytesAt { get; set; }
    public int ByteCount { get; set; }
    /// <summary>Index in the byte block of the mode the lobby filters on (record +0x33 = block byte 3).</summary>
    public int ModeByte { get; set; }
    /// <summary>The lobby keeps a record when its mode byte is above 8 and (mode - <see cref="ModeBase"/>) is the searched mode or the search is for any.</summary>
    public int ModeBase { get; set; }
    public int StringsAt { get; set; }
}

/// <summary>Offsets of the introduction (0x23).</summary>
public sealed class IntroductionLayout
{
    public byte Class { get; set; } = 2;
    public byte Id { get; set; }
    public int Size { get; set; }
    public int SessionIdAt { get; set; }
    public int CountAt { get; set; }
    public int AddressAt { get; set; }
    public int PortAt { get; set; }
}

/// <summary>Reads a number written plainly or as a "0x..." string (ids and offsets read better in hex).</summary>
public sealed class HexNumberConverter<T> : JsonConverter<T> where T : struct, System.Numerics.INumber<T>
{
    public override T Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.Number)
            return T.CreateChecked(reader.GetInt64());
        string text = reader.GetString() ?? throw new JsonException("a number or a \"0x..\" string was expected");
        long value = text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? long.Parse(text[2..], System.Globalization.NumberStyles.HexNumber, System.Globalization.CultureInfo.InvariantCulture)
            : long.Parse(text, System.Globalization.CultureInfo.InvariantCulture);
        return T.CreateChecked(value);
    }

    public override void Write(Utf8JsonWriter writer, T value, JsonSerializerOptions options) => writer.WriteNumberValue(long.CreateChecked(value));
}
