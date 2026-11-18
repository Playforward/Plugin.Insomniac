namespace Plugin.Insomniac;

/// <summary>
/// Plugin-wide settings, kept in <c>Configs/InsomniacConfig.json</c>. What differs per game is in the
/// title's <c>insomniac/title.json</c> (<see cref="InsomniacTitle"/>).
/// </summary>
public sealed class InsomniacSettings
{
    /// <summary>
    /// The address the Universe gives consoles for the Galaxy (introductions, quick-match records). Empty: 127.0.0.1
    /// for a console on this machine, else this machine's first LAN IPv4 address.
    /// </summary>
    public string PublicHost { get; set; } = "";

    /// <summary>
    /// Which service answers on which ServerApp listener. Each port also needs an entry in
    /// <c>ServerAppSettings.json</c> (UDP ones with <c>UseUDP</c> true). The game is told ports by its
    /// lobby options, so a listener on another port needs those redirected to it (tools/port-redirect.sh).
    /// </summary>
    public List<InsomniacListener> Listeners { get; set; } =
    [
        new() { Component = InsomniacComponents.Universe, Port = 12350, Udp = true },
        new() { Component = InsomniacComponents.Igloo, Port = 10091 },
        new() { Component = InsomniacComponents.LiveData, Port = 10443, GamePort = 443 },
        new() { Component = InsomniacComponents.Galaxy, Port = 12351, Udp = true },
    ];

    /// <summary>
    /// Secrets the titles refer to by name (the MR cipher's keys and S-box). Kept here, out of the
    /// repositories; tools/re/r3keys.py prints them from a decrypted EBOOT.
    /// </summary>
    public Dictionary<string, string> Keys { get; set; } = [];

    /// <summary>Where the TLS certificate and anything uploaded are kept, relative to the working directory.</summary>
    public string DataDir { get; set; } = "Data/insomniac";

    /// <summary>Log every datagram and request at Debug level.</summary>
    public bool LogTraffic { get; set; } = true;
}

public sealed class InsomniacListener
{
    public string Component { get; set; } = "";

    /// <summary>The ServerApp listener's port.</summary>
    public int Port { get; set; }
    public bool Udp { get; set; }

    /// <summary>The port the game uses, when it is not <see cref="Port"/> (for logs and the redirect script); 0 = the same.</summary>
    public int GamePort { get; set; }
}

public static class InsomniacComponents
{
    /// <summary>The MR Universe server (UDP; R3 lobby option LOBBY_MR_UNIVERSE_PORT, default 12350).</summary>
    public const string Universe = "UNIVERSE";

    /// <summary>SCEA's Igloo web service (HTTPS; LOBBY_STATS_PORT 10091 on R3).</summary>
    public const string Igloo = "IGLOO";

    /// <summary>The live data file host (HTTPS; LOBBY_LIVE_DATA_PORT 443 on R3).</summary>
    public const string LiveData = "LIVEDATA";

    /// <summary>
    /// The MR Galaxy (ENet over UDP; LOBBY_MR_GALAXY_PORT, default 12351), where matched consoles connect. Not served
    /// yet: datagrams are logged deciphered.
    /// </summary>
    public const string Galaxy = "GALAXY";
}

public static class InsomniacAddresses
{
    /// <summary>This machine's first non-loopback IPv4 address, else loopback.</summary>
    public static System.Net.IPAddress Lan() =>
        System.Net.Dns.GetHostAddresses(System.Net.Dns.GetHostName())
            .FirstOrDefault(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork && !System.Net.IPAddress.IsLoopback(a))
        ?? System.Net.IPAddress.Loopback;
}
