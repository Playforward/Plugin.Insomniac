using Plugin.Insomniac.Mr;
using Plugin.Insomniac.Web;
using ServerShared.Controllers;
using ServerShared.EventArguments;
using ServerShared.Plugins;
using ServerShared.Server;
using ServerShared.Titles;
using System.Net;

namespace Plugin.Insomniac;

/// <summary>
/// Insomniac Games' own PS3 online services (Resistance 3 first), served on ServerApp listeners: the message
/// router (MR) Universe server over UDP, and SCEA's Igloo stats service and the live data host over HTTPS.
/// Matches themselves are player-hosted (ENet between consoles) and need no server. Which games are served
/// comes from title data (<see cref="InsomniacTitle"/>).
/// </summary>
public sealed class InsomniacPlugin : ServerPlugin<InsomniacSettings>
{
    public override uint Priority => 1;
    public override string Name => "Insomniac";

    private readonly HashSet<int> _universePorts = [];
    private readonly HashSet<int> _galaxyPorts = [];
    private Dictionary<InsomniacTitle, MrCipher> _ciphers = [];
    private UniverseService? _universe;
    private WebComponent? _web;

    public override void Start()
    {
        List<string> problems = [];
        List<InsomniacTitle> titles = InsomniacTitle.LoadAll(TitleRegistry.All, problems);
        foreach (string problem in problems)
            Log.Error("[insomniac] {Problem}", problem);
        if (titles.Count == 0)
        {
            Log.Warning("[insomniac] no title with ProtocolFamily \"{Family}\" in Configs/{File}; not starting",
                InsomniacTitle.ProtocolFamily, TitleRegistry.ConfigFileName);
            return;
        }

        Dictionary<InsomniacTitle, MrCipher> ciphers = [];
        foreach (InsomniacTitle title in titles)
            if (CipherFor(title) is { } cipher)
                ciphers[title] = cipher;
        List<(InsomniacTitle, MrCipher)> universeTitles = [.. ciphers.Select(c => (c.Key, c.Value))];
        _ciphers = ciphers;
        if (universeTitles.Count > 0)
        {
            _universe = new UniverseService(universeTitles, Config.LogTraffic);
            foreach (InsomniacTitle title in ciphers.Keys.Where(t => t.Matchmaking.Enabled))
                new Matchmaking(title, GalaxyFor).Register(_universe);
        }

        Dictionary<int, IReadOnlyList<IWebService>> webPorts = [];
        foreach (InsomniacListener listener in Config.Listeners.Where(l => !l.Udp))
        {
            List<IWebService> services = listener.Component.ToUpperInvariant() switch
            {
                InsomniacComponents.Igloo => [.. titles.Where(t => t.Igloo.Hosts.Count > 0).Select(t => new IglooService(t, Config.LogTraffic))],
                InsomniacComponents.LiveData => [.. titles.Where(t => t.LiveData.Hosts.Count > 0).Select(t => new LiveDataService(t, ciphers.GetValueOrDefault(t)))],
                _ => [],
            };
            if (services.Count > 0)
                webPorts[listener.Port] = services;
        }
        if (webPorts.Count > 0)
        {
            LegacyTlsCredentials credentials = LegacyTlsCredentials.LoadOrCreate(Path.Combine(Config.DataDir, "web"),
                titles.SelectMany(t => t.Igloo.Hosts).FirstOrDefault() ?? "insomniac");
            _web = new WebComponent(webPorts, credentials, Config.LogTraffic);
        }

        BindListeners();
        CoreUdpSession.OnBytesReceived += OnUdpBytes;
        CoreUnsecureSession.OnBytesReceived += OnTcpBytes;
        CoreUnsecureSession.OnDisconnectedEvent += OnTcpDisconnected;

        Log.Information("[insomniac] serving {Titles}; listening: {Listeners}", string.Join(", ", titles),
            string.Join(", ", Config.Listeners.Select(l =>
                $"{l.Component} {l.Port}/{(l.Udp ? "udp" : "tcp")}{(l.GamePort != 0 && l.GamePort != l.Port ? $" (game uses {l.GamePort})" : "")}")));
    }

    public override void Stop()
    {
        CoreUdpSession.OnBytesReceived -= OnUdpBytes;
        CoreUnsecureSession.OnBytesReceived -= OnTcpBytes;
        CoreUnsecureSession.OnDisconnectedEvent -= OnTcpDisconnected;
        _universe?.Dispose();
        _universe = null;
        _web = null;
        _universePorts.Clear();
        _galaxyPorts.Clear();
        _ciphers = [];
    }

    /// <summary>The Galaxy address a console is told: PublicHost, else loopback for a console on this machine, else the LAN address.</summary>
    private IPEndPoint? GalaxyFor(MrPeer peer)
    {
        if (Config.Listeners.FirstOrDefault(l => l.Udp && string.Equals(l.Component, InsomniacComponents.Galaxy, StringComparison.OrdinalIgnoreCase)) is not { } galaxy)
            return null;
        int port = galaxy.GamePort != 0 ? galaxy.GamePort : galaxy.Port;
        if (!string.IsNullOrWhiteSpace(Config.PublicHost))
            return new IPEndPoint(IPAddress.TryParse(Config.PublicHost, out IPAddress? parsed) ? parsed
                : Dns.GetHostAddresses(Config.PublicHost).First(a => a.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork), port);
        return new IPEndPoint(IPAddress.IsLoopback(peer.Remote.Address) ? IPAddress.Loopback : InsomniacAddresses.Lan(), port);
    }

    private MrCipher? CipherFor(InsomniacTitle title)
    {
        MrCipherDefinition cipher = title.Universe.Cipher;
        string? keys = Config.Keys.GetValueOrDefault(cipher.Keys);
        string? sbox = Config.Keys.GetValueOrDefault(cipher.SBox);
        if (string.IsNullOrEmpty(keys) || string.IsNullOrEmpty(sbox))
        {
            Log.Error("[insomniac] {Title}: keys \"{Keys}\" and \"{SBox}\" are not in {File} Keys (tools/re/r3keys.py prints them); " +
                      "no Universe server for it", title, cipher.Keys, cipher.SBox, ConfigFileName);
            return null;
        }
        try
        {
            title.Universe.HeaderIdBytes();
            return MrCipher.FromHex(keys, sbox, cipher.Passes);
        }
        catch (Exception exception) when (exception is FormatException or ArgumentException)
        {
            Log.Error("[insomniac] {Title}: Universe cipher or header id not usable: {Message}; no Universe server for it", title, exception.Message);
            return null;
        }
    }

    /// <summary>Hooks each configured listener; a port ServerApp has no server for is an error, not a silent timeout.</summary>
    private void BindListeners()
    {
        foreach (InsomniacListener listener in Config.Listeners)
        {
            var server = ServerController.Servers.FirstOrDefault(s => s.Port == listener.Port && s.IsUdp == listener.Udp);
            if (server is null)
            {
                Log.Error("[insomniac] no {Kind} server on port {Port} for {Component}; add it to ServerAppSettings.json{Udp}",
                    listener.Udp ? "UDP" : "TCP", listener.Port, listener.Component, listener.Udp ? " with UseUDP=true" : "");
                continue;
            }
            switch (listener.Component.ToUpperInvariant())
            {
                case InsomniacComponents.Universe when listener.Udp:
                    if (_universe is not null)
                        _universePorts.Add(listener.Port);
                    break;
                case InsomniacComponents.Galaxy when listener.Udp:
                    _galaxyPorts.Add(listener.Port);
                    break;
                case InsomniacComponents.Igloo or InsomniacComponents.LiveData when !listener.Udp:
                    if (_web?.Serves(listener.Port) != true)
                        Log.Warning("[insomniac] {Component} listener {Port}: no title has hosts for it", listener.Component, listener.Port);
                    break;
                default:
                    Log.Error("[insomniac] listener {Port}/{Kind}: component {Component} is not served that way (UNIVERSE and GALAXY are UDP; IGLOO and LIVEDATA are TCP)",
                        listener.Port, listener.Udp ? "udp" : "tcp", listener.Component);
                    break;
            }
        }
    }

    private void OnUdpBytes(object? sender, SessionBytesReceivedEventArgs e)
    {
        if (sender is not CoreUdpSession session || session.EndPoint is not IPEndPoint remote)
            return;
        if (_galaxyPorts.Contains(session.Server.Port))
        {
            GalaxyDatagram(remote, session.Server.Port, e.Data.Span);
            return;
        }
        if (_universe is not { } universe || !_universePorts.Contains(session.Server.Port))
            return;
        try
        {
            universe.Received(remote, e.Data.Span, bytes => session.SendAsync(bytes));
        }
        catch (Exception exception)
        {
            Log.Error(exception, "[insomniac/universe] UDP {Port}: datagram from {Remote} could not be handled", session.Server.Port, remote);
        }
    }

    /// <summary>
    /// Logs a Galaxy datagram as received and deciphered with each title's MR cipher (the client hands ENet the MR
    /// cipher as its packet callbacks when encryption is on [C 1.02 0x8f85c0]). No answer: the Galaxy is not served yet.
    /// </summary>
    private void GalaxyDatagram(IPEndPoint remote, int port, ReadOnlySpan<byte> data)
    {
        string shown = Convert.ToHexString(data[..Math.Min(data.Length, 128)]);
        byte[] received = data.ToArray();
        IEnumerable<string> plain = _ciphers.Select(c =>
        {
            byte[] copy = [.. received];
            c.Value.Decrypt(copy);
            return $"{c.Key.Descriptor.TitleId}: {Convert.ToHexString(copy.AsSpan(0, Math.Min(copy.Length, 128)))}";
        });
        Log.Information("[insomniac/galaxy] {Remote} -> {Port}: {Length}B {Data}; deciphered {Plain} (not answered: no Galaxy yet)",
            remote, port, data.Length, shown, string.Join("; ", plain));
    }

    private void OnTcpBytes(object? sender, SessionBytesReceivedEventArgs e)
    {
        if (_web is not { } web || sender is not CoreUnsecureSession session || session.Server is not CoreUnsecureServer server || !web.Serves(server.Port))
            return;
        web.Received(session.Id, server.Port, session.Socket?.RemoteEndPoint as IPEndPoint, e.Data.Span,
            bytes => session.SendAsync(bytes), () => session.Disconnect());
    }

    private void OnTcpDisconnected(object? sender, SessionGuidEventArgs e) => _web?.Disconnected(e.Id);
}
