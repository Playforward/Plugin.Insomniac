using System.Collections.Concurrent;
using System.Net;

namespace Plugin.Insomniac.Web;

/// <summary>A title's HTTP(S) service on one of the web listeners (Igloo, live data).</summary>
public interface IWebService
{
    /// <summary>For logs: "igloo", "livedata".</summary>
    string Kind { get; }

    InsomniacTitle Title { get; }

    /// <summary>Host names this service answers for (the game's own, redirected here).</summary>
    IReadOnlyCollection<string> Hosts { get; }

    /// <summary>The answer, or null when the service has nothing at that path (404).</summary>
    WebServiceResponse? Handle(WebServiceRequest request);
}

/// <summary>
/// The web listeners: TLS is ended here with <see cref="LegacyTlsSession"/>, so the PS3's TLS 1.0 clients are
/// served on hosts whose OpenSSL refuses them. Each request goes to the listener's service whose
/// <see cref="IWebService.Hosts"/> has its Host, or to the only one when there is one.
/// </summary>
/// <remarks>
/// Not bound to a socket: the plugin hands it each connection's bytes. ServerApp's TCP listener passes raw bytes
/// on for anything not starting with an upper-case ASCII letter, which a TLS record never does; plain HTTP goes
/// to ServerApp's own HTTP routes instead and is not served here. The game's certificate check is the one
/// Resistance 2 has ("Validating certificate", same web request code) [guess for R3: R2 1.60's callback 0x266634
/// accepts any chain].
/// </remarks>
public sealed class WebComponent(IReadOnlyDictionary<int, IReadOnlyList<IWebService>> servicesByPort, LegacyTlsCredentials credentials, bool logTraffic)
{
    private const byte TlsHandshakeRecord = 0x16;
    private readonly ConcurrentDictionary<Guid, WebConnection> _connections = new();

    public bool Serves(int port) => servicesByPort.ContainsKey(port);

    /// <summary>Bytes arrived on a connection to <paramref name="port"/>; <paramref name="send"/> carries whatever goes back.</summary>
    public void Received(Guid connectionId, int port, IPEndPoint? remote, ReadOnlySpan<byte> data, Action<byte[]> send, Action disconnect)
    {
        if (!servicesByPort.TryGetValue(port, out IReadOnlyList<IWebService>? services))
            return;
        bool isNew = !_connections.ContainsKey(connectionId);
        WebConnection connection = isNew ? _connections.GetOrAdd(connectionId, new WebConnection(OpenSession(data), remote)) : _connections[connectionId];
        if (isNew && logTraffic)
            Log.Debug("[insomniac/web] {Remote} -> {Port}: new connection ({Kind}), first {Length} bytes {Bytes}", remote, port,
                connection.Tls is null ? "not TLS" : "TLS", data.Length, Convert.ToHexString(data[..Math.Min(data.Length, 96)]));
        try
        {
            byte[] plain = data.ToArray();
            if (connection.Tls is { } tls)
            {
                bool wasDone = tls.HandshakeComplete;
                plain = tls.Receive(data);
                Flush(tls, send);
                if (!wasDone && tls.HandshakeComplete && logTraffic)
                    Log.Debug("[insomniac/web] {Remote}: TLS up ({Negotiated})", remote, tls.Negotiated);
                if (tls.IsClosed)
                {
                    Disconnected(connectionId);
                    disconnect();
                    return;
                }
            }
            if (plain.Length == 0)
                return;

            foreach (WebServiceRequest request in connection.Reader.Feed(plain, remote))
            {
                WebServiceResponse response = Answer(services, request);
                bool keepAlive = !string.Equals(request.Headers.GetValueOrDefault("connection"), "close", StringComparison.OrdinalIgnoreCase);
                byte[] bytes = response.Serialize(keepAlive);
                if (connection.Tls is { } session)
                {
                    session.Send(bytes);
                    Flush(session, send);
                }
                else
                    send(bytes);
            }
        }
        catch (Exception exception)
        {
            Log.Warning(exception, "[insomniac/web] {Remote}: connection dropped", remote);
            if (connection.Tls is { } session)
                Flush(session, send);
            Disconnected(connectionId);
            disconnect();
        }
    }

    public void Disconnected(Guid connectionId)
    {
        if (_connections.TryRemove(connectionId, out WebConnection? connection) && connection.Tls is { HandshakeComplete: false })
            Log.Information("[insomniac/web] {Remote}: closed before the TLS handshake finished (certificate or cipher suites refused?)", connection.Remote);
    }

    /// <summary>The answer of the service whose host the request names (else the only one), logged.</summary>
    public static WebServiceResponse Answer(IReadOnlyList<IWebService> services, WebServiceRequest request)
    {
        IWebService? service = services.FirstOrDefault(s => s.Hosts.Contains(request.Host, StringComparer.OrdinalIgnoreCase))
                               ?? (services.Count == 1 ? services[0] : null);
        WebServiceResponse response;
        try
        {
            response = service?.Handle(request) ?? WebServiceResponse.NotFound();
        }
        catch (Exception exception)
        {
            Log.Error(exception, "[insomniac/web] {Request} failed", request);
            response = WebServiceResponse.Text("server error", 500);
        }
        Log.Information("[insomniac/{Kind}] {Remote} {Request} ({Length} body bytes) -> {Status} ({ResponseLength} bytes)",
            service?.Kind ?? "web", request.Remote, request, request.Body.Length, response.Status, response.Body.Length);
        return response;
    }

    /// <summary>A TLS session for a handshake record; none (the bytes are taken as they are) otherwise.</summary>
    private LegacyTlsSession? OpenSession(ReadOnlySpan<byte> first) =>
        first.Length > 0 && first[0] == TlsHandshakeRecord ? new LegacyTlsSession(credentials) : null;

    private static void Flush(IWebTlsSession tls, Action<byte[]> send)
    {
        byte[] output = tls.TakeOutput();
        if (output.Length > 0)
            send(output);
    }

    private sealed class WebConnection(IWebTlsSession? tls, IPEndPoint? remote)
    {
        public IWebTlsSession? Tls { get; } = tls;
        public IPEndPoint? Remote { get; } = remote;
        public HttpRequestReader Reader { get; } = new();
    }
}
