namespace Plugin.Insomniac.Web;

/// <summary>
/// SCEA's Igloo web service for one title: stats, leaderboards, replays, player data, as Python CGI paths
/// (R3: <c>/resistance3/*.py</c> on port 10091, lobbyoptions.csv). Until a path is implemented it gets the
/// fixed answer title.json gives it, else 404; every request is logged with its query and body.
/// </summary>
/// <remarks>
/// R3 1.02 reads these lobby options [C callers of 0x1bfd60]: stats host/port everywhere, sync request
/// (0x467f18), upload (0x467654), player data (0x46870c, 0x46895c), MyResistance status (0x471cc4), the
/// page request "%s?name=%s&amp;page=%s&amp;lang=%s&amp;fmt=%s" (0x46cc90). LOBBY_LOGIN_URI (setInfo.py)
/// is never read, as in Resistance 2: logging in is not an Igloo step.
/// </remarks>
public sealed class IglooService(InsomniacTitle title, bool logTraffic) : IWebService
{
    public string Kind => "igloo";
    public InsomniacTitle Title => title;
    public IReadOnlyCollection<string> Hosts => title.Igloo.Hosts;

    public WebServiceResponse? Handle(WebServiceRequest request)
    {
        if (logTraffic)
            Log.Debug("[insomniac/igloo] {Request} headers {Headers} body {Body}", request,
                string.Join("; ", request.Headers.Select(h => $"{h.Key}: {h.Value}")),
                Convert.ToHexString(request.Body.AsSpan(0, Math.Min(request.Body.Length, 512))));

        WebAnswer? answer = title.Igloo.Answers.FirstOrDefault(a => string.Equals(a.Key, request.Path, StringComparison.OrdinalIgnoreCase)).Value;
        if (answer is null)
        {
            Log.Warning("[insomniac/igloo] {Title}: nothing at {Path} yet (query {Query})", title, request.Path,
                string.Join("&", request.Query.Select(q => $"{q.Key}={q.Value}")));
            return null;
        }
        return new WebServiceResponse
        {
            Status = answer.Status,
            ContentType = answer.ContentType,
            Body = System.Text.Encoding.UTF8.GetBytes(answer.Body),
        };
    }
}
