using Plugin.Insomniac.Mr;

namespace Plugin.Insomniac.Web;

/// <summary>
/// The live data host for one title: a table of contents (<see cref="LiveDataToc"/>), then the files it lists
/// (R3 1.05: <c>https://ig-r3-livedata.s3.amazonaws.com:443/encrypted/toc.bin</c>, files under <c>/encrypted/</c>,
/// lobbyoptions.csv in patch_02.psarc). The TOC is built on each request from the files in the title's live data
/// directory, so adding a file there is all it takes to publish it.
/// </summary>
/// <remarks>
/// [C R3 1.05] LiveDataMgr (state machine 0x46ecd0) caches the files in "\live_data\", deletes ones the TOC no
/// longer lists and processes "precompiled configs" from them. Without a TOC it stops in its error state and the
/// online menus do not go on [live 2026-11-13: 404, then no Universe traffic]. The original files are lost (the S3
/// bucket is gone), so the directory starts empty: an empty TOC is a valid one.
/// </remarks>
public sealed class LiveDataService(InsomniacTitle title, MrCipher? cipher) : IWebService
{
    public string Kind => "livedata";
    public InsomniacTitle Title => title;
    public IReadOnlyCollection<string> Hosts => title.LiveData.Hosts;

    private string Root => Path.GetFullPath(Path.Combine(title.Directory, title.LiveData.Directory));

    public WebServiceResponse? Handle(WebServiceRequest request)
    {
        if (!request.Method.Equals("GET", StringComparison.OrdinalIgnoreCase) && !request.Method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
        {
            Log.Warning("[insomniac/livedata] {Title}: {Method} {Path} is not a fetch; not served", title, request.Method, request.Path);
            return null;
        }
        string path = Uri.UnescapeDataString(request.Path);

        if (title.LiveData.Tocs.FirstOrDefault(t => string.Equals(t.Path, path, StringComparison.OrdinalIgnoreCase)) is { } toc)
            return Toc(toc);

        foreach (TocDefinition form in title.LiveData.Tocs.Where(t => path.StartsWith(t.FilesPath, StringComparison.OrdinalIgnoreCase)))
            if (Files(form).FirstOrDefault(f => f.Name == path[form.FilesPath.Length..]) is { } file)
                return WebServiceResponse.Binary(file.Data);

        Log.Warning("[insomniac/livedata] {Title}: nothing at {Path} (TOC paths: {Tocs}; files in {Root})", title, request.Path,
            string.Join(", ", title.LiveData.Tocs.Select(t => t.Path)), Root);
        return null;
    }

    private WebServiceResponse? Toc(TocDefinition toc)
    {
        if (toc.Enciphered && cipher is null)
        {
            Log.Error("[insomniac/livedata] {Title}: {Path} must be enciphered, but the title has no MR cipher (keys missing from the config)", title, toc.Path);
            return null;
        }
        List<LiveDataFile> files = Files(toc);
        // The TOC also sets the client's shared pass count: keep it at what the Universe channel uses.
        byte[] body = LiveDataToc.Build(files, toc, (ushort)title.Universe.Cipher.Passes, toc.Enciphered ? cipher : null);
        Log.Information("[insomniac/livedata] {Title}: TOC {Path} lists {Count} file(s){Names}", title, toc.Path, files.Count,
            files.Count > 0 ? $": {string.Join(", ", files.Select(f => $"{f.Name} ({f.Data.Length}B)"))}" : "");
        return WebServiceResponse.Binary(body);
    }

    /// <summary>The files directly in the live data directory the client would take, in name order (oddities logged and left out).</summary>
    private List<LiveDataFile> Files(TocDefinition toc)
    {
        if (!System.IO.Directory.Exists(Root))
            return [];
        List<LiveDataFile> files = [];
        foreach (string path in System.IO.Directory.GetFiles(Root).Order(StringComparer.Ordinal))
        {
            LiveDataFile file = new(Path.GetFileName(path), File.ReadAllBytes(path));
            if (LiveDataToc.Check(file, toc) is { } problem)
            {
                Log.Warning("[insomniac/livedata] {Title}: {Problem}; not listed", title, problem);
                continue;
            }
            if (files.Count == toc.MaxEntries)
            {
                Log.Warning("[insomniac/livedata] {Title}: more than {Max} files; {Name} and later ones not listed", title, toc.MaxEntries, file.Name);
                break;
            }
            files.Add(file);
        }
        return files;
    }
}
