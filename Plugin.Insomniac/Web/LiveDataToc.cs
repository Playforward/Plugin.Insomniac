using Plugin.Insomniac.Mr;
using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace Plugin.Insomniac.Web;

/// <summary>One file the live data TOC lists.</summary>
public sealed record LiveDataFile(string Name, byte[] Data);

/// <summary>
/// The live data table of contents (<c>toc.bin</c>) as LiveDataMgr reads it [C R3 1.05 parser 0x46d138, file
/// requests 0x46d830, download check in the state machine 0x46ecd0].
/// </summary>
/// <remarks>
/// <para>The client sets the shared MR cipher to <see cref="TocDefinition.CipherPasses"/> passes (11) and deciphers the
/// whole body (0x476370, the Universe cipher), then wants, big-endian:</para>
/// <code>
///  0  u32  length       the body's length
///  4  u16  passes       the shared MR cipher pass count from now on (0x476274): Universe, ENet and live data files
///  6  u16  count        entries; (length - 16) / 0x28 exactly, at most 64
///  8  u64  checksum     passes + the sum of each entry's five u64 words, entries whose name contains ".txt" left out
/// 16  entries, 0x28 bytes each:
///      0  char[20]  name (NUL-padded; the file is fetched at base URI + name)
///     20  u32       size (under 0x10000)
///     24  u8[16]    MD5 of the file as served (0xb7f6f0: MD5 init constants 0xb7f2b0)
/// </code>
/// <para>A downloaded file is kept when its size and MD5 match its entry; an entry equal to a cached file's skips the
/// download. Error states (0x15) show a "%s (%u.%u-%u.%u.%u)" dialog and tell the loading screen live data failed.
/// What the game does with the files (".ldbc", "precompiled configs") and whether they are enciphered is not known
/// yet; files are served as they are.</para>
/// </remarks>
public static class LiveDataToc
{
    public const int HeaderSize = 16;
    public const int EntrySize = 0x28;
    public const int NameSize = 20;
    private static readonly byte[] UnsummedName = ".txt"u8.ToArray();

    /// <summary>The TOC for <paramref name="files"/> (checked with <see cref="Check"/> first), enciphered when <paramref name="cipher"/> is given.</summary>
    public static byte[] Build(IReadOnlyList<LiveDataFile> files, TocDefinition toc, ushort sharedPasses, MrCipher? cipher)
    {
        if (files.Count > toc.MaxEntries)
            throw new ArgumentException($"{files.Count} files; the client takes at most {toc.MaxEntries}");
        byte[] body = new byte[HeaderSize + EntrySize * files.Count];
        ulong checksum = sharedPasses;
        for (int i = 0; i < files.Count; i++)
        {
            if (Check(files[i], toc) is { } problem)
                throw new ArgumentException(problem);
            Span<byte> entry = body.AsSpan(HeaderSize + EntrySize * i, EntrySize);
            Encoding.ASCII.GetBytes(files[i].Name, entry[..NameSize]);
            BinaryPrimitives.WriteUInt32BigEndian(entry[NameSize..], (uint)files[i].Data.Length);
            MD5.HashData(files[i].Data, entry[(NameSize + 4)..]);
            if (entry[..NameSize].IndexOf(UnsummedName) < 0)
                for (int word = 0; word < EntrySize / 8; word++)
                    checksum += BinaryPrimitives.ReadUInt64BigEndian(entry[(word * 8)..]);
        }
        BinaryPrimitives.WriteUInt32BigEndian(body, (uint)body.Length);
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(4), sharedPasses);
        BinaryPrimitives.WriteUInt16BigEndian(body.AsSpan(6), (ushort)files.Count);
        BinaryPrimitives.WriteUInt64BigEndian(body.AsSpan(8), checksum);
        cipher?.Encrypt(body, toc.CipherPasses);
        return body;
    }

    /// <summary>Why the client would not take this file, or null.</summary>
    public static string? Check(LiveDataFile file, TocDefinition toc)
    {
        if (file.Name.Length == 0 || file.Name.Length >= NameSize || file.Name.Any(c => c < 0x21 || c > 0x7e))
            return $"\"{file.Name}\": a name is 1-{NameSize - 1} printable ASCII characters (the entry holds {NameSize} bytes with its NUL)";
        if (file.Data.Length > toc.MaxFileSize)
            return $"\"{file.Name}\": {file.Data.Length} bytes; the client refuses files over {toc.MaxFileSize}";
        return null;
    }
}
