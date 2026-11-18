using System.Buffers.Binary;

namespace Plugin.Insomniac.Mr;

/// <summary>
/// The packet cipher of Insomniac's message router (MR) transport, applied to
/// every Universe datagram, header included.
/// </summary>
/// <remarks>
/// [C R3 1.02 encrypt 0x472bd0, decrypt 0x472cc0, pass count 0xf4dd30 (setter 0x472bc4)] A 4-byte window
/// slides over the packet one byte at a time (positions 0..len-4 on encrypt, len-4..0 on decrypt). At each
/// position the window is read little-endian and, for each pass: rotate right 6, XOR the pass key, then put
/// each byte through the S-box. Keys are the low 32 bits of 8-byte slots at 0xf4dd38, the S-box is at 0xf4dd98
/// (its inverse at 0xf4de98 is derived here). The same functions are ENet's encrypt callbacks when the
/// encryption flag (MR config +0x34) is set [C 0x8f85c0]. RE-Work/r3/tools/mrcrypt.py is the reference.
/// Keys and S-box are game data: tools/re/r3keys.py reads them from a decrypted EBOOT into the server config.
/// </remarks>
public sealed class MrCipher
{
    private readonly uint[] _keys;
    private readonly byte[] _sbox;
    private readonly byte[] _inverse = new byte[256];

    public int Passes { get; }

    public MrCipher(IReadOnlyList<uint> keys, ReadOnlySpan<byte> sbox, int passes)
    {
        if (sbox.Length != 256)
            throw new ArgumentException($"the S-box has {sbox.Length} bytes, not 256", nameof(sbox));
        if (passes < 1 || passes > keys.Count)
            throw new ArgumentException($"{passes} passes need as many keys; {keys.Count} given", nameof(passes));
        _keys = [.. keys];
        _sbox = sbox.ToArray();
        bool[] seen = new bool[256];
        for (int i = 0; i < 256; i++)
        {
            if (seen[_sbox[i]])
                throw new ArgumentException($"the S-box is not a permutation (0x{_sbox[i]:X2} twice)", nameof(sbox));
            seen[_sbox[i]] = true;
            _inverse[_sbox[i]] = (byte)i;
        }
        Passes = passes;
    }

    /// <summary>
    /// A cipher from the server config's hex strings: <paramref name="keysHex"/> = big-endian u32 keys back to
    /// back, <paramref name="sboxHex"/> = the 256 S-box bytes (the forms tools/re/r3keys.py prints).
    /// </summary>
    public static MrCipher FromHex(string keysHex, string sboxHex, int passes)
    {
        byte[] keyBytes = Convert.FromHexString(keysHex.Trim());
        if (keyBytes.Length % 4 != 0)
            throw new FormatException($"cipher keys are {keyBytes.Length} bytes, not a whole number of u32s");
        uint[] keys = new uint[keyBytes.Length / 4];
        for (int i = 0; i < keys.Length; i++)
            keys[i] = BinaryPrimitives.ReadUInt32BigEndian(keyBytes.AsSpan(i * 4));
        return new MrCipher(keys, Convert.FromHexString(sboxHex.Trim()), passes);
    }

    public void Encrypt(Span<byte> data) => Encrypt(data, Passes);

    public void Decrypt(Span<byte> data) => Decrypt(data, Passes);

    /// <summary>
    /// With a pass count of the caller's: the game sets the shared count before each use (e.g. 11 before it
    /// deciphers the live data TOC [C R3 1.05 0x46d138 -> setter 0x476274]).
    /// </summary>
    public void Encrypt(Span<byte> data, int passes)
    {
        CheckPasses(passes);
        for (int p = 0; p + 4 <= data.Length; p++)
        {
            uint w = BinaryPrimitives.ReadUInt32LittleEndian(data[p..]);
            for (int i = 0; i < passes; i++)
                w = Substitute(((w >> 6) | (w << 26)) ^ _keys[i], _sbox);
            BinaryPrimitives.WriteUInt32LittleEndian(data[p..], w);
        }
    }

    public void Decrypt(Span<byte> data, int passes)
    {
        CheckPasses(passes);
        for (int p = data.Length - 4; p >= 0; p--)
        {
            uint w = BinaryPrimitives.ReadUInt32LittleEndian(data[p..]);
            for (int i = passes - 1; i >= 0; i--)
            {
                w = Substitute(w, _inverse) ^ _keys[i];
                w = (w << 6) | (w >> 26);
            }
            BinaryPrimitives.WriteUInt32LittleEndian(data[p..], w);
        }
    }

    private void CheckPasses(int passes)
    {
        if (passes < 1 || passes > _keys.Length)
            throw new ArgumentOutOfRangeException(nameof(passes), $"{passes} passes need as many keys; there are {_keys.Length}");
    }

    private static uint Substitute(uint w, byte[] box) =>
        box[w & 0xff] | (uint)box[(w >> 8) & 0xff] << 8 | (uint)box[(w >> 16) & 0xff] << 16 | (uint)box[w >> 24] << 24;
}
