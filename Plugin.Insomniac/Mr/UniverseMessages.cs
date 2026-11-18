using System.Buffers.Binary;
using System.Net;
using System.Text;

namespace Plugin.Insomniac.Mr;

/// <summary>
/// Universe message bodies. Each message is a fixed-size record: byte 0 a class (1 on what the client sends, 2 on the
/// network-thread records it reads), byte 1 the id, then big-endian fields at fixed offsets, read by accessors that
/// check the message is long enough for the field [C R3 1.05 writer inits zero-fill the size, e.g. 0x904b08 (0x26),
/// 0x9047c4 (0x21), 0x8ff9d4 (0x11)]. Offsets come from title.json (<see cref="MatchmakingDefinition"/>).
/// </summary>
public static class UniverseMessages
{
    public static ushort U16(ReadOnlySpan<byte> m, int offset) => m.Length >= offset + 2 ? BinaryPrimitives.ReadUInt16BigEndian(m[offset..]) : (ushort)0;
    public static byte U8(ReadOnlySpan<byte> m, int offset) => m.Length > offset ? m[offset] : (byte)0;

    /// <summary>An IPv4 address as the client keeps it (network order in a big-endian u32).</summary>
    public static uint Ipv4(IPAddress address)
    {
        byte[] bytes = address.MapToIPv4().GetAddressBytes();
        return BinaryPrimitives.ReadUInt32BigEndian(bytes);
    }

    /// <summary>
    /// Message 0x23 [C 1.05 handler 0x8faa94]: u16 session id @2 (0 = quick-match results are complete), u32 count @4,
    /// u32 IPv4 @8, u16 port @0x0c. With a session id the client ENet-connects that session to the address; with 0 it
    /// tells the lobby the result count and the address to host on.
    /// </summary>
    public static byte[] Introduction(IntroductionLayout layout, ushort sessionId, uint count, uint ipv4, ushort port)
    {
        byte[] m = New(layout.Size, layout.Class, layout.Id);
        BinaryPrimitives.WriteUInt16BigEndian(m.AsSpan(layout.SessionIdAt), sessionId);
        BinaryPrimitives.WriteUInt32BigEndian(m.AsSpan(layout.CountAt), count);
        BinaryPrimitives.WriteUInt32BigEndian(m.AsSpan(layout.AddressAt), ipv4);
        BinaryPrimitives.WriteUInt16BigEndian(m.AsSpan(layout.PortAt), port);
        return m;
    }

    /// <summary>
    /// Message 0x11, one quick-match candidate [C 1.05 handler 0x8f95a8, getters 0x8fe35c/0x8feb04/0x8ffa24/0x8fedb8/
    /// 0x8ffa8c/0x8ffb18/0x8ffc2c/0x8ffce8..0x8fff18, strings 0x8fff88/0x9000f4]. The lobby (0x3caa2c) takes
    /// address, port and key as the candidate when the mode byte is above 8 and (mode - 9) is what it searches for
    /// (0 = any); a key of 0xffff is refused.
    /// </summary>
    public static byte[] Record(RecordLayout layout, CandidateRecord record)
    {
        byte[] first = Encoding.UTF8.GetBytes(record.FirstName);
        byte[] second = Encoding.UTF8.GetBytes(record.SecondName);
        if (first.Length > 0xff || second.Length > 0xff)
            throw new ArgumentException("record strings are at most 255 bytes (u8 length)");
        byte[] m = New(Math.Max(layout.Size, layout.StringsAt + 2 + first.Length + second.Length), layout.Class, layout.Id);
        Span<byte> s = m;
        BinaryPrimitives.WriteUInt64BigEndian(s[layout.IdentityAt..], record.Identity);
        BinaryPrimitives.WriteUInt32BigEndian(s[layout.Word0At..], record.Word0);
        BinaryPrimitives.WriteUInt32BigEndian(s[layout.AddressAt..], record.Ipv4);
        BinaryPrimitives.WriteUInt16BigEndian(s[layout.PortAt..], record.Port);
        BinaryPrimitives.WriteUInt16BigEndian(s[layout.KeyAt..], record.Key);
        BinaryPrimitives.WriteUInt32BigEndian(s[layout.Word1At..], record.Word1);
        BinaryPrimitives.WriteUInt16BigEndian(s[layout.Short0At..], record.Short0);
        record.Bytes.AsSpan(0, Math.Min(record.Bytes.Length, layout.ByteCount)).CopyTo(s[layout.BytesAt..]);
        s[layout.BytesAt + layout.ModeByte] = record.Mode;
        int p = layout.StringsAt;
        s[p++] = (byte)first.Length;
        first.CopyTo(s[p..]);
        p += first.Length;
        s[p++] = (byte)second.Length;
        second.CopyTo(s[p..]);
        return m;
    }

    private static byte[] New(int size, byte cls, byte id)
    {
        byte[] m = new byte[size];
        m[0] = cls;
        m[1] = id;
        return m;
    }
}

/// <summary>What one 0x11 record says (field meanings beyond address, port, key and mode are not known yet).</summary>
public sealed class CandidateRecord
{
    public ulong Identity { get; init; }
    public uint Word0 { get; init; }
    public uint Ipv4 { get; init; }
    public ushort Port { get; init; }
    public ushort Key { get; init; }
    public uint Word1 { get; init; }
    public ushort Short0 { get; init; }
    /// <summary>The u8 block (record +0x30..+0x35); <see cref="Mode"/> overwrites its mode byte.</summary>
    public byte[] Bytes { get; init; } = [];
    public byte Mode { get; init; }
    public string FirstName { get; init; } = "";
    public string SecondName { get; init; } = "";
}
