using System.Buffers.Binary;

namespace Plugin.Insomniac.Mr;

/// <summary>Bits of <see cref="MrPacket.Flags"/>.</summary>
[Flags]
public enum MrFlags : byte
{
    None = 0,

    /// <summary>
    /// Sequenced: the receiver checks <see cref="MrPacket.Sequence"/> [C R3 1.02 0x4736dc]. Clear = unreliable,
    /// delivered as it comes (0x473244 clears it).
    /// </summary>
    Sequenced = 0x01,

    /// <summary>
    /// Set with <see cref="Sequenced"/> on the client's reliable sends (0x473044 ORs in 3, sequence 0). On a packet
    /// to the client, Sequenced|Request is delivered when its sequence is the next one, without an ack (0x473760).
    /// </summary>
    Request = 0x02,

    /// <summary>
    /// An acknowledgement of the packet with this <see cref="MrPacket.Sequence"/>. Alone (no payload) it is a plain
    /// ack; with Sequenced|Request and a payload it is an answer that also acks the client's pending send (0x473730).
    /// </summary>
    Ack = 0x04,

    /// <summary>The client drops any packet with one of these set [C 0x4734c4 tests flags &amp; 0x38].</summary>
    Rejected = 0x38,
}

/// <summary>
/// One Universe datagram of Insomniac's message router (MR) transport: a 16-byte header, then the message.
/// The whole datagram is enciphered with <see cref="MrCipher"/>.
/// </summary>
/// <remarks>
/// Layout [C R3 1.02 send 0x473044/0x473244, ack 0x4738dc, receive 0x4734c4]; multi-byte fields are big-endian:
/// <code>
///  0  u16  Sequence    reliable sends from the client carry 0; acks and server pushes carry the sequence
///  2  u8   Flags       MrFlags
///  3  u8   Salt        rand() per packet (0xb80380), so equal messages encipher differently
///  4  u8   Magic0      'i'
///  5  u8   Magic1      '1'
///  6  u8   Version     1 (the client drops other values on data packets)
///  7  u8×4 HeaderId    per title, 0x473e1c(0x69, 0x0e, 0x96, 0x0a) on R3 [C 0x3bf88c]; checked by the client
/// 11  u8×5 Reserved    zero on data packets
/// 16  ...  Payload     the message; payload[1] is its id [C 0x902d18]
/// </code>
/// The client's own acks fill only bytes 0..5: its bytes 6..15 are whatever the stack held, so they are not
/// checked on a payload-less ack. The receive buffer is 0x290 bytes, so a datagram is at most 656 bytes.
/// </remarks>
public sealed class MrPacket
{
    public const int HeaderSize = 16;
    public const byte Magic0 = (byte)'i';
    public const byte Magic1 = (byte)'1';

    public ushort Sequence { get; set; }
    public MrFlags Flags { get; set; }
    public byte Salt { get; set; }
    public byte FirstMagic { get; set; } = Magic0;
    public byte SecondMagic { get; set; } = Magic1;
    public byte Version { get; set; }
    public byte[] HeaderId { get; set; } = new byte[4];
    public byte[] Reserved { get; set; } = new byte[5];
    public byte[] Payload { get; set; } = [];

    public bool HasMagic => FirstMagic == Magic0 && SecondMagic == Magic1;

    /// <summary>A payload-less ack (the only packet whose bytes 6..15 mean nothing).</summary>
    public bool IsPlainAck => (Flags & MrFlags.Ack) != 0 && Payload.Length == 0;

    /// <summary>The message id (payload[1]), or null when the payload is shorter than two bytes.</summary>
    public byte? MessageId => Payload.Length > 1 ? Payload[1] : null;

    /// <summary>Reads a deciphered datagram; null when it is shorter than the header.</summary>
    public static MrPacket? Parse(ReadOnlySpan<byte> plain)
    {
        if (plain.Length < HeaderSize)
            return null;
        return new MrPacket
        {
            Sequence = BinaryPrimitives.ReadUInt16BigEndian(plain),
            Flags = (MrFlags)plain[2],
            Salt = plain[3],
            FirstMagic = plain[4],
            SecondMagic = plain[5],
            Version = plain[6],
            HeaderId = plain[7..11].ToArray(),
            Reserved = plain[11..16].ToArray(),
            Payload = plain[HeaderSize..].ToArray(),
        };
    }

    /// <summary>The datagram before enciphering.</summary>
    public byte[] Serialize()
    {
        if (HeaderId.Length != 4 || Reserved.Length != 5)
            throw new InvalidOperationException("an MR header id is 4 bytes and its reserved field 5");
        byte[] bytes = new byte[HeaderSize + Payload.Length];
        BinaryPrimitives.WriteUInt16BigEndian(bytes, Sequence);
        bytes[2] = (byte)Flags;
        bytes[3] = Salt;
        bytes[4] = FirstMagic;
        bytes[5] = SecondMagic;
        bytes[6] = Version;
        HeaderId.CopyTo(bytes, 7);
        Reserved.CopyTo(bytes, 11);
        Payload.CopyTo(bytes, HeaderSize);
        return bytes;
    }

    public override string ToString() =>
        $"seq {Sequence} flags {Flags} ({(byte)Flags:X2}){(MessageId is { } id ? $" message 0x{id:X2}" : "")} {Payload.Length}B";
}
