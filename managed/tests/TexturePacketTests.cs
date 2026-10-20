using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using TerrariaMobile.Serialization;

static class TexturePacketTests
{
    static int checks;
    static readonly string Archive = new('a', 64);
    static readonly Guid Generation = Guid.Parse("13fb5666-8cf1-4941-acf8-8d54eff30d10");
    const string Key = "Example/Images/Icon.rawimg";
    static void Check(bool value) { if (!value) throw new Exception("Texture packet contract differs"); checks++; }
    static void Reject(Action action)
    {
        try { action(); } catch (InvalidDataException) { checks++; return; }
        throw new Exception("Invalid texture packet accepted");
    }
    public static void Run()
    {
        var raw = new byte[20];
        BinaryPrimitives.WriteInt32LittleEndian(raw, 1);
        BinaryPrimitives.WriteInt32LittleEndian(raw.AsSpan(4), 2);
        BinaryPrimitives.WriteInt32LittleEndian(raw.AsSpan(8), 1);
        new byte[] { 1, 2, 3, 255, 4, 5, 6, 127 }.CopyTo(raw, 12);
        var packet = MobileTexturePacket.Create(Key, Generation, Archive, MobileRawImage.Decode(raw));
        byte[] bytes = packet.Encode();
        var read = MobileTexturePacket.Decode(bytes, Key, Generation, Archive);
        Check(read.Asset == Key && read.Generation == Generation && read.Width == 2 && read.Height == 1);
        Check(Convert.ToHexString(read.CopyPng()) == Convert.ToHexString(packet.CopyPng()));
        var copy = read.CopyPng(); copy[0] = 0; Check(read.CopyPng()[0] == 137);
        Reject(() => MobileTexturePacket.Decode(bytes, "Other/Images/Icon.rawimg", Generation, Archive));
        Reject(() => MobileTexturePacket.Decode(bytes, Key, Guid.NewGuid(), Archive));
        Reject(() => MobileTexturePacket.Decode(bytes, Key, Generation, new string('b', 64)));
        Reject(() => MobileTexturePacket.Decode(bytes, Key, Generation, Archive, maxPngBytes: 1));
        Reject(() => MobileTexturePacket.Decode(bytes, Key, Generation, Archive, maxPixelBytes: 7));
        foreach (int length in new[] { 0, 4, 8, 9, bytes.Length - 1 })
            Reject(() => MobileTexturePacket.Decode(bytes.AsSpan(0, length).ToArray(), Key, Generation, Archive));
        var extra = new byte[bytes.Length + 1]; bytes.CopyTo(extra, 0);
        Reject(() => MobileTexturePacket.Decode(extra, Key, Generation, Archive));
        var bad = (byte[])bytes.Clone(); bad[4] = 2;
        Reject(() => MobileTexturePacket.Decode(bad, Key, Generation, Archive));
        byte[] WithPng(byte[] replacement)
        {
            int start = bytes.Length - packet.CopyPng().Length;
            var frame = new byte[start + replacement.Length]; bytes.AsSpan(0, start).CopyTo(frame);
            BinaryPrimitives.WriteInt32LittleEndian(frame.AsSpan(start - 36, 4), replacement.Length);
            SHA256.HashData(replacement).CopyTo(frame.AsSpan(start - 32, 32));
            replacement.CopyTo(frame, start); return frame;
        }
        Reject(() => MobileTexturePacket.Decode(WithPng(packet.CopyPng().AsSpan(0, 33).ToArray()), Key, Generation, Archive));
        var badCrc = packet.CopyPng(); badCrc[32] ^= 1;
        Reject(() => MobileTexturePacket.Decode(WithPng(badCrc), Key, Generation, Archive));
        var largerRaw = new byte[24];
        BinaryPrimitives.WriteInt32LittleEndian(largerRaw, 1);
        BinaryPrimitives.WriteInt32LittleEndian(largerRaw.AsSpan(4), 3);
        BinaryPrimitives.WriteInt32LittleEndian(largerRaw.AsSpan(8), 1);
        var tooManyPixels = MobileRawImage.Decode(largerRaw).EncodePng();
        BinaryPrimitives.WriteInt32BigEndian(tooManyPixels.AsSpan(16, 4), 2);
        BinaryPrimitives.WriteUInt32BigEndian(tooManyPixels.AsSpan(29, 4), MobileRawImage.ComputePngCrc(tooManyPixels.AsSpan(12, 17)));
        Reject(() => MobileTexturePacket.Decode(WithPng(tooManyPixels), Key, Generation, Archive));
        bad = (byte[])bytes.Clone(); bad[9] = 255;
        Reject(() => MobileTexturePacket.Decode(bad, Key, Generation, Archive));
        bad = (byte[])bytes.Clone(); BinaryPrimitives.WriteInt32LittleEndian(bad.AsSpan(5), -1);
        Reject(() => MobileTexturePacket.Decode(bad, Key, Generation, Archive));
        bad = (byte[])bytes.Clone(); BinaryPrimitives.WriteInt32LittleEndian(bad.AsSpan(5), int.MaxValue);
        Reject(() => MobileTexturePacket.Decode(bad, Key, Generation, Archive));
        bad = (byte[])bytes.Clone(); bad[^1] ^= 1;
        Reject(() => MobileTexturePacket.Decode(bad, Key, Generation, Archive));
        // A self-consistent checksum cannot conceal a mismatched PNG header.
        bad = (byte[])bytes.Clone(); int pngStart = bytes.Length - packet.CopyPng().Length;
        bad[pngStart + 19] ^= 1;
        SHA256.HashData(bad.AsSpan(pngStart)).CopyTo(bad.AsSpan(pngStart - 32, 32));
        Reject(() => MobileTexturePacket.Decode(bad, Key, Generation, Archive));
        Check(packet.Encode().Length == bytes.Length && packet.CopyPng()[0] == 137);
        Console.WriteLine("PASS " + checks + " texture packet identity/generation/checksum/bounds checks; no GPU");
    }
}
