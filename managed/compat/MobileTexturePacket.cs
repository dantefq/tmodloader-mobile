using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Buffers.Binary;
using System.IO.Compression;

namespace TerrariaMobile.Serialization;

// Checked CPU transport, not a graphics handle or proof of trusted provenance.
// The receiver supplies the expected asset/archive/generation from its own load plan.
public sealed class MobileTexturePacket
{
    public const int MaxPngBytes = 128 * 1024 * 1024;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private readonly byte[] png;
    public string Asset { get; }
    public Guid Generation { get; }
    public string ArchiveSha256 { get; }
    public int Width { get; }
    public int Height { get; }
    public byte[] CopyPng() => (byte[])png.Clone();
    private MobileTexturePacket(string asset, Guid generation, string hash, int width, int height, byte[] bytes)
    { Asset = asset; Generation = generation; ArchiveSha256 = hash; Width = width; Height = height; png = bytes; }

    private static void Identity(string asset, Guid generation, string hash)
    {
        if (string.IsNullOrEmpty(asset) || Utf8.GetByteCount(asset) > 512 || !asset.Contains('/') ||
            asset.Contains('\\') || asset.Split('/').Any(p => p.Length == 0 || p is "." or "..") ||
            asset.Any(c => c < 32 || c == ':' || c == '\u007f')) throw new ArgumentException("Invalid qualified asset identity");
        if (generation == Guid.Empty || hash == null || hash.Length != 64 ||
            hash.Any(c => !(c is >= '0' and <= '9' or >= 'a' and <= 'f')))
            throw new ArgumentException("Explicit generation and lowercase SHA256 required");
    }
    public static MobileTexturePacket Create(string asset, Guid generation, string archiveSha256, MobileRawImage image)
    {
        Identity(asset, generation, archiveSha256);
        if (image == null) throw new ArgumentNullException(nameof(image));
        long rawBytes = (long)image.PixelByteCount + image.Height;
        if (rawBytes + rawBytes / 100 + 4096 > MaxPngBytes)
            throw new InvalidDataException("Image exceeds bounded PNG encoding workspace");
        byte[] bytes = image.EncodePng();
        if (bytes.Length > MaxPngBytes) throw new InvalidDataException("PNG exceeds transport budget");
        return new MobileTexturePacket(asset, generation, archiveSha256, image.Width, image.Height, bytes);
    }
    public byte[] Encode()
    {
        using var output = new MemoryStream();
        using var writer = new BinaryWriter(output, Utf8, true);
        writer.Write(new byte[] { 84, 77, 73, 84, 1 });
        var key = Utf8.GetBytes(Asset); writer.Write(key.Length); writer.Write(key);
        writer.Write(Generation.ToByteArray()); writer.Write(Convert.FromHexString(ArchiveSha256));
        writer.Write(Width); writer.Write(Height); writer.Write(png.Length);
        writer.Write(SHA256.HashData(png)); writer.Write(png);
        return output.ToArray();
    }
    public static MobileTexturePacket Decode(byte[] data, string expectedAsset, Guid expectedGeneration,
        string expectedArchiveSha256, int maxPngBytes = 16 * 1024 * 1024, int maxPixelBytes = 64 * 1024 * 1024)
    {
        Identity(expectedAsset, expectedGeneration, expectedArchiveSha256);
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (maxPngBytes <= 0 || maxPngBytes > MaxPngBytes || maxPixelBytes <= 0 || maxPixelBytes > 256 * 1024 * 1024)
            throw new ArgumentOutOfRangeException("Invalid transport budget");
        if (data.LongLength > (long)maxPngBytes + 613) throw new InvalidDataException("Texture packet exceeds budget");
        try
        {
            using var input = new MemoryStream(data, false);
            using var reader = new BinaryReader(input, Utf8);
            if (!reader.ReadBytes(5).SequenceEqual(new byte[] { 84, 77, 73, 84, 1 })) throw new InvalidDataException("Unsupported texture packet");
            int length = reader.ReadInt32();
            if (length < 1 || length > 512 || length > input.Length - input.Position) throw new InvalidDataException("Invalid asset key length");
            string asset = Utf8.GetString(reader.ReadBytes(length));
            var generation = new Guid(Read(reader, 16));
            string hash = Convert.ToHexString(Read(reader, 32)).ToLowerInvariant();
            if (asset != expectedAsset || generation != expectedGeneration || hash != expectedArchiveSha256)
                throw new InvalidDataException("Texture belongs to another asset, archive or generation");
            int width = reader.ReadInt32(), height = reader.ReadInt32(), count = reader.ReadInt32();
            if (width <= 0 || height <= 0 || width > 32768 || height > 32768 || (long)width * height * 4 > maxPixelBytes)
                throw new InvalidDataException("Texture pixel dimensions exceed budget");
            var digest = Read(reader, 32);
            if (count < 33 || count > maxPngBytes || count != input.Length - input.Position)
                throw new InvalidDataException("Texture PNG length differs or exceeds budget");
            var png = Read(reader, count);
            if (!CryptographicOperations.FixedTimeEquals(digest, SHA256.HashData(png))) throw new InvalidDataException("PNG checksum differs");
            if (!png.AsSpan(0, 8).SequenceEqual(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 }) ||
                BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(8, 4)) != 13 ||
                !png.AsSpan(12, 4).SequenceEqual(new byte[] { 73, 72, 68, 82 }) ||
                BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(16, 4)) != width ||
                BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(20, 4)) != height ||
                !png.AsSpan(24, 5).SequenceEqual(new byte[] { 8, 6, 0, 0, 0 }))
                throw new InvalidDataException("PNG header differs from packet dimensions/format");
            ValidatePngPayload(png, width, height);
            return new MobileTexturePacket(asset, generation, hash, width, height, png);
        }
        catch (EndOfStreamException e) { throw new InvalidDataException("Truncated texture packet", e); }
        catch (DecoderFallbackException e) { throw new InvalidDataException("Invalid asset key UTF8", e); }
    }
    private static byte[] Read(BinaryReader reader, int count)
    { var result = reader.ReadBytes(count); if (result.Length != count) throw new EndOfStreamException(); return result; }
    private static void ValidatePngPayload(byte[] png, int width, int height)
    {
        // The sender's own profile is IHDR/one IDAT/IEND, RGBA8, row filter 0.
        int offset = 8, compressedOffset = 0, compressedCount = 0;
        foreach (string expected in new[] { "IHDR", "IDAT", "IEND" })
        {
            if (png.Length - offset < 12) throw new InvalidDataException("Truncated PNG chunk");
            int count = BinaryPrimitives.ReadInt32BigEndian(png.AsSpan(offset, 4));
            if (count < 0 || count > png.Length - offset - 12 ||
                Encoding.ASCII.GetString(png, offset + 4, 4) != expected)
                throw new InvalidDataException("PNG chunk differs from transport profile");
            if (BinaryPrimitives.ReadUInt32BigEndian(png.AsSpan(offset + 8 + count, 4)) !=
                MobileRawImage.ComputePngCrc(png.AsSpan(offset + 4, count + 4)))
                throw new InvalidDataException("PNG chunk CRC differs");
            if (expected == "IDAT") { compressedOffset = offset + 8; compressedCount = count; }
            if (expected == "IEND" && count != 0) throw new InvalidDataException("PNG end chunk is not empty");
            offset += count + 12;
        }
        if (offset != png.Length) throw new InvalidDataException("PNG has trailing data");
        using var compressed = new MemoryStream(png, compressedOffset, compressedCount, false);
        using var decoder = new ZLibStream(compressed, CompressionMode.Decompress);
        var row = new byte[checked(width * 4 + 1)];
        for (int i = 0; i < height; i++)
        {
            decoder.ReadExactly(row);
            if (row[0] != 0) throw new InvalidDataException("PNG row filter differs from transport profile");
        }
        if (decoder.ReadByte() != -1) throw new InvalidDataException("PNG expands beyond declared rows");
    }
}
