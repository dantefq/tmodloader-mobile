using System;
using System.Buffers.Binary;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace TerrariaMobile.Serialization;

// CPU-side image only. Does not create a texture or change a graphics device.
public sealed class MobileRawImage
{
    private readonly byte[] pixels;
    public int Width { get; }
    public int Height { get; }
    public int PixelByteCount => pixels.Length;
    private MobileRawImage(int width, int height, byte[] rgba)
    {
        Width = width; Height = height; pixels = rgba;
    }
    public byte[] CopyRgba() => (byte[])pixels.Clone();
    // Lossless PNG transport for a future Unity LoadImage binding. No GPU work.
    public byte[] EncodePng()
    {
        using var output = new MemoryStream();
        output.Write(new byte[] { 137, 80, 78, 71, 13, 10, 26, 10 });
        var header = new byte[13];
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(0, 4), Width);
        BinaryPrimitives.WriteInt32BigEndian(header.AsSpan(4, 4), Height);
        header[8] = 8; header[9] = 6; // RGBA8, standard compression/filter, no interlace.
        WriteChunk(output, "IHDR", header);
        using var compressed = new MemoryStream();
        using (var z = new ZLibStream(compressed, CompressionLevel.Optimal, true))
        {
            int stride = Width * 4;
            for (int row = 0; row < Height; row++)
            {
                z.WriteByte(0); // No filtering: preserve byte/channel and row order.
                z.Write(pixels, row * stride, stride);
            }
        }
        WriteChunk(output, "IDAT", compressed.ToArray());
        WriteChunk(output, "IEND", Array.Empty<byte>());
        return output.ToArray();
    }
    private static void WriteChunk(Stream output, string name, byte[] data)
    {
        var type = Encoding.ASCII.GetBytes(name);
        Span<byte> value = stackalloc byte[4];
        BinaryPrimitives.WriteInt32BigEndian(value, data.Length); output.Write(value);
        output.Write(type); output.Write(data);
        uint crc = uint.MaxValue;
        foreach (byte b in type) crc = UpdateCrc(crc, b);
        foreach (byte b in data) crc = UpdateCrc(crc, b);
        BinaryPrimitives.WriteUInt32BigEndian(value, ~crc); output.Write(value);
    }
    private static uint UpdateCrc(uint crc, byte value)
    {
        crc ^= value;
        for (int bit = 0; bit < 8; bit++) crc = (crc >> 1) ^ ((crc & 1) != 0 ? 0xedb88320u : 0);
        return crc;
    }
    internal static uint ComputePngCrc(ReadOnlySpan<byte> data)
    {
        uint crc = uint.MaxValue;
        foreach (byte b in data) crc = UpdateCrc(crc, b);
        return ~crc;
    }
    private static void ValidateLimits(int maxDimension, int maxPixelBytes)
    {
        if (maxDimension <= 0 || maxDimension > 32768 || maxPixelBytes <= 0 || maxPixelBytes > 256 * 1024 * 1024)
            throw new ArgumentOutOfRangeException("Image limits outside supported bounds");
    }
    public static MobileRawImage Decode(byte[] data, int maxDimension = 8192, int maxPixelBytes = 64 * 1024 * 1024)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        ValidateLimits(maxDimension, maxPixelBytes);
        if (data.Length < 12) throw new InvalidDataException("Truncated raw image header");
        int version = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0, 4));
        int width = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(4, 4));
        int height = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(8, 4));
        if (version != 1) throw new InvalidDataException("Unsupported raw image version");
        if (width <= 0 || height <= 0 || width > maxDimension || height > maxDimension)
            throw new InvalidDataException("Raw image dimensions outside bounds");
        long count = (long)width * height * 4;
        if (count > maxPixelBytes || count + 12 != data.LongLength)
            throw new InvalidDataException("Raw image pixel length differs or exceeds budget");
        var pixels = new byte[(int)count];
        Buffer.BlockCopy(data, 12, pixels, 0, pixels.Length);
        return new MobileRawImage(width, height, pixels);
    }

    public static MobileRawImage FromArchive(MobileTmodArchive archive, string entry,
        int maxDimension = 8192, int maxPixelBytes = 64 * 1024 * 1024)
    {
        if (archive == null) throw new ArgumentNullException(nameof(archive));
        if (entry == null || !entry.EndsWith(".rawimg", StringComparison.Ordinal))
            throw new ArgumentException("Expected an explicit rawimg archive entry", nameof(entry));
        ValidateLimits(maxDimension, maxPixelBytes);
        var bytes = archive.GetBytes(entry, Math.Min(maxPixelBytes + 12, MobileTmodArchive.MaxEntryBytes));
        if (bytes == null) throw new FileNotFoundException("Raw image archive entry missing", entry);
        return Decode(bytes, maxDimension, maxPixelBytes);
    }
}
