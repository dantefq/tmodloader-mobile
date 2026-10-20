using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace TerrariaMobile.Serialization;

// Bounded modern TMOD data reader. Never extracts files or loads an assembly.
public sealed class MobileTmodArchive
{
    public const int MaxArchiveBytes = 512 * 1024 * 1024;
    public const int MaxEntryBytes = 128 * 1024 * 1024;
    public const int MaxEntries = 100000;
    public string Name { get; }
    public Version Version { get; }
    public Version TModLoaderVersion { get; }
    public int Count => entries.Count;
    public string Sha256 { get; }
    public bool PayloadSha1Verified => true;
    public bool SignatureAuthenticated => false;
    private readonly byte[] data;
    private readonly Dictionary<string, Entry> entries = new(StringComparer.Ordinal);
    private readonly List<string> names = new();
    private readonly record struct Entry(int Offset, int Length, int Stored);
    private static readonly UTF8Encoding Utf8 = new(false, true);

    private static string Text(BinaryReader reader)
    {
        int length = reader.Read7BitEncodedInt();
        if (length < 0 || length > 4096 || length > reader.BaseStream.Length - reader.BaseStream.Position)
            throw new InvalidDataException("Invalid TMOD string size");
        var bytes = reader.ReadBytes(length);
        if (bytes.Length != length) throw new InvalidDataException("Truncated TMOD string");
        return Utf8.GetString(bytes);
    }
    private static string Normalize(string name)
    {
        if (string.IsNullOrEmpty(name)) throw new ArgumentException("Empty resource name");
        var normalized = name.Replace('\\', '/');
        if (normalized.StartsWith('/') || normalized.Split('/').Any(p => p.Length == 0 || p == "." || p == "..") ||
            normalized.Any(c => c < 32 || c == ':')) throw new ArgumentException("Resource name must be relative and canonical");
        return normalized;
    }
    private MobileTmodArchive(byte[] ownedData, byte[] expectedSha256)
    {
        data = ownedData;
        if (data.Length > MaxArchiveBytes) throw new InvalidDataException("TMOD archive exceeds limit");
        var sha256 = SHA256.HashData(data);
        Sha256 = Convert.ToHexString(sha256).ToLowerInvariant();
        if (expectedSha256 != null && (expectedSha256.Length != 32 ||
            !CryptographicOperations.FixedTimeEquals(sha256, expectedSha256)))
            throw new InvalidDataException("TMOD SHA256 differs from expected artifact");
        try
        {
            using var stream = new MemoryStream(data, false);
            using var reader = new BinaryReader(stream, Utf8, true);
            if (!reader.ReadBytes(4).SequenceEqual(new byte[] { 84, 77, 79, 68 })) throw new InvalidDataException("Not a TMOD");
            if (!System.Version.TryParse(Text(reader), out var loader) || loader < new Version(0, 11))
                throw new NotSupportedException("Legacy TMOD table compression is not supported");
            TModLoaderVersion = loader;
            var digest = reader.ReadBytes(20);
            if (reader.ReadBytes(256).Length != 256) throw new InvalidDataException("Truncated TMOD signature");
            int payloadLength = reader.ReadInt32();
            if (payloadLength < 0 || payloadLength != stream.Length - stream.Position)
                throw new InvalidDataException("TMOD payload length mismatch");
            if (!CryptographicOperations.FixedTimeEquals(digest, SHA1.HashData(data.AsSpan((int)stream.Position, payloadLength))))
                throw new InvalidDataException("TMOD payload SHA1 mismatch");
            Name = Text(reader);
            if (string.IsNullOrWhiteSpace(Name) || Name.Contains('/') || Name.Contains('\\'))
                throw new InvalidDataException("Invalid mod identity");
            if (!System.Version.TryParse(Text(reader), out var version)) throw new InvalidDataException("Invalid mod version");
            Version = version;
            int count = reader.ReadInt32();
            if (count < 0 || count > MaxEntries) throw new InvalidDataException("Invalid TMOD entry count");
            var table = new List<(string name, int length, int stored)>();
            var unique = new HashSet<string>(StringComparer.Ordinal);
            long expandedTotal = 0, storedTotal = 0;
            for (int i = 0; i < count; i++)
            {
                string name = Normalize(Text(reader));
                if (!unique.Add(name)) throw new InvalidDataException("Duplicate normalized TMOD entry");
                int length = reader.ReadInt32(), stored = reader.ReadInt32();
                if (length < 0 || stored < 0 || length > MaxEntryBytes || stored > MaxEntryBytes)
                    throw new InvalidDataException("Invalid TMOD entry size");
                expandedTotal += length; storedTotal += stored;
                if (expandedTotal > MaxArchiveBytes || storedTotal > MaxArchiveBytes)
                    throw new InvalidDataException("TMOD cumulative size exceeds limit");
                table.Add((name, length, stored));
            }
            if (storedTotal != stream.Length - stream.Position) throw new InvalidDataException("TMOD entry coverage mismatch");
            int position = (int)stream.Position;
            foreach (var row in table)
            {
                entries.Add(row.name, new Entry(position, row.length, row.stored)); names.Add(row.name);
                position = checked(position + row.stored);
            }
        }
        catch (EndOfStreamException error) { throw new InvalidDataException("Truncated TMOD", error); }
        catch (DecoderFallbackException error) { throw new InvalidDataException("Invalid TMOD UTF8", error); }
        catch (FormatException error) { throw new InvalidDataException("Invalid TMOD string prefix", error); }
        catch (ArgumentException error) { throw new InvalidDataException("Invalid TMOD declaration", error); }
    }
    public static MobileTmodArchive FromBytes(byte[] data, byte[] expectedSha256 = null)
    {
        if (data == null) throw new ArgumentNullException(nameof(data));
        if (data.Length > MaxArchiveBytes) throw new InvalidDataException("TMOD archive exceeds limit");
        return new MobileTmodArchive((byte[])data.Clone(), expectedSha256);
    }
    public static MobileTmodArchive FromFile(string path, byte[] expectedSha256 = null)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length > MaxArchiveBytes) throw new InvalidDataException("TMOD archive exceeds limit");
        var bytes = new byte[checked((int)input.Length)]; input.ReadExactly(bytes);
        return new MobileTmodArchive(bytes, expectedSha256);
    }
    public List<string> GetFileNames() => new(names);
    public int? GetEntryLength(string name) => entries.TryGetValue(Normalize(name), out var entry) ? entry.Length : null;
    public bool HasFile(string name) => entries.ContainsKey(Normalize(name));
    public byte[] GetBytes(string name)
        => GetBytes(name, MaxEntryBytes);
    public byte[] GetBytes(string name, int maxExpandedBytes)
    {
        if (maxExpandedBytes < 0 || maxExpandedBytes > MaxEntryBytes)
            throw new ArgumentOutOfRangeException(nameof(maxExpandedBytes));
        if (!entries.TryGetValue(Normalize(name), out var entry)) return null;
        if (entry.Length > maxExpandedBytes) throw new InvalidDataException("TMOD resource exceeds caller budget");
        var result = new byte[entry.Length];
        if (entry.Length == entry.Stored) Array.Copy(data, entry.Offset, result, 0, entry.Length);
        else
        {
            using var stored = new MemoryStream(data, entry.Offset, entry.Stored, false);
            using var expanded = new DeflateStream(stored, CompressionMode.Decompress);
            try { expanded.ReadExactly(result); }
            catch (EndOfStreamException error) { throw new InvalidDataException("Truncated compressed TMOD resource", error); }
            if (expanded.ReadByte() != -1) throw new InvalidDataException("TMOD expanded resource exceeds declared size");
        }
        return result;
    }
    public Stream GetStream(string name)
    {
        var bytes = GetBytes(name); return bytes == null ? null : new MemoryStream(bytes, false);
    }
}
