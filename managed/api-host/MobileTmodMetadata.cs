using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using TerrariaMobile.Serialization;

namespace TerrariaMobile.Managed;

// Host inspection only. Hashes the stored archive, reads its table and expands
// only Info. This never grants the runtime permission to load large resources.
public sealed record MobileTmodMetadata(MobileModManifest Manifest, string Sha256,
    Version TModLoaderVersion, long DeclaredExpandedBytes, long StoredBytes)
{
    public bool PayloadSha1Verified => true;
    public bool SignatureAuthenticated => false;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static string Text(BinaryReader reader)
    {
        int size = reader.Read7BitEncodedInt();
        if (size < 0 || size > 4096 || size > reader.BaseStream.Length - reader.BaseStream.Position)
            throw new InvalidDataException("Invalid metadata string size");
        return Utf8.GetString(reader.ReadBytes(size));
    }
    public static MobileTmodMetadata FromFile(string path)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        if (input.Length > MobileTmodArchive.MaxArchiveBytes) throw new InvalidDataException("TMOD archive exceeds limit");
        string sha256 = Convert.ToHexString(SHA256.HashData(input)).ToLowerInvariant();
        input.Position = 0;
        using var reader = new BinaryReader(input, Utf8, true);
        try
        {
            if (!reader.ReadBytes(4).SequenceEqual(new byte[] { 84, 77, 79, 68 })) throw new InvalidDataException("Not a TMOD");
            if (!Version.TryParse(Text(reader), out var loader) || loader < new Version(0, 11))
                throw new NotSupportedException("Legacy TMOD table compression is not supported");
            byte[] digest = reader.ReadBytes(20);
            if (reader.ReadBytes(256).Length != 256) throw new InvalidDataException("Truncated TMOD signature");
            int payloadLength = reader.ReadInt32();
            long payloadStart = input.Position;
            if (payloadLength < 0 || payloadLength != input.Length - payloadStart) throw new InvalidDataException("TMOD payload length mismatch");
            if (!CryptographicOperations.FixedTimeEquals(digest, SHA1.HashData(input))) throw new InvalidDataException("TMOD payload SHA1 mismatch");
            input.Position = payloadStart;
            string name = Text(reader);
            if (string.IsNullOrWhiteSpace(name) || name.Contains('/') || name.Contains('\\')) throw new InvalidDataException("Invalid mod identity");
            if (!Version.TryParse(Text(reader), out var version)) throw new InvalidDataException("Invalid mod version");
            int count = reader.ReadInt32();
            if (count < 0 || count > MobileTmodArchive.MaxEntries) throw new InvalidDataException("Invalid TMOD entry count");
            var unique = new HashSet<string>(StringComparer.Ordinal);
            long expanded = 0, stored = 0, infoOffset = -1;
            int infoLength = 0, infoStored = 0;
            for (int i = 0; i < count; i++)
            {
                string entry = Text(reader).Replace('\\', '/');
                if (string.IsNullOrEmpty(entry) || entry.StartsWith('/') || entry.Split('/').Any(p => p.Length == 0 || p == "." || p == "..") ||
                    entry.Any(c => c < 32 || c == ':') || !unique.Add(entry)) throw new InvalidDataException("Invalid or duplicate TMOD entry name");
                int length = reader.ReadInt32(), size = reader.ReadInt32();
                if (length < 0 || size < 0 || length > MobileTmodArchive.MaxEntryBytes || size > MobileTmodArchive.MaxEntryBytes)
                    throw new InvalidDataException("Invalid TMOD entry size");
                if (entry == "Info")
                {
                    if (length > MobileModManifest.MaxInfoBytes || size > MobileModManifest.MaxInfoBytes)
                        throw new InvalidDataException("Info exceeds limit");
                    infoOffset = stored; infoLength = length; infoStored = size;
                }
                expanded += length; stored += size;
                if (stored > MobileTmodArchive.MaxArchiveBytes) throw new InvalidDataException("TMOD stored size exceeds limit");
            }
            if (stored != input.Length - input.Position) throw new InvalidDataException("TMOD entry coverage mismatch");
            if (infoOffset < 0) throw new InvalidDataException("TMOD Info entry missing");
            input.Position += infoOffset;
            byte[] bytes = reader.ReadBytes(infoStored);
            if (bytes.Length != infoStored) throw new InvalidDataException("Truncated Info");
            if (infoLength != infoStored)
            {
                using var compressed = new MemoryStream(bytes, false);
                using var deflate = new DeflateStream(compressed, CompressionMode.Decompress);
                bytes = new byte[infoLength]; deflate.ReadExactly(bytes);
                if (deflate.ReadByte() != -1) throw new InvalidDataException("Info exceeds declared size");
            }
            return new(MobileModManifest.FromInfo(name, version, bytes, loader), sha256, loader, expanded, stored);
        }
        catch (EndOfStreamException error) { throw new InvalidDataException("Truncated TMOD metadata", error); }
        catch (DecoderFallbackException error) { throw new InvalidDataException("Invalid TMOD metadata UTF8", error); }
        catch (FormatException error) { throw new InvalidDataException("Invalid TMOD metadata string prefix", error); }
    }
}
