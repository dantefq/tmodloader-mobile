using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Terraria.ModLoader.IO;

namespace TerrariaMobile.Serialization;

// Own bounded format, not tModLoader NBT/TagIO. Never deserializes CLR type names.
public static class MobileTagCodec
{
    public const int MaxPayloadBytes = 4 * 1024 * 1024;
    public const int MaxDepth = 32;
    public const int MaxCollection = 16384;
    public const int MaxNodes = 100000;
    private const int HeaderBytes = 41;
    private static readonly UTF8Encoding Utf8 = new(false, true);
    private static readonly byte[] Magic = { 84, 77, 65, 83 }; // TMAS

    private enum Kind : byte { Byte = 1, Short, Int, Long, Float, Double, Bool, String, Bytes, Ints, Compound, List }
    private sealed class Budget
    {
        private int nodes;
        public void Node(int depth)
        {
            if (depth > MaxDepth || ++nodes > MaxNodes) throw new InvalidDataException("Tag complexity limit exceeded");
        }
    }
    private sealed class LimitedStream : MemoryStream
    {
        private void Check(int count)
        {
            if (count < 0 || Position + count > MaxPayloadBytes) throw new InvalidDataException("Tag payload too large");
        }
        public override void Write(byte[] data, int offset, int count) { Check(count); base.Write(data, offset, count); }
        public override void Write(ReadOnlySpan<byte> data) { Check(data.Length); base.Write(data); }
        public override void WriteByte(byte value) { Check(1); base.WriteByte(value); }
    }

    private static Kind TypeKind(Type type)
    {
        if (type == typeof(byte)) return Kind.Byte;
        if (type == typeof(short)) return Kind.Short;
        if (type == typeof(int)) return Kind.Int;
        if (type == typeof(long)) return Kind.Long;
        if (type == typeof(float)) return Kind.Float;
        if (type == typeof(double)) return Kind.Double;
        if (type == typeof(bool)) return Kind.Bool;
        if (type == typeof(string)) return Kind.String;
        if (type == typeof(byte[])) return Kind.Bytes;
        if (type == typeof(int[])) return Kind.Ints;
        if (type == typeof(TagCompound)) return Kind.Compound;
        if (type.IsGenericType && type.GetGenericTypeDefinition() == typeof(List<>)) return Kind.List;
        throw new NotSupportedException("Unsupported mobile tag type: " + type);
    }
    private static int Count(int count)
    {
        if (count < 0 || count > MaxCollection) throw new InvalidDataException("Tag collection limit exceeded");
        return count;
    }
    private static void WriteText(BinaryWriter writer, string text)
    {
        if (text == null || text.Length > 65536) throw new InvalidDataException("Invalid tag string");
        var data = Utf8.GetBytes(text);
        if (data.Length > 65536) throw new InvalidDataException("Tag string too large");
        writer.Write(data.Length); writer.Write(data);
    }
    private static byte[] Exact(BinaryReader reader, int length)
    {
        if (length < 0 || length > reader.BaseStream.Length - reader.BaseStream.Position)
            throw new InvalidDataException("Truncated tag data");
        var data = reader.ReadBytes(length);
        if (data.Length != length) throw new InvalidDataException("Truncated tag data");
        return data;
    }
    private static string ReadText(BinaryReader reader)
    {
        int length = reader.ReadInt32();
        if (length < 0 || length > 65536) throw new InvalidDataException("Invalid tag string size");
        return Utf8.GetString(Exact(reader, length));
    }

    private static void WriteValue(BinaryWriter writer, object value, Kind kind, Budget budget, int depth)
    {
        budget.Node(depth);
        switch (kind)
        {
            case Kind.Byte: writer.Write((byte)value); break;
            case Kind.Short: writer.Write((short)value); break;
            case Kind.Int: writer.Write((int)value); break;
            case Kind.Long: writer.Write((long)value); break;
            case Kind.Float: writer.Write((float)value); break;
            case Kind.Double: writer.Write((double)value); break;
            case Kind.Bool: writer.Write((bool)value); break;
            case Kind.String: WriteText(writer, (string)value); break;
            case Kind.Bytes:
                var bytes = (byte[])value;
                writer.Write(Count(bytes.Length)); writer.Write(bytes); break;
            case Kind.Ints:
                var ints = (int[])value;
                writer.Write(Count(ints.Length)); foreach (int n in ints) writer.Write(n); break;
            case Kind.Compound:
                var tag = (TagCompound)value;
                writer.Write(Count(tag.Count));
                foreach (var entry in tag.OrderBy(e => e.Key, StringComparer.Ordinal))
                {
                    WriteText(writer, entry.Key);
                    if (entry.Value == null) throw new InvalidDataException("Null tag value");
                    var type = TypeKind(entry.Value.GetType()); writer.Write((byte)type);
                    WriteValue(writer, entry.Value, type, budget, depth + 1);
                }
                break;
            case Kind.List:
                var list = (IList)value;
                var elementKind = TypeKind(value.GetType().GetGenericArguments()[0]);
                if (elementKind == Kind.List) throw new NotSupportedException("Nested list types require compound wrappers");
                writer.Write((byte)elementKind); writer.Write(Count(list.Count));
                foreach (var element in list)
                {
                    if (element == null || TypeKind(element.GetType()) != elementKind)
                        throw new InvalidDataException("List element type differs");
                    WriteValue(writer, element, elementKind, budget, depth + 1);
                }
                break;
            default: throw new InvalidDataException("Unknown tag type");
        }
    }
    private static IList NewList(Kind kind) => kind switch
    {
        Kind.Byte => new List<byte>(), Kind.Short => new List<short>(), Kind.Int => new List<int>(),
        Kind.Long => new List<long>(), Kind.Float => new List<float>(), Kind.Double => new List<double>(),
        Kind.Bool => new List<bool>(), Kind.String => new List<string>(), Kind.Bytes => new List<byte[]>(),
        Kind.Ints => new List<int[]>(), Kind.Compound => new List<TagCompound>(),
        _ => throw new InvalidDataException("Unknown list type")
    };
    private static object ReadValue(BinaryReader reader, Kind kind, Budget budget, int depth)
    {
        budget.Node(depth);
        switch (kind)
        {
            case Kind.Byte: return reader.ReadByte();
            case Kind.Short: return reader.ReadInt16();
            case Kind.Int: return reader.ReadInt32();
            case Kind.Long: return reader.ReadInt64();
            case Kind.Float: return reader.ReadSingle();
            case Kind.Double: return reader.ReadDouble();
            case Kind.Bool:
                var b = reader.ReadByte();
                if (b > 1) throw new InvalidDataException("Invalid boolean");
                return b == 1;
            case Kind.String: return ReadText(reader);
            case Kind.Bytes: return Exact(reader, Count(reader.ReadInt32()));
            case Kind.Ints:
                var n = Count(reader.ReadInt32());
                if ((long)n * 4 > reader.BaseStream.Length - reader.BaseStream.Position)
                    throw new InvalidDataException("Truncated integer array");
                var ints = new int[n]; for (int i = 0; i < n; i++) ints[i] = reader.ReadInt32(); return ints;
            case Kind.Compound:
                int count = Count(reader.ReadInt32()); var tag = new TagCompound();
                for (int i = 0; i < count; i++)
                {
                    string key = ReadText(reader);
                    if (tag.ContainsKey(key)) throw new InvalidDataException("Duplicate tag key");
                    tag.Add(key, ReadValue(reader, (Kind)reader.ReadByte(), budget, depth + 1));
                }
                return tag;
            case Kind.List:
                var elementKind = (Kind)reader.ReadByte();
                var list = NewList(elementKind); int length = Count(reader.ReadInt32());
                for (int i = 0; i < length; i++) list.Add(ReadValue(reader, elementKind, budget, depth + 1));
                return list;
            default: throw new InvalidDataException("Unknown tag type");
        }
    }

    public static byte[] Encode(TagCompound tag)
    {
        if (tag == null) throw new ArgumentNullException(nameof(tag));
        using var payload = new LimitedStream();
        using (var writer = new BinaryWriter(payload, Utf8, true)) WriteValue(writer, tag, Kind.Compound, new Budget(), 0);
        byte[] data = payload.ToArray();
        using var envelope = new MemoryStream();
        using (var writer = new BinaryWriter(envelope, Utf8, true))
        {
            writer.Write(Magic); writer.Write((byte)1); writer.Write(data.Length);
            writer.Write(SHA256.HashData(data)); writer.Write(data);
        }
        return envelope.ToArray();
    }
    public static TagCompound Decode(byte[] envelope)
    {
        if (envelope == null || envelope.Length < HeaderBytes || envelope.Length > MaxPayloadBytes + HeaderBytes)
            throw new InvalidDataException("Invalid tag envelope size");
        try
        {
            using var stream = new MemoryStream(envelope, false);
            using var reader = new BinaryReader(stream, Utf8, true);
            if (!Exact(reader, 4).SequenceEqual(Magic) || reader.ReadByte() != 1)
                throw new InvalidDataException("Unsupported mobile tag format");
            int size = reader.ReadInt32(); byte[] digest = Exact(reader, 32);
            if (size != stream.Length - stream.Position) throw new InvalidDataException("Tag payload length mismatch");
            byte[] payload = Exact(reader, size);
            if (!CryptographicOperations.FixedTimeEquals(digest, SHA256.HashData(payload)))
                throw new InvalidDataException("Tag checksum mismatch");
            using var input = new MemoryStream(payload, false);
            using var values = new BinaryReader(input, Utf8, true);
            var result = (TagCompound)ReadValue(values, Kind.Compound, new Budget(), 0);
            if (input.Position != input.Length) throw new InvalidDataException("Unexpected tag trailing bytes");
            return result;
        }
        catch (EndOfStreamException error) { throw new InvalidDataException("Truncated mobile tag", error); }
        catch (DecoderFallbackException error) { throw new InvalidDataException("Invalid tag UTF-8", error); }
    }
    public static TagCompound Copy(TagCompound tag) => Decode(Encode(tag));
}
