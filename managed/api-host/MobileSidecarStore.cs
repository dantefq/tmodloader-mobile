using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Terraria;
using Terraria.ModLoader.IO;
using TerrariaMobile.Serialization;

namespace TerrariaMobile.Managed;

public sealed class SidecarBinding
{
    public Guid Profile { get; }
    public Guid Generation { get; }
    private readonly byte[] vanillaHash;
    public byte[] VanillaSha256 => (byte[])vanillaHash.Clone();
    public SidecarBinding(Guid profile, Guid generation, byte[] vanillaSha256)
    {
        if (profile == Guid.Empty || generation == Guid.Empty || vanillaSha256 == null || vanillaSha256.Length != 32)
            throw new ArgumentException("Profile, generation and SHA256 must be explicit");
        Profile = profile; Generation = generation; vanillaHash = (byte[])vanillaSha256.Clone();
    }
    public bool Matches(SidecarBinding other) => other != null && Profile == other.Profile &&
        Generation == other.Generation && CryptographicOperations.FixedTimeEquals(vanillaHash, other.vanillaHash);
    public static SidecarBinding FromVanillaFile(Guid profile, Guid generation, string path)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read);
        return new SidecarBinding(profile, generation, SHA256.HashData(input));
    }
}

// Immutable document owns a bounded deep copy. Returned snapshots cannot mutate it.
public sealed class SidecarDocument
{
    public SidecarBinding Binding { get; }
    private readonly TagCompound root;
    public IReadOnlyCollection<string> Slots => root.GetCompound("slots").Keys.ToArray();
    public SidecarDocument(SidecarBinding binding, IReadOnlyDictionary<string, TagCompound> slots)
    {
        if (binding == null || slots == null) throw new ArgumentNullException();
        if (slots.Count > 4096) throw new ArgumentException("Too many sidecar slots");
        var entries = new TagCompound();
        foreach (var entry in slots)
        {
            ValidateSlot(entry.Key);
            if (entry.Value == null) throw new ArgumentException("Null item snapshot");
            entries.Add(entry.Key, entry.Value);
        }
        Binding = binding;
        root = MobileTagCodec.Copy(new TagCompound { ["format"] = 1, ["profile"] = binding.Profile.ToString("D"),
            ["generation"] = binding.Generation.ToString("D"), ["vanillaSha256"] = binding.VanillaSha256, ["slots"] = entries });
    }
    private static void ValidateSlot(string slot)
    {
        if (string.IsNullOrEmpty(slot) || slot.Length > 128 || !slot.Contains('/') || slot.StartsWith('/') ||
            slot.EndsWith('/') || slot.Contains("//") || slot.Any(c => !(c is >= 'a' and <= 'z' or >= 'A' and <= 'Z' or
                >= '0' and <= '9' or '-' or '_' or '/')))
            throw new ArgumentException("Invalid logical slot identity");
    }
    public TagCompound GetSnapshot(string slot)
    {
        if (!root.GetCompound("slots").TryGet<TagCompound>(slot, out var tag)) throw new KeyNotFoundException(slot);
        return MobileTagCodec.Copy(tag);
    }
    public byte[] Encode() => MobileTagCodec.Encode(root);
    public static SidecarDocument Decode(byte[] data)
    {
        var tag = MobileTagCodec.Decode(data);
        if (tag.Count != 5 || tag.GetInt("format") != 1 || !tag.ContainsKey("slots") || !tag.ContainsKey("vanillaSha256"))
            throw new InvalidDataException("Unsupported sidecar document");
        if (!Guid.TryParseExact(tag.GetString("profile"), "D", out var profile) ||
            !Guid.TryParseExact(tag.GetString("generation"), "D", out var generation))
            throw new InvalidDataException("Invalid sidecar identity");
        var entries = tag.GetCompound("slots");
        var slots = new Dictionary<string, TagCompound>(StringComparer.Ordinal);
        foreach (var entry in entries)
        {
            if (entry.Value is not TagCompound snapshot) throw new InvalidDataException("Invalid item snapshot");
            slots.Add(entry.Key, snapshot);
        }
        try { return new SidecarDocument(new SidecarBinding(profile, generation, tag.GetByteArray("vanillaSha256")), slots); }
        catch (ArgumentException error) { throw new InvalidDataException("Invalid sidecar document", error); }
    }

    public SidecarRestore Restore(MobileContentRegistry registry)
    {
        if (registry == null) throw new ArgumentNullException(nameof(registry));
        var known = new Dictionary<string, Item>(StringComparer.Ordinal);
        var unknown = new Dictionary<string, TagCompound>(StringComparer.Ordinal);
        foreach (string slot in Slots)
        {
            // Plugins receive a copy; a LoadData hook cannot alter the stored document.
            var snapshot = GetSnapshot(slot);
            if (registry.TryRestore(snapshot, out var item)) known.Add(slot, item);
            else unknown.Add(slot, GetSnapshot(slot));
        }
        return new SidecarRestore(known, new SidecarDocument(Binding, unknown));
    }
    public static SidecarDocument Capture(MobileContentRegistry registry, SidecarBinding binding,
        IReadOnlyDictionary<string, Item> items, SidecarDocument unresolved = null)
    {
        if (registry == null || binding == null || items == null) throw new ArgumentNullException();
        var slots = new Dictionary<string, TagCompound>(StringComparer.Ordinal);
        if (unresolved != null)
        {
            if (binding.Profile != unresolved.Binding.Profile) throw new ArgumentException("Unknown data belongs to another profile");
            foreach (string slot in unresolved.Slots) slots.Add(slot, unresolved.GetSnapshot(slot));
        }
        foreach (var entry in items)
        {
            if (slots.ContainsKey(entry.Key)) throw new InvalidOperationException("Cannot replace unresolved content: " + entry.Key);
            slots.Add(entry.Key, registry.Save(entry.Value));
        }
        return new SidecarDocument(binding, slots);
    }
}

public sealed class SidecarRestore
{
    public IReadOnlyDictionary<string, Item> Items { get; }
    public SidecarDocument Unresolved { get; }
    internal SidecarRestore(Dictionary<string, Item> items, SidecarDocument unresolved)
    {
        Items = new ReadOnlyDictionary<string, Item>(items); Unresolved = unresolved;
    }
}

// Own sidecar files only. This class never writes a vanilla player/world file.
public static class MobileSidecarStore
{
    private static string Resolve(string path)
    {
        if (!string.Equals(Path.GetExtension(path), ".tmal", StringComparison.OrdinalIgnoreCase))
            throw new ArgumentException("Own sidecar filename must end in .tmal");
        return Path.GetFullPath(path);
    }
    private static SidecarDocument ReadDocument(string path)
    {
        using var input = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read | FileShare.Delete);
        if (input.Length > MobileTagCodec.MaxPayloadBytes + 41) throw new InvalidDataException("Sidecar too large");
        var data = new byte[checked((int)input.Length)]; input.ReadExactly(data);
        return SidecarDocument.Decode(data);
    }
    private static void ValidateBinding(SidecarDocument document, SidecarBinding expected)
    {
        if (expected == null || !document.Binding.Matches(expected))
            throw new InvalidDataException("Sidecar profile, generation or vanilla save fingerprint differs");
    }
    public static SidecarDocument Read(string path, SidecarBinding expected)
    {
        var document = ReadDocument(Resolve(path)); ValidateBinding(document, expected); return document;
    }
    public static SidecarDocument ReadRecoverable(string path, SidecarBinding expected, out bool fromBackup)
    {
        string file = Resolve(path);
        fromBackup = false;
        try { return Read(file, expected); }
        catch (Exception error) when (error is IOException or InvalidDataException or ArgumentException or InvalidCastException)
        {
            // A backup is usable only if it independently matches the exact expected save.
            var backup = ReadDocument(file + ".bak"); ValidateBinding(backup, expected);
            fromBackup = true; return backup;
        }
    }
    public static void Write(string path, SidecarDocument document, Guid? expectedPreviousGeneration = null)
    {
        if (document == null) throw new ArgumentNullException(nameof(document));
        string file = Resolve(path);
        byte[] data = document.Encode(); // Fully validate before touching filesystem state.
        Directory.CreateDirectory(Path.GetDirectoryName(file));
        // Cooperating writers share this lock; it is retained and is not a stale-process marker.
        using var gate = new FileStream(file + ".lock", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
        bool exists = File.Exists(file);
        if (exists)
        {
            var previous = ReadDocument(file);
            if (expectedPreviousGeneration == null || previous.Binding.Generation != expectedPreviousGeneration ||
                previous.Binding.Profile != document.Binding.Profile || previous.Binding.Generation == document.Binding.Generation)
                throw new InvalidOperationException("Stale generation or mismatched profile; sidecar not replaced");
        }
        else if (expectedPreviousGeneration != null)
            throw new InvalidOperationException("Expected previous sidecar is missing");
        string temporary = file + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            using (var output = new FileStream(temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                output.Write(data); output.Flush(true);
            }
            if (exists) File.Replace(temporary, file, file + ".bak");
            else File.Move(temporary, file);
        }
        finally { if (File.Exists(temporary)) File.Delete(temporary); }
    }
}
