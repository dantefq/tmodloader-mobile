using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Terraria;
using Terraria.ModLoader.IO;
using TerrariaMobile.Managed;
using TerrariaMobile.Serialization;

static class PersistenceTests
{
    static int checks;
    static void Check(bool value, string message)
    {
        if (!value) throw new Exception(message);
        checks++;
    }
    static void Reject<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { checks++; return; }
        throw new Exception("Expected " + typeof(T));
    }
    static byte[] Envelope(Action<BinaryWriter> build)
    {
        using var payload = new MemoryStream();
        using (var writer = new BinaryWriter(payload, Encoding.UTF8, true)) build(writer);
        var bytes = payload.ToArray();
        using var envelope = new MemoryStream();
        using (var writer = new BinaryWriter(envelope, Encoding.UTF8, true))
        {
            writer.Write(new byte[] { 84, 77, 65, 83, 1 }); writer.Write(bytes.Length);
            writer.Write(SHA256.HashData(bytes)); writer.Write(bytes);
        }
        return envelope.ToArray();
    }
    static void Key(BinaryWriter writer, string name, byte type)
    {
        var bytes = Encoding.UTF8.GetBytes(name); writer.Write(bytes.Length); writer.Write(bytes); writer.Write(type);
    }
    static MobileContentRegistry Registry(int id)
    {
        var result = new MobileContentRegistry(); result.Add(new TestMod(), new[] { typeof(ABlade), typeof(StatefulGlobal) });
        result.Initialize(id); return result;
    }
    public static void Run()
    {
        var source = new TagCompound { ["byte"] = (byte)7, ["short"] = (short)-3, ["int"] = 41, ["long"] = long.MaxValue,
            ["float"] = 1.25f, ["double"] = 2.5, ["bool"] = true, ["name"] = "Модовый меч", ["bytes"] = new byte[] { 1, 2 },
            ["ints"] = new[] { -2, 7 }, ["list"] = new List<int> { 1, 9 }, ["empty"] = new List<string>(),
            ["nested"] = new TagCompound { ["charges"] = 9 },
            ["items"] = new List<TagCompound> { new() { ["damage"] = 37 } } };
        var encoded = MobileTagCodec.Encode(source); var restored = MobileTagCodec.Decode(encoded);
        Check(restored.GetByte("byte") == 7 && restored.GetShort("short") == -3 && restored.GetInt("int") == 41,
              "Small integer types preserved");
        Check(restored.GetLong("long") == long.MaxValue && restored.GetFloat("float") == 1.25f && restored.GetDouble("double") == 2.5,
              "Numeric widths preserved");
        Check(restored.GetBool("bool") && restored.GetString("name") == "Модовый меч", "Boolean and UTF8 roundtrip");
        Check(restored.GetByteArray("bytes").SequenceEqual(new byte[] { 1, 2 }) && restored.GetIntArray("ints")[0] == -2,
              "Primitive arrays roundtrip");
        Check(restored.GetList<int>("list")[1] == 9 && restored.GetList<string>("empty").Count == 0, "Typed lists roundtrip");
        Check(restored.GetList<TagCompound>("items")[0].GetInt("damage") == 37, "Compound list roundtrip");
        Check(encoded.SequenceEqual(MobileTagCodec.Encode(restored)), "Canonical encoding is reproducible");
        var reversed = new TagCompound(); foreach (var entry in source.Reverse()) reversed.Add(entry.Key, entry.Value);
        Check(encoded.SequenceEqual(MobileTagCodec.Encode(reversed)), "Dictionary insertion order is irrelevant");
        var clone = (TagCompound)source.Clone(); clone.GetByteArray("bytes")[0] = 99; clone.GetCompound("nested")["charges"] = 1;
        Check(source.GetByteArray("bytes")[0] == 1 && source.GetCompound("nested").GetInt("charges") == 9, "Deep clone isolation");
        Check(source.Get<List<int>>("absent").Count == 0 && source.GetIntArray("absent").Length == 0, "Typed empty defaults");
        Check(!source.TryGet<int>("absent", out var missing) && missing == 0, "TryGet does not fabricate a value");
        source.Set("optional", 2); source.Set("optional", null);
        Check(!source.ContainsKey("optional"), "Null removes a tag");
        Reject<ArgumentException>(() => source.Set("int", 3));
        Check(source.GetAsInt("short") == -3 && source.GetAsLong("byte") == 7 && source.GetAsDouble("float") == 1.25,
              "Explicit numeric widening helpers");
        Check(source.GetAsShort("int") == 0 && source.GetAsInt("long") == 0 && source.GetAsDouble("absent") == 0,
              "Widening helpers do not narrow or invent missing data");
        using (var iterator = source.GetEnumerator()) Check(iterator.MoveNext(), "Enumerator matches public interface signature");

        var damaged = (byte[])encoded.Clone(); damaged[^1] ^= 1;
        Reject<InvalidDataException>(() => MobileTagCodec.Decode(damaged));
        Reject<InvalidDataException>(() => MobileTagCodec.Decode(encoded[..^1]));
        Reject<InvalidDataException>(() => MobileTagCodec.Decode(encoded.Concat(new byte[] { 0 }).ToArray()));
        var future = (byte[])encoded.Clone(); future[4] = 2;
        Reject<InvalidDataException>(() => MobileTagCodec.Decode(future));
        Reject<InvalidDataException>(() => MobileTagCodec.Decode(Envelope(w => { w.Write(1); Key(w, "x", 99); })));
        Reject<InvalidDataException>(() => MobileTagCodec.Decode(Envelope(w => { w.Write(1); Key(w, "x", 7); w.Write((byte)2); })));
        Reject<InvalidDataException>(() => MobileTagCodec.Decode(Envelope(w => { w.Write(2); Key(w, "x", 3); w.Write(1); Key(w, "x", 3); w.Write(2); })));
        Reject<InvalidDataException>(() => MobileTagCodec.Decode(Envelope(w => { w.Write(0); w.Write((byte)0); })));
        Reject<InvalidDataException>(() => MobileTagCodec.Decode(Envelope(w => w.Write(-1))));
        Reject<InvalidDataException>(() => MobileTagCodec.Decode(Envelope(w => { w.Write(1); w.Write(1); w.Write((byte)255); w.Write((byte)3); w.Write(1); })));
        var cycle = new TagCompound(); cycle["loop"] = cycle;
        Reject<InvalidDataException>(() => MobileTagCodec.Encode(cycle));
        Reject<NotSupportedException>(() => MobileTagCodec.Encode(new TagCompound { ["unsupported"] = DateTime.UtcNow }));
        Reject<NotSupportedException>(() => MobileTagCodec.Encode(new TagCompound { ["nestedList"] = new List<List<int>>() }));
        Reject<InvalidDataException>(() => MobileTagCodec.Encode(new TagCompound { ["oversized"] = new int[MobileTagCodec.MaxCollection + 1] }));
        Reject<InvalidDataException>(() => MobileTagCodec.Encode(new TagCompound { ["huge"] = new List<string>(Enumerable.Repeat(new string('a', 4096), 2000)) }));
        var tooManyNodes = new TagCompound();
        for (int i = 0; i < 7; i++) tooManyNodes["list" + i] = Enumerable.Range(0, MobileTagCodec.MaxCollection).ToList();
        Reject<InvalidDataException>(() => MobileTagCodec.Encode(tooManyNodes));

        string folder = Path.Combine(AppContext.BaseDirectory, "persistence-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(folder);
        try
        {
            // Entirely synthetic ordinary save fixture; no Terraria file is accessed.
            string vanilla = Path.Combine(folder, "synthetic-player.plr");
            File.WriteAllBytes(vanilla, new byte[] { 1, 2, 3 });
            var profile = Guid.NewGuid(); var generation = Guid.NewGuid();
            var first = SidecarBinding.FromVanillaFile(profile, generation, vanilla);
            string file = Path.Combine(folder, "synthetic-player.tmal");
            using var registry = Registry(6196);
            var blade = registry.Create(6196); ((ABlade)blade.ModItem).Charges = 11;
            blade.GetGlobalItem<StatefulGlobal>().Counter = 21;
            var items = new Dictionary<string, Item> { ["inventory/0"] = blade };
            var document = SidecarDocument.Capture(registry, first, items);
            var ordinaryBefore = File.ReadAllBytes(vanilla);
            MobileSidecarStore.Write(file, document);
            Check(ordinaryBefore.SequenceEqual(File.ReadAllBytes(vanilla)), "Store never writes ordinary save");
            var read = MobileSidecarStore.Read(file, first);
            using var nextRegistry = Registry(7000);
            var loaded = read.Restore(nextRegistry);
            Check(loaded.Items["inventory/0"].type == 7000 && ((ABlade)loaded.Items["inventory/0"].ModItem).Charges == 11,
                  "Disk restoration uses content name after ID change");
            Check(loaded.Items["inventory/0"].GetGlobalItem<StatefulGlobal>().Counter == 21, "GlobalItem state survives disk");
            Check(loaded.Unresolved.Slots.Count == 0, "Known data fully resolved");
            var copy = read.GetSnapshot("inventory/0"); copy.GetCompound("data")["charges"] = 0;
            Check(read.GetSnapshot("inventory/0").GetCompound("data").GetInt("charges") == 11, "Document snapshots are isolated");
            Reject<KeyNotFoundException>(() => read.GetSnapshot("inventory/99"));
            using (var noMods = new MobileContentRegistry())
            {
                noMods.Initialize(6196);
                var absent = read.Restore(noMods);
                Check(absent.Items.Count == 0 && absent.Unresolved.Slots.Count == 1, "Missing mod retained as unresolved");
                var carried = SidecarDocument.Capture(noMods, first, new Dictionary<string, Item>(), absent.Unresolved);
                Check(carried.Encode().SequenceEqual(read.Encode()), "Unknown data survives resave byte for byte");
                Check(carried.Restore(nextRegistry).Items.Count == 1, "Re-enabled mod recovers preserved data");
                Reject<InvalidOperationException>(() => SidecarDocument.Capture(registry, first, items, absent.Unresolved));
                var foreign = new SidecarBinding(Guid.NewGuid(), generation, first.VanillaSha256);
                Reject<ArgumentException>(() => SidecarDocument.Capture(noMods, foreign, new Dictionary<string, Item>(), absent.Unresolved));
            }
            Reject<InvalidDataException>(() => MobileSidecarStore.Read(file, new SidecarBinding(Guid.NewGuid(), generation, first.VanillaSha256)));
            Reject<InvalidDataException>(() => MobileSidecarStore.Read(file, new SidecarBinding(profile, Guid.NewGuid(), first.VanillaSha256)));
            Reject<InvalidDataException>(() => MobileSidecarStore.Read(file, new SidecarBinding(profile, generation, new byte[32])));
            var original = File.ReadAllBytes(file);
            Reject<InvalidOperationException>(() => MobileSidecarStore.Write(file, document));
            Check(original.SequenceEqual(File.ReadAllBytes(file)), "Blind overwrite refused without modifying file");
            Reject<ArgumentException>(() => MobileSidecarStore.Write(vanilla, document));
            Reject<ArgumentException>(() => new SidecarDocument(first, new Dictionary<string, TagCompound> { ["../bad"] = copy }));

            File.WriteAllBytes(vanilla, new byte[] { 4, 5, 6 });
            var second = SidecarBinding.FromVanillaFile(profile, Guid.NewGuid(), vanilla);
            var secondDocument = SidecarDocument.Capture(registry, second, items);
            Reject<InvalidOperationException>(() => MobileSidecarStore.Write(file, secondDocument, Guid.NewGuid()));
            MobileSidecarStore.Write(file, secondDocument, first.Generation);
            Check(MobileSidecarStore.Read(file, second).Slots.Count == 1, "Atomic replace publishes new generation");
            Check(MobileSidecarStore.ReadRecoverable(file, first, out var fromBackup).Binding.Matches(first) && fromBackup,
                  "Matching previous generation available from backup");
            var corruptPrimary = File.ReadAllBytes(file); corruptPrimary[^1] ^= 1; File.WriteAllBytes(file, corruptPrimary);
            Check(MobileSidecarStore.ReadRecoverable(file, first, out fromBackup).Binding.Matches(first) && fromBackup,
                  "Corrupt primary can recover exact matching backup");
            Reject<InvalidDataException>(() => MobileSidecarStore.ReadRecoverable(file, second, out _));
            Check(corruptPrimary.SequenceEqual(File.ReadAllBytes(file)), "Recovery reads do not overwrite corrupt evidence");
            Reject<InvalidDataException>(() => MobileSidecarStore.Write(file, secondDocument, first.Generation));
            File.WriteAllBytes(file, secondDocument.Encode()); // Restore our test fixture to continue lock/replacement cases.
            using (var gate = new FileStream(file + ".lock", FileMode.Open, FileAccess.ReadWrite, FileShare.None))
                Reject<IOException>(() => MobileSidecarStore.Write(file, secondDocument, second.Generation));
            var third = SidecarBinding.FromVanillaFile(profile, Guid.NewGuid(), vanilla);
            MobileSidecarStore.Write(file, SidecarDocument.Capture(registry, third, items), second.Generation);
            Check(MobileSidecarStore.ReadRecoverable(file, second, out fromBackup).Binding.Matches(second) && fromBackup,
                  "Backup updated to immediate previous generation");
            Check(Directory.GetFiles(folder, "*.tmp").Length == 0, "No temporary files remain after writes");
            Reject<InvalidOperationException>(() => MobileSidecarStore.Write(Path.Combine(folder, "missing.tmal"), document, first.Generation));
        }
        finally { Directory.Delete(folder, true); }
        Console.WriteLine($"PASS {checks} persistence checks; synthetic files only, no Android device used");
    }
}
