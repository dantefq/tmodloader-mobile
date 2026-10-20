using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Terraria.ModLoader;
using TerrariaMobile.Managed;
using TerrariaMobile.Serialization;

static class ArchiveTests
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
    static byte[] Payload(string name, Action<BinaryWriter> table)
    {
        using var output = new MemoryStream();
        using (var writer = new BinaryWriter(output, Encoding.UTF8, true)) { writer.Write(name); writer.Write("1.0.0"); table(writer); }
        return output.ToArray();
    }
    static byte[] Envelope(byte[] payload, string loader = "2026.8.3.0")
    {
        using var output = new MemoryStream();
        using (var writer = new BinaryWriter(output, Encoding.UTF8, true))
        {
            writer.Write(new byte[] { 84, 77, 79, 68 }); writer.Write(loader);
            writer.Write(SHA1.HashData(payload)); writer.Write(new byte[256]); writer.Write(payload.Length); writer.Write(payload);
        }
        return output.ToArray();
    }
    public static void Run()
    {
        byte[] expanded = Enumerable.Repeat((byte)42, 4096).ToArray();
        using var buffer = new MemoryStream();
        using (var deflate = new DeflateStream(buffer, CompressionLevel.SmallestSize, true)) deflate.Write(expanded);
        byte[] compressed = buffer.ToArray(); byte[] text = Encoding.UTF8.GetBytes("Модовый ресурс");
        byte[] bytes = Envelope(Payload("Test", w =>
        {
            w.Write(3);
            w.Write("data/message.txt"); w.Write(text.Length); w.Write(text.Length);
            w.Write("data/repeated.bin"); w.Write(expanded.Length); w.Write(compressed.Length);
            w.Write("data/empty"); w.Write(0); w.Write(0);
            w.Write(text); w.Write(compressed);
        }));
        var archive = MobileTmodArchive.FromBytes(bytes, SHA256.HashData(bytes));
        Check(archive.Name == "Test" && archive.Version.ToString() == "1.0.0" && archive.Count == 3, "Archive identity and table");
        Check(archive.PayloadSha1Verified && !archive.SignatureAuthenticated, "Integrity distinct from signature authentication");
        Check(archive.GetBytes("data/message.txt").SequenceEqual(text), "Uncompressed resource read");
        Check(archive.GetBytes("data/repeated.bin").SequenceEqual(expanded), "Bounded raw deflate resource read");
        Check(archive.GetBytes("data/repeated.bin", expanded.Length).SequenceEqual(expanded), "Exact caller resource budget");
        Reject<InvalidDataException>(() => archive.GetBytes("data/repeated.bin", expanded.Length - 1));
        Reject<ArgumentOutOfRangeException>(() => archive.GetBytes("data/repeated.bin", -1));
        Check(archive.GetBytes("data/empty").Length == 0, "Empty resource");
        Check(archive.HasFile("data\\message.txt") && archive.GetBytes("missing") == null, "Backslash normalization and missing data");
        var names = archive.GetFileNames(); names.Clear();
        Check(archive.GetFileNames().Count == 3, "Resource names are copied");
        var copy = archive.GetBytes("data/message.txt"); copy[0] ^= 1;
        Check(archive.GetBytes("data/message.txt").SequenceEqual(text), "Resource bytes are copied");
        bytes[^1] ^= 1;
        Check(archive.GetBytes("data/repeated.bin").SequenceEqual(expanded), "Archive owns source bytes");
        Reject<InvalidDataException>(() => MobileTmodArchive.FromBytes(bytes));
        Reject<InvalidDataException>(() => MobileTmodArchive.FromBytes(archiveBytes(), new byte[32]));
        Reject<InvalidDataException>(() => MobileTmodArchive.FromBytes(archiveBytes()[..^1]));
        Reject<InvalidDataException>(() => MobileTmodArchive.FromBytes(Envelope(Payload("Test", w => w.Write(-1)))));
        Reject<InvalidDataException>(() => MobileTmodArchive.FromBytes(Envelope(Payload("Test", w => { w.Write(0); w.Write((byte)1); }))));
        Reject<NotSupportedException>(() => MobileTmodArchive.FromBytes(Envelope(Payload("Test", w => w.Write(0)), "0.10.0")));
        Reject<InvalidDataException>(() => MobileTmodArchive.FromBytes(Envelope(Payload("Test", w =>
        { w.Write(2); w.Write("a/b"); w.Write(0); w.Write(0); w.Write("a\\b"); w.Write(0); w.Write(0); }))));
        Reject<InvalidDataException>(() => MobileTmodArchive.FromBytes(Envelope(Payload("Test", w =>
        { w.Write(1); w.Write("../escape"); w.Write(0); w.Write(0); }))));
        Reject<InvalidDataException>(() => MobileTmodArchive.FromBytes(Envelope(Payload("Test", w =>
        { w.Write(1); w.Write("huge"); w.Write(MobileTmodArchive.MaxEntryBytes + 1); w.Write(0); }))));
        Reject<InvalidDataException>(() => MobileTmodArchive.FromBytes(Envelope(Payload("Test", w =>
        {
            w.Write(5);
            for(int i=0;i<5;i++){w.Write("opaque/"+i);w.Write(MobileTmodArchive.MaxEntryBytes);w.Write(0);}
        })))); // Metadata-only host inspection must not relax runtime resource admission.
        Reject<ArgumentException>(() => archive.GetBytes("/absolute"));
        var oversized = MobileTmodArchive.FromBytes(Envelope(Payload("Test", w =>
        { w.Write(1); w.Write("short"); w.Write(1); w.Write(compressed.Length); w.Write(compressed); })));
        Reject<InvalidDataException>(() => oversized.GetBytes("short"));
        var truncated = MobileTmodArchive.FromBytes(Envelope(Payload("Test", w =>
        { w.Write(1); w.Write("long"); w.Write(expanded.Length + 1); w.Write(compressed.Length); w.Write(compressed); })));
        Reject<InvalidDataException>(() => truncated.GetBytes("long"));
        var mod = new ResourceMod();
        using (var registry = new MobileContentRegistry())
        {
            Reject<ArgumentException>(() => registry.Add(new TestMod(), Array.Empty<Type>(), MobileTmodArchive.FromBytes(
                Envelope(Payload("Other", w => w.Write(0))))));
            registry.Add(mod, new[] { typeof(ResourceItem) }, archive);
            registry.Add(new CallerMod(), Array.Empty<Type>());
            registry.Initialize(6196);
            Check(registry.ItemNames.Count == 1 && mod.Loaded, "Resources available to enabled predicate and lifecycle");
            Check(CallerMod.CallResult == "Модовый ресурс" && CallerMod.MissingLookupSafe, "Cross-mod lookup, Call and qualified resource access");
            Check(mod.FileExists("data/message.txt") && mod.GetFileNames().Count == 3, "Mod resource API bound");
            Check(mod.Version.ToString() == "1.0.0" && mod.TModLoaderVersion.ToString() == "2026.8.3.0",
                  "Mod reports archive versions");
            using var stream1 = mod.GetFileStream("data/repeated.bin");
            using var stream2 = mod.GetFileStream("data/repeated.bin", true);
            Check(!stream1.CanWrite && stream1.ReadByte() == 42 && stream2.Position == 0, "Independent read-only resource streams");
            using var another = new MobileContentRegistry();
            Reject<InvalidOperationException>(() => another.Add(mod, Array.Empty<Type>(), archive));
        }
        Check(mod.UnloadedWithResources && mod.GetFileBytes("data/message.txt") == null, "Resources released after Unload");
        string file = Path.Combine(AppContext.BaseDirectory, "resource-fixture-" + Guid.NewGuid().ToString("N") + ".tmod");
        try
        {
            File.WriteAllBytes(file, archiveBytes());
            Check(MobileTmodArchive.FromFile(file).Count == 3, "Filesystem archive read");
        }
        finally { File.Delete(file); }
        Console.WriteLine($"PASS {checks} TMOD resource checks; synthetic archive data only");
        byte[] archiveBytes() => Envelope(Payload("Test", w =>
        {
            w.Write(3);
            w.Write("data/message.txt"); w.Write(text.Length); w.Write(text.Length);
            w.Write("data/repeated.bin"); w.Write(expanded.Length); w.Write(compressed.Length);
            w.Write("data/empty"); w.Write(0); w.Write(0); w.Write(text); w.Write(compressed);
        }));
    }
}
sealed class ResourceMod : Mod
{
    public override string Name => "Test";
    public bool Loaded, UnloadedWithResources;
    public override void Load() => Loaded = FileExists("data/message.txt");
    public override void Unload() => UnloadedWithResources = FileExists("data/message.txt");
    public override object Call(params object[] args) => args.Length == 1 && (string)args[0] == "message" ?
        Encoding.UTF8.GetString(GetFileBytes("data/message.txt")) : null;
}
sealed class ResourceItem : ModItem
{
    public override bool IsLoadingEnabled(Mod mod) => mod.FileExists("data/message.txt");
}
sealed class CallerMod : Mod
{
    public override string Name => "Caller";
    public static string CallResult;
    public static bool MissingLookupSafe;
    public override void Load()
    {
        if (ModLoader.Mods.Length != 2 || !ModLoader.HasMod("Test")) throw new Exception("Mod discovery differs");
        CallResult = (string)ModLoader.GetMod("Test").Call("message");
        MissingLookupSafe = !ModLoader.TryGetMod("Absent", out var missing) && missing == null &&
            !ModContent.FileExists("Absent/data/message.txt") && !ModContent.FileExists("unqualified");
        if (Encoding.UTF8.GetString(ModContent.GetFileBytes("Test/data/message.txt")) != CallResult ||
            !ModContent.FileExists("Test/data/message.txt")) throw new Exception("Qualified resource lookup differs");
    }
}
