using System;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Security.Cryptography;
using Terraria.ModLoader;
using TerrariaMobile.Managed;
using TerrariaMobile.Serialization;

// Own 2x2 RGBA fixture shared by host checks and the isolated Android probe.
static class TextureBridgeChecks
{
    public static readonly byte[] Pixels = { 1, 2, 3, 255, 40, 50, 60, 127, 7, 8, 9, 0, 9, 8, 7, 1 };
    public static MobileContentRegistry Create(bool oversizedIdentity = false)
    {
        using var raw = new MemoryStream();
        using (var writer = new BinaryWriter(raw, Encoding.UTF8, true))
        { writer.Write(1); writer.Write(2); writer.Write(2); writer.Write(Pixels); }
        byte[] image = raw.ToArray();
        using var payload = new MemoryStream();
        using (var writer = new BinaryWriter(payload, Encoding.UTF8, true))
        {
            writer.Write("TextureBridgeLab"); writer.Write("1.0"); writer.Write(1);
            writer.Write("Images/Icon.rawimg"); writer.Write(image.Length); writer.Write(image.Length); writer.Write(image);
        }
        byte[] data = payload.ToArray();
        using var archive = new MemoryStream();
        using (var writer = new BinaryWriter(archive, Encoding.UTF8, true))
        {
            writer.Write(new byte[] { 84, 77, 79, 68 }); writer.Write("2026.5.3.0");
            writer.Write(SHA1.HashData(data)); writer.Write(new byte[256]); writer.Write(data.Length); writer.Write(data);
        }
        var registry = new MobileContentRegistry();
        registry.Add(new LabMod(), new[] { oversizedIdentity ? typeof(LongIcon) : typeof(Icon) }, MobileTmodArchive.FromBytes(archive.ToArray()));
        registry.Initialize(6196);
        return registry;
    }
    public static string Transfer(string export)
    {
        using var json = JsonDocument.Parse(export);
        return json.RootElement.GetProperty("plan").GetProperty("transferId").GetString();
    }
    public static int Run()
    {
        int checks = 0;
        void Check(bool ok) { if (!ok) throw new Exception("Texture bridge check " + checks); checks++; }
        void Reject<T>(Action action) where T : Exception
        { try { action(); } catch (T) { checks++; return; } throw new Exception("Expected " + typeof(T).Name); }
        using var registry = Create(); var gate = new object();
        Reject<ArgumentNullException>(() => new MobileTextureBridge(null, gate));
        Reject<ArgumentNullException>(() => new MobileTextureBridge(registry, null));
        var bridge = new MobileTextureBridge(registry, gate);
        using (var description = JsonDocument.Parse(bridge.Describe()))
            Check(description.RootElement.GetProperty("generation").GetGuid() == registry.ContentGeneration &&
                description.RootElement.GetProperty("pending").GetInt32() == 0);
        Reject<System.Collections.Generic.KeyNotFoundException>(() => bridge.BeginItem(1));
        Check(registry.PendingTextureTransferCount == 0);
        string export = bridge.BeginItem(6196), id = Transfer(export);
        using (var json = JsonDocument.Parse(export))
        {
            var plan = json.RootElement.GetProperty("plan");
            Check(json.RootElement.GetProperty("format").GetString() == "tmal-texture-export-v1");
            Check(plan.GetProperty("item").GetString() == "TextureBridgeLab/Icon");
            var packet = Convert.FromBase64String(json.RootElement.GetProperty("packetBase64").GetString());
            var decoded = MobileTexturePacket.Decode(packet, plan.GetProperty("asset").GetString(), registry.ContentGeneration,
                plan.GetProperty("archiveSha256").GetString());
            Check(decoded.Width == 2 && decoded.Height == 2);
        }
        Check(registry.PendingTextureTransferCount == 1 && bridge.ReadExport(id) == export);
        Reject<InvalidOperationException>(() => bridge.BeginItem(6196));
        Reject<InvalidOperationException>(() => bridge.Unload());
        Reject<ArgumentException>(() => bridge.ReadExport("bad"));
        Reject<ArgumentException>(() => bridge.CompleteNativeTeardown(Guid.Empty.ToString("D")));
        Reject<ArgumentException>(() => bridge.CompleteNativeTeardown(id.Replace("-", "")));
        Reject<InvalidOperationException>(() => bridge.CompleteNativeTeardown(Guid.NewGuid().ToString("D")));
        Check(registry.PendingTextureTransferCount == 1);
        GC.Collect(); GC.WaitForPendingFinalizers();
        Check(bridge.ReadExport(id) == export);
        bridge.CompleteNativeTeardown(id); Check(registry.PendingTextureTransferCount == 0);
        Reject<InvalidOperationException>(() => bridge.ReadExport(id));
        Reject<InvalidOperationException>(() => bridge.CompleteNativeTeardown(id));
        string next = bridge.BeginItem(6196), nextId = Transfer(next); Check(nextId != id);
        Reject<InvalidOperationException>(() => bridge.CompleteNativeTeardown(id));
        Check(registry.PendingTextureTransferCount == 1);
        bridge.CompleteNativeTeardown(nextId); bridge.Unload();
        Check(registry.ImageCacheResidentBytes == 0);
        Reject<InvalidOperationException>(() => bridge.Describe());
        Reject<InvalidOperationException>(() => bridge.BeginItem(6196));
        bridge.Unload();
        using (var large = Create(oversizedIdentity: true))
        {
            var bounded = new MobileTextureBridge(large, new object());
            Reject<NotSupportedException>(() => bounded.BeginItem(6196));
            Check(large.PendingTextureTransferCount == 0);
            using var description = JsonDocument.Parse(bounded.Describe());
            Check(description.RootElement.GetProperty("pending").GetInt32() == 0);
        }
        Console.WriteLine("PASS " + checks + " texture bridge export/lifecycle checks; no native graphics");
        return checks;
    }
    sealed class LabMod : Mod { public override string Name => "TextureBridgeLab"; }
    sealed class Icon : ModItem { public override string Texture => "TextureBridgeLab/Images/Icon"; }
    sealed class LongIcon : ModItem
    {
        public override string Name => new string('x', 100000);
        public override string Texture => "TextureBridgeLab/Images/Icon";
    }
}
