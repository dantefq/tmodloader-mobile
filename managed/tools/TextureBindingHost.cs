using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Terraria.ModLoader;
using TerrariaMobile.Managed;
using TerrariaMobile.Serialization;

// Own host fixture. Reads ONE pinned texture as data, never loads a SOTS DLL.
// The live registry remains on this process's command loop until native teardown.
static class TextureBindingHost
{
    const string SourceArchive = "4642380a29751664afa9122f01a8cf4491232ef9cd7bdb40e15c6d8e4e7c3790";
    const string SourceImage = "783e86053ec749c41e1b05e89cca94a09966ff3b40423ca18dd9faf8a9494b05";
    static string Hash(byte[] bytes) => Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant();
    static void Reply(object value) { Console.WriteLine(JsonSerializer.Serialize(value)); Console.Out.Flush(); }
    static byte[] LabArchive(byte[] raw)
    {
        using var payload = new MemoryStream();
        using (var writer = new BinaryWriter(payload, Encoding.UTF8, true))
        {
            writer.Write("TextureBindingLab"); writer.Write("1.0"); writer.Write(1);
            writer.Write("Images/SourceIcon.rawimg"); writer.Write(raw.Length); writer.Write(raw.Length); writer.Write(raw);
        }
        var data = payload.ToArray();
        using var output = new MemoryStream();
        using (var writer = new BinaryWriter(output, Encoding.UTF8, true))
        {
            writer.Write(new byte[] { 84, 77, 79, 68 }); writer.Write("2026.5.3.0");
            writer.Write(SHA1.HashData(data)); writer.Write(new byte[256]); writer.Write(data.Length); writer.Write(data);
        }
        return output.ToArray();
    }
    static int Main(string[] args)
    {
        try
        {
            if (args.Length != 2) throw new ArgumentException("Expected pinned source archive and empty private output directory");
            string folder = Path.GetFullPath(args[1]); Directory.CreateDirectory(folder);
            if (Directory.GetFileSystemEntries(folder).Length != 0) throw new IOException("Refusing to overwrite an existing fixture");
            for (var p = new DirectoryInfo(folder); p != null; p = p.Parent)
                if (Directory.Exists(Path.Combine(p.FullName, ".git"))) throw new IOException("Private resources must remain outside a checkout");
            var source = MobileTmodArchive.FromFile(args[0], Convert.FromHexString(SourceArchive));
            var raw = source.GetBytes("Items/HelicopterParts.rawimg", 256 * 256 * 4 + 12);
            if (Hash(raw) != SourceImage) throw new InvalidDataException("Pinned source image differs");
            byte[] labArchive = LabArchive(raw);
            File.WriteAllBytes(Path.Combine(folder, "own-lab-resources.tmod"), labArchive);
            using var registry = new MobileContentRegistry();
            registry.Add(new LabMod(), new[] { typeof(Preview) }, MobileTmodArchive.FromBytes(labArchive));
            registry.Initialize(6196);
            var binding = registry.PrepareItemTextureBinding(registry.ItemType("TextureBindingLab/Preview"));
            var bridge = new MobileTextureBridge(registry, new object());
            string export = bridge.BeginItem(binding.ItemType);
            File.WriteAllText(Path.Combine(folder, "texture-export.json"), export);
            using var exported = JsonDocument.Parse(export);
            var plan = exported.RootElement.GetProperty("plan");
            string transferId = plan.GetProperty("transferId").GetString();
            File.WriteAllText(Path.Combine(folder, "texture-binding-plan.json"), plan.GetRawText());
            var bytes = Convert.FromBase64String(exported.RootElement.GetProperty("packetBase64").GetString());
            File.WriteAllBytes(Path.Combine(folder, "texture-binding.png.tmit"), bytes);
            File.WriteAllBytes(Path.Combine(folder, "source.rawimg"), raw);
            Reply(new { status = "ready", generation = binding.Generation, transfer_id = transferId, packet_sha256 = Hash(bytes),
                common_texture_bridge = true,
                original_archive_sha256 = source.Sha256, original_image_sha256 = Hash(raw),
                original_mod_code_executed = false, private_lab_resource_archive = true });
            bool unloaded = false;
            string command;
            while ((command = Console.ReadLine()) != null)
            {
                if (command == "validate")
                {
                    binding.ValidateOwner();
                    using var current = JsonDocument.Parse(bridge.ReadExport(transferId));
                    Reply(new { status = "active", generation = registry.ContentGeneration, item_type = binding.ItemType,
                        transfer_id = transferId, pending_transfers = registry.PendingTextureTransferCount,
                        packet_sha256 = Hash(Convert.FromBase64String(current.RootElement.GetProperty("packetBase64").GetString())) });
                }
                else if (command == "unload-while-active")
                {
                    bool blocked = false;
                    try { bridge.Unload(); } catch (InvalidOperationException) { blocked = true; }
                    if (!blocked || registry.PendingTextureTransferCount != 1) throw new Exception("Active native transfer did not block unload");
                    binding.ValidateOwner();
                    Reply(new { status = "unload-blocked", pending_transfers = registry.PendingTextureTransferCount });
                }
                else if (command.StartsWith("complete ", StringComparison.Ordinal))
                {
                    bridge.CompleteNativeTeardown(command.Substring(9));
                    Reply(new { status = "teardown-acknowledged", transfer_id = transferId, pending_transfers = registry.PendingTextureTransferCount });
                }
                else if (command == "unload")
                {
                    if (unloaded) throw new InvalidOperationException("Registry already unloaded");
                    bridge.Unload(); unloaded = true;
                    bool rejected = false;
                    try { binding.ValidateOwner(); } catch (InvalidOperationException) { rejected = true; }
                    if (!rejected || registry.ImageCacheResidentBytes != 0) throw new Exception("Stale binding/unload contract differs");
                    Reply(new { status = "unloaded", stale_binding_rejected = rejected, image_cache_resident_bytes = registry.ImageCacheResidentBytes });
                }
                else if (command == "quit") return 0;
                else throw new ArgumentException("Unknown host command");
            }
            return 0;
        }
        catch (Exception error) { Console.Error.WriteLine(error.GetType().Name + ": " + error.Message); return 2; }
    }
    sealed class LabMod : Mod { public override string Name => "TextureBindingLab"; }
    sealed class Preview : ModItem { public override string Texture => "TextureBindingLab/Images/SourceIcon"; }
}
