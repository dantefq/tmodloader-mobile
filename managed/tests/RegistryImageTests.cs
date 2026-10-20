using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using Terraria.ModLoader;
using TerrariaMobile.Managed;
using TerrariaMobile.Serialization;

static class RegistryImageTests
{
    static int checks;
    static void Check(bool ok) { if (!ok) throw new Exception("Registry image contract differs"); checks++; }
    static void Reject<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { checks++; return; }
        throw new Exception("Expected " + typeof(T).Name);
    }
    static MobileTmodArchive Archive(string name = "ImageTest", byte firstPixel = 1, int width = 2)
    {
        using var raw = new MemoryStream();
        using (var w = new BinaryWriter(raw, Encoding.UTF8, true))
        {
            w.Write(1); w.Write(width); w.Write(1);
            for (int x = 0; x < width; x++) w.Write(x == 0 ? new byte[] { firstPixel, 2, 3, 255 } : new byte[] { 4, 5, 6, 127 });
        }
        byte[] pixels = raw.ToArray();
        using var payload = new MemoryStream();
        using (var w = new BinaryWriter(payload, Encoding.UTF8, true))
        {
            w.Write(name); w.Write("1.0"); w.Write(1); w.Write("Images/Icon.rawimg");
            w.Write(pixels.Length); w.Write(pixels.Length); w.Write(pixels);
        }
        var data = payload.ToArray();
        using var output = new MemoryStream();
        using (var w = new BinaryWriter(output, Encoding.UTF8, true))
        {
            w.Write(new byte[] { 84, 77, 79, 68 }); w.Write("2026.5.3.0");
            w.Write(SHA1.HashData(data)); w.Write(new byte[256]); w.Write(data.Length); w.Write(data);
        }
        return MobileTmodArchive.FromBytes(output.ToArray());
    }
    public static void Run()
    {
        var registry = new MobileContentRegistry(maxImageCacheBytes: 8);
        var resourceArchive = Archive();
        Reject<InvalidOperationException>(() => registry.ReadItemImage(6196));
        Reject<InvalidOperationException>(() => registry.PrepareItemTextureBinding(6196));
        registry.Add(new ImageMod(), new[] { typeof(IconItem), typeof(AliasItem), typeof(MissingItem),
            typeof(UnsafePathItem), typeof(VanillaAliasItem), typeof(CrossModItem), typeof(MutableItem) }, resourceArchive);
        registry.Add(new ProviderMod(), Array.Empty<Type>(), Archive("Provider", 55));
        registry.Initialize(6196);
        var image = registry.ReadItemImage(registry.ItemType("ImageTest/IconItem"));
        Check(image.Width == 2 && image.Height == 1 && image.CopyRgba()[3] == 255);
        Check(ReferenceEquals(image, registry.ReadItemImage(registry.ItemType("ImageTest/AliasItem"))));
        Check(registry.ImageCacheResidentBytes == 8);
        var packet = registry.PrepareItemTexture(registry.ItemType("ImageTest/IconItem"));
        var decoded = MobileTexturePacket.Decode(packet.Encode(), "ImageTest/Images/Icon.rawimg",
            registry.ContentGeneration, resourceArchive.Sha256);
        Check(decoded.Width == 2 && decoded.Height == 1 && decoded.Generation == registry.ContentGeneration);
        var binding = registry.PrepareItemTextureBinding(registry.ItemType("ImageTest/IconItem"));
        binding.ValidateOwner(); Check(binding.Item == "ImageTest/IconItem" && binding.ItemType == registry.ItemType(binding.Item));
        Check(binding.Generation == registry.ContentGeneration && binding.ArchiveSha256 == resourceArchive.Sha256);
        Check(binding.Asset == "ImageTest/Images/Icon.rawimg" && binding.Width == 2 && binding.Height == 1);
        Check(binding.PngSha256 == Convert.ToHexString(SHA256.HashData(decoded.CopyPng())).ToLowerInvariant());
        using (var plan = JsonDocument.Parse(binding.PlanJson()))
        {
            Check(plan.RootElement.GetProperty("generation").GetString() == registry.ContentGeneration.ToString("D"));
            Check(plan.RootElement.GetProperty("itemType").GetInt32() == binding.ItemType &&
                plan.RootElement.GetProperty("pngSha256").GetString() == binding.PngSha256);
        }
        var copy = binding.CopyPacket(); copy[0] ^= 1;
        Check(binding.CopyPacket()[0] == 84);
        Check(MobileTexturePacket.Decode(binding.CopyPacket(), binding.Asset, binding.Generation, binding.ArchiveSha256).Width == 2);
        Reject<ArgumentNullException>(() => registry.ValidateTextureBinding(null));
        var transfer = registry.BeginTextureTransfer(binding);
        Check(registry.PendingTextureTransferCount == 1 && !transfer.IsComplete);
        Check(transfer.CopyPacket().Length == binding.CopyPacket().Length);
        using (var transferPlan = JsonDocument.Parse(transfer.PlanJson()))
            Check(transferPlan.RootElement.GetProperty("transferId").GetString() == transfer.TransferId.ToString("D"));
        Reject<InvalidOperationException>(() => registry.BeginTextureTransfer(binding));
        Reject<InvalidOperationException>(() => registry.Dispose());
        binding.ValidateOwner(); Check(registry.ImageCacheResidentBytes == 8 && registry.PendingTextureTransferCount == 1);
        Reject<ArgumentException>(() => transfer.CompleteNativeTeardown(Guid.NewGuid()));
        transfer.CompleteNativeTeardown(transfer.TransferId);
        Check(transfer.IsComplete && registry.PendingTextureTransferCount == 0);
        Reject<InvalidOperationException>(() => transfer.PlanJson());
        Reject<InvalidOperationException>(() => transfer.CopyPacket());
        Reject<InvalidOperationException>(() => transfer.CompleteNativeTeardown(transfer.TransferId));
        var nextTransfer = registry.BeginTextureTransfer(binding);
        Reject<InvalidOperationException>(() => transfer.CompleteNativeTeardown(transfer.TransferId));
        Check(registry.PendingTextureTransferCount == 1 && nextTransfer.TransferId != transfer.TransferId);
        Reject<ArgumentException>(() => nextTransfer.CompleteNativeTeardown(transfer.TransferId));
        nextTransfer.CompleteNativeTeardown(nextTransfer.TransferId);
        Check(registry.PendingTextureTransferCount == 0);
        using (var next = new MobileContentRegistry())
        {
            Check(next.ContentGeneration != registry.ContentGeneration);
            Reject<InvalidDataException>(() => MobileTexturePacket.Decode(packet.Encode(), packet.Asset,
                next.ContentGeneration, resourceArchive.Sha256));
            next.Add(new ImageMod(), new[] { typeof(IconItem) }, Archive()); next.Initialize(6196);
            Reject<ArgumentException>(() => next.ValidateTextureBinding(binding));
        }
        var mutableBinding = registry.PrepareItemTextureBinding(registry.ItemType("ImageTest/MutableItem"));
        var mutableTransfer = registry.BeginTextureTransfer(mutableBinding);
        try
        {
            MutableItem.Resource = "Images/Other";
            Reject<InvalidOperationException>(() => mutableBinding.ValidateOwner());
            Reject<InvalidOperationException>(() => mutableBinding.CopyPacket());
            Reject<InvalidOperationException>(() => mutableTransfer.PlanJson());
            // A changed resource cannot prevent the release acknowledgement.
            mutableTransfer.CompleteNativeTeardown(mutableTransfer.TransferId);
            Check(registry.PendingTextureTransferCount == 0);
        }
        finally { MutableItem.Resource = "Images/Icon"; }
        Reject<FileNotFoundException>(() => registry.ReadItemImage(registry.ItemType("ImageTest/MissingItem")));
        Reject<ArgumentException>(() => registry.ReadItemImage(registry.ItemType("ImageTest/UnsafePathItem")));
        Reject<NotSupportedException>(() => registry.ReadItemImage(registry.ItemType("ImageTest/VanillaAliasItem")));
        Reject<System.Collections.Generic.KeyNotFoundException>(() => registry.ReadItemImage(1));
        Check(registry.ImageCacheResidentBytes == 8);
        var cross = registry.ReadItemImage(registry.ItemType("ImageTest/CrossModItem"));
        Check(cross.CopyRgba()[0] == 55 && image.CopyRgba()[0] == 1);
        var crossBinding = registry.PrepareItemTextureBinding(registry.ItemType("ImageTest/CrossModItem"));
        Check(crossBinding.Item == "ImageTest/CrossModItem" && crossBinding.Asset == "Provider/Images/Icon.rawimg" &&
            crossBinding.ArchiveSha256 != resourceArchive.Sha256);
        Check(registry.ImageCacheResidentBytes == 8);
        registry.Dispose(); Check(registry.ImageCacheResidentBytes == 0);
        Reject<InvalidOperationException>(() => registry.ReadItemImage(6196));
        Reject<InvalidOperationException>(() => registry.PrepareItemTexture(6196));
        Reject<InvalidOperationException>(() => binding.ValidateOwner());
        Reject<InvalidOperationException>(() => binding.CopyPacket());
        Reject<InvalidOperationException>(() => binding.PlanJson());
        Check(image.CopyRgba()[7] == 127);
        var failing = new MobileContentRegistry();
        failing.Add(new FailingUnloadMod(), new[] { typeof(IconItem) }, Archive()); failing.Initialize(7000);
        failing.ReadItemImage(7000); Check(failing.ImageCacheResidentBytes == 8);
        var failedUnloadBinding = failing.PrepareItemTextureBinding(7000);
        Reject<AggregateException>(() => failing.Dispose());
        Check(failing.ImageCacheResidentBytes == 0); failing.Dispose();
        Reject<InvalidOperationException>(() => failedUnloadBinding.ValidateOwner());
        using (var oversized = new MobileContentRegistry())
        {
            oversized.Add(new ImageMod(), new[] { typeof(IconItem) }, Archive(width: 257)); oversized.Initialize(6196);
            Reject<NotSupportedException>(() => oversized.PrepareItemTextureBinding(6196));
        }
        Console.WriteLine("PASS " + checks + " registry image/resource/lifecycle checks; CPU only");
    }
    sealed class ImageMod : Mod { public override string Name => "ImageTest"; }
    sealed class FailingUnloadMod : Mod
    {
        public override string Name => "ImageTest";
        public override void Unload() => throw new InvalidOperationException("Own fixture unload failure");
    }
    sealed class ProviderMod : Mod { public override string Name => "Provider"; }
    sealed class IconItem : ModItem { public override string Texture => "ImageTest/Images/Icon"; }
    sealed class AliasItem : ModItem { public override string Texture => "ImageTest/Images\\Icon"; }
    sealed class MissingItem : ModItem { public override string Texture => "ImageTest/Images/Missing"; }
    sealed class UnsafePathItem : ModItem { public override string Texture => "ImageTest/../Icon"; }
    sealed class VanillaAliasItem : ModItem { public override string Texture => "Terraria/Images/Item_3507"; }
    sealed class CrossModItem : ModItem { public override string Texture => "Provider/Images/Icon"; }
    sealed class MutableItem : ModItem
    {
        public static string Resource = "Images/Icon";
        public override string Texture => "ImageTest/" + Resource;
    }
}
