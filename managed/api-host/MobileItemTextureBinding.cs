using System;
using System.Security.Cryptography;
using System.Text.Json;
using TerrariaMobile.Serialization;

namespace TerrariaMobile.Managed;

// Immutable, owner-bound host request. It contains no native address or file
// path and does not authorize mod execution or install a graphics resource.
public sealed class MobileItemTextureBinding
{
    public const int NativeMaxDimension = 256;
    public const int NativeMaxPngBytes = 64 * 1024;
    private readonly MobileContentRegistry owner;
    private readonly MobileTexturePacket packet;
    public int ItemType { get; }
    public string Item { get; }
    public string Asset => packet.Asset;
    public Guid Generation => packet.Generation;
    public string ArchiveSha256 => packet.ArchiveSha256;
    public string PngSha256 { get; }
    public int Width => packet.Width;
    public int Height => packet.Height;

    internal MobileItemTextureBinding(MobileContentRegistry registry, int itemType, string item, MobileTexturePacket value)
    {
        owner = registry; ItemType = itemType; Item = item;
        if (value.Width > NativeMaxDimension || value.Height > NativeMaxDimension)
            throw new NotSupportedException("Texture exceeds the small native backend dimensions");
        // The load plan's digest is derived only AFTER this managed reader has
        // checked the PNG chunk profile, CRCs and bounded decompressed rows.
        packet = MobileTexturePacket.Decode(value.Encode(), value.Asset, value.Generation, value.ArchiveSha256,
            NativeMaxPngBytes, NativeMaxDimension * NativeMaxDimension * 4);
        PngSha256 = Convert.ToHexString(SHA256.HashData(packet.CopyPng())).ToLowerInvariant();
    }
    internal bool HasOwner(MobileContentRegistry registry) => ReferenceEquals(owner, registry);
    public void ValidateOwner() => owner.ValidateTextureBinding(this);
    public byte[] CopyPacket() { ValidateOwner(); return packet.Encode(); }
    public string PlanJson() => PlanJson(null);
    internal string PlanJson(Guid? transferId)
    {
        ValidateOwner();
        return JsonSerializer.Serialize(new { format = transferId.HasValue ? "tmal-item-texture-transfer-v1" : "tmal-item-texture-binding-v1", itemType = ItemType,
            item = Item, asset = Asset, generation = Generation.ToString("D"), archiveSha256 = ArchiveSha256,
            pngSha256 = PngSha256, width = Width, height = Height, transferId = transferId?.ToString("D") });
    }
}
