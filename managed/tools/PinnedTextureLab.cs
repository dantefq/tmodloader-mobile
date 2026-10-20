using System;
using System.IO;
using System.Text;
using System.Reflection;
using System.Security.Cryptography;
using Terraria.ModLoader;
using TerrariaMobile.Managed;
using TerrariaMobile.Serialization;

// Private original texture data only. Never loads an original mod assembly or
// supplies gameplay defaults. The provider/archive/item below are our own lab.
static class PinnedTextureLab
{
    public const string Profile = "sots-helicopterparts";
    public const string RawSha256 = "783e86053ec749c41e1b05e89cca94a09966ff3b40423ca18dd9faf8a9494b05";
    public const int RawBytes = 12 + 44 * 34 * 4;
    public static void ValidateRaw(byte[] raw)
    {
        if (raw == null || raw.Length != RawBytes) throw new InvalidDataException("Pinned texture length differs");
        var image = MobileRawImage.Decode(raw, 256, 256 * 256 * 4);
        if (image.Width != 44 || image.Height != 34 ||
                Convert.ToHexString(SHA256.HashData(raw)).ToLowerInvariant() != RawSha256)
            throw new InvalidDataException("Pinned texture dimensions or digest differ");
    }
    public static MobileContentRegistry Create()
    {
        string root = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        using var input = File.OpenRead(Path.Combine(root, "pinned-icon.rawimg"));
        if (input.Length != RawBytes) throw new InvalidDataException("Private pinned resource size differs");
        var raw = new byte[RawBytes]; input.ReadExactly(raw);
        if (input.ReadByte() != -1) throw new InvalidDataException("Private resource changed during read");
        ValidateRaw(raw);
        using var payload = new MemoryStream();
        using (var writer = new BinaryWriter(payload, Encoding.UTF8, true))
        {
            writer.Write("TextureBindingLab"); writer.Write("1.0"); writer.Write(1);
            writer.Write("Images/SourceIcon.rawimg"); writer.Write(raw.Length); writer.Write(raw.Length); writer.Write(raw);
        }
        byte[] data = payload.ToArray(); using var output = new MemoryStream();
        using (var writer = new BinaryWriter(output, Encoding.UTF8, true))
        {
            writer.Write(new byte[] { 84, 77, 79, 68 }); writer.Write("2026.5.3.0");
            writer.Write(SHA1.HashData(data)); writer.Write(new byte[256]); writer.Write(data.Length); writer.Write(data);
        }
        var registry = new MobileContentRegistry();
        registry.Add(new LabMod(), new[] { typeof(Preview) }, MobileTmodArchive.FromBytes(output.ToArray()));
        registry.Initialize(6196); return registry;
    }
    public static int NegativeChecks()
    {
        int checks = 0;
        void Reject(byte[] raw)
        {
            try { ValidateRaw(raw); }
            catch (InvalidDataException) { checks++; return; }
            throw new Exception("Unpinned raw image accepted");
        }
        byte[] Shape(int version, int width, int height)
        {
            var data = new byte[RawBytes];
            BitConverter.GetBytes(version).CopyTo(data, 0);
            BitConverter.GetBytes(width).CopyTo(data, 4);
            BitConverter.GetBytes(height).CopyTo(data, 8); return data;
        }
        Reject(new byte[12]); Reject(Shape(2, 44, 34));
        Reject(Shape(1, 34, 44)); Reject(Shape(1, 44, 34));
        return checks;
    }
    sealed class LabMod : Mod { public override string Name => "TextureBindingLab"; }
    sealed class Preview : ModItem { public override string Texture => "TextureBindingLab/Images/SourceIcon"; }
}
