using System;
using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text;
using System.IO.Compression;
using TerrariaMobile.Serialization;

static class RawImageTests
{
    static int checks;
    static void Check(bool value) { if (!value) throw new Exception("Image contract differs"); checks++; }
    static byte[] Image(int version, int w, int h, byte[] pixels)
    {
        var bytes = new byte[12 + pixels.Length];
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(0), version);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(4), w);
        BinaryPrimitives.WriteInt32LittleEndian(bytes.AsSpan(8), h);
        pixels.CopyTo(bytes, 12); return bytes;
    }
    static void Reject(Action action)
    {
        try { action(); } catch (InvalidDataException) { checks++; return; }
        throw new Exception("Malformed image accepted");
    }
    static MobileTmodArchive Archive(string entry, byte[] raw, int declared = -1)
    {
        using var compressed = new MemoryStream();
        using (var z = new DeflateStream(compressed, CompressionLevel.SmallestSize, true)) z.Write(raw);
        var stored = compressed.ToArray();
        using var payload = new MemoryStream();
        using (var w = new BinaryWriter(payload, Encoding.UTF8, true))
        {
            w.Write("ImageTest"); w.Write("1.0"); w.Write(1); w.Write(entry);
            w.Write(declared < 0 ? raw.Length : declared); w.Write(stored.Length); w.Write(stored);
        }
        var data = payload.ToArray();
        using var envelope = new MemoryStream();
        using (var w = new BinaryWriter(envelope, Encoding.UTF8, true))
        {
            w.Write(new byte[] { 84, 77, 79, 68 }); w.Write("2026.5.3.0");
            w.Write(SHA1.HashData(data)); w.Write(new byte[256]); w.Write(data.Length); w.Write(data);
        }
        return MobileTmodArchive.FromBytes(envelope.ToArray());
    }
    public static void Main(string[] args)
    {
        byte[] rgba = { 1, 2, 3, 255, 40, 50, 60, 127, 7, 8, 9, 0, 9, 8, 7, 1 };
        var input = Image(1, 2, 2, rgba);
        var image = MobileRawImage.Decode(input);
        Check(image.Width == 2 && image.Height == 2 && image.PixelByteCount == 16);
        Check(Convert.ToHexString(image.CopyRgba()) == Convert.ToHexString(rgba));
        input[12] = 99; var copy = image.CopyRgba(); copy[1] = 99;
        Check(image.CopyRgba()[0] == 1 && image.CopyRgba()[1] == 2);
        Reject(() => MobileRawImage.Decode(new byte[11]));
        Reject(() => MobileRawImage.Decode(Image(2, 2, 2, rgba)));
        Reject(() => MobileRawImage.Decode(Image(1, 0, 2, rgba)));
        Reject(() => MobileRawImage.Decode(Image(1, -1, 2, rgba)));
        Reject(() => MobileRawImage.Decode(Image(1, int.MaxValue, int.MaxValue, rgba)));
        Reject(() => MobileRawImage.Decode(Image(1, 8193, 1, rgba)));
        Reject(() => MobileRawImage.Decode(Image(1, 2, 2, new byte[15])));
        Reject(() => MobileRawImage.Decode(Image(1, 2, 2, new byte[17])));
        Reject(() => MobileRawImage.Decode(Image(1, 2, 2, rgba), maxPixelBytes: 15));
        var archive = Archive("Images/Test.rawimg", Image(1, 2, 2, rgba));
        var fromArchive = MobileRawImage.FromArchive(archive, "Images/Test.rawimg");
        Check(Convert.ToHexString(fromArchive.CopyRgba()) == Convert.ToHexString(rgba));
        Reject(() => MobileRawImage.FromArchive(archive, "Images/Test.rawimg", maxPixelBytes: 15));
        // Declared expansion is rejected before attempting to decompress inconsistent bytes.
        var oversized = Archive("Images/Large.rawimg", new byte[] { 0 }, declared: 1024 * 1024);
        try { MobileRawImage.FromArchive(oversized, "Images/Large.rawimg", maxPixelBytes: 128); throw new Exception("Budget bypassed"); }
        catch (InvalidDataException e) { Check(e.Message.Contains("caller budget")); }
        try { MobileRawImage.FromArchive(archive, "Missing.rawimg"); throw new Exception("Missing asset accepted"); }
        catch (FileNotFoundException) { checks++; }
        try { MobileRawImage.FromArchive(archive, "Images/Test.png"); throw new Exception("Wrong format accepted"); }
        catch (ArgumentException) { checks++; }
        var secondPixels = (byte[])rgba.Clone(); secondPixels[0] = 33;
        var thirdPixels = (byte[])rgba.Clone(); thirdPixels[0] = 44;
        var secondArchive = Archive("Images/Test.rawimg", Image(1, 2, 2, secondPixels));
        var thirdArchive = Archive("Images/Test.rawimg", Image(1, 2, 2, thirdPixels));
        using (var cache = new MobileRawImageCache(maxResidentBytes: 32))
        {
            var first = cache.Get(archive, "Images/Test.rawimg");
            var second = cache.Get(secondArchive, "Images/Test.rawimg");
            Check(first.CopyRgba()[0] == 1 && second.CopyRgba()[0] == 33);
            Check(ReferenceEquals(first, cache.Get(archive, "Images\\Test.rawimg")));
            var third = cache.Get(thirdArchive, "Images/Test.rawimg");
            Check(cache.Count == 2 && cache.ResidentBytes == 32 && third.CopyRgba()[0] == 44);
            Check(ReferenceEquals(first, cache.Get(archive, "Images/Test.rawimg")));
            Check(!ReferenceEquals(second, cache.Get(secondArchive, "Images/Test.rawimg")));
            Reject(() => cache.Get(oversized, "Images/Large.rawimg"));
            Check(cache.Count == 2 && cache.ResidentBytes == 32);
            cache.Clear(); Check(cache.Count == 0 && cache.ResidentBytes == 0);
            Check(first.CopyRgba()[0] == 1); // Eviction/clear never invalidates client-owned data.
            cache.Dispose();
            try { cache.Get(archive, "Images/Test.rawimg"); throw new Exception("Disposed cache used"); }
            catch (ObjectDisposedException) { checks++; }
        }
        Console.WriteLine("PASS raw image parser: " + checks + " bounds/channel/ownership checks");
        if (args.Length is >= 1 and <= 3)
        {
            var sourceArchive = args.Length > 1 ? MobileTmodArchive.FromFile(args[0]) : null;
            var original = args.Length == 1 ? MobileRawImage.Decode(File.ReadAllBytes(args[0])) :
                MobileRawImage.FromArchive(sourceArchive, args[1]);
            if (args.Length == 3)
            {
                File.WriteAllBytes(args[2], original.EncodePng());
                File.WriteAllBytes(args[2] + ".fixture.png", image.EncodePng());
                var packet = MobileTexturePacket.Create(sourceArchive.Name + "/" + args[1].Replace('\\', '/'),
                    Guid.Parse("13fb5666-8cf1-4941-acf8-8d54eff30d10"), sourceArchive.Sha256, original);
                var frame = packet.Encode();
                var received = MobileTexturePacket.Decode(frame, packet.Asset, packet.Generation, sourceArchive.Sha256);
                Check(Convert.ToHexString(received.CopyPng()) == Convert.ToHexString(packet.CopyPng()));
                File.WriteAllBytes(args[2] + ".tmit", frame);
            }
            Console.WriteLine(JsonSerializer.Serialize(new { width = original.Width, height = original.Height,
                bytes = original.PixelByteCount, rgba_sha256 = Convert.ToHexString(SHA256.HashData(original.CopyRgba())).ToLowerInvariant(),
                packet_checked = args.Length == 3, graphics_created = false, android_verified = false }));
        }
    }
}
