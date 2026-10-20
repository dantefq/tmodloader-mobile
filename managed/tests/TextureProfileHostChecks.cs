using System;
using System.IO;
using System.Text.Json;
using System.Security.Cryptography;
using TerrariaMobile.TextureLab;
using TerrariaMobile.Serialization;

// Host CLR checks against the exact own Android probe assembly. Outputs private.
static class TextureProfileHostChecks
{
    static int checks;
    static void Check(bool value) { if (!value) throw new Exception("Pinned profile host check " + checks); checks++; }
    static JsonDocument Send(object value) => JsonDocument.Parse(AndroidTextureProbeHost.Request(JsonSerializer.Serialize(value)));
    static int Main()
    {
        using (var early = Send(new { operation = "begin" })) Check(early.RootElement.GetProperty("error").GetString() == "InvalidOperationException");
        using (var invalid = Send(new { operation = "initialize", profile = "unknown" })) Check(invalid.RootElement.GetProperty("error").GetString() == "ArgumentException");
        using var ready = Send(new { operation = "initialize", profile = "sots-helicopterparts" });
        Check(ready.RootElement.GetProperty("profile").GetString() == "sots-helicopterparts");
        Check(ready.RootElement.GetProperty("profileChecks").GetInt32() == 4);
        Check(!ready.RootElement.GetProperty("originalModCodeExecuted").GetBoolean());
        string generation = ready.RootElement.GetProperty("generation").GetString();
        string export = AndroidTextureProbeHost.Request("{\"operation\":\"begin\"}");
        using var exported = JsonDocument.Parse(export); var plan = exported.RootElement.GetProperty("plan");
        Check(plan.GetProperty("generation").GetString() == generation);
        Check(plan.GetProperty("item").GetString() == "TextureBindingLab/Preview");
        Check(plan.GetProperty("width").GetInt32() == 44 && plan.GetProperty("height").GetInt32() == 34);
        byte[] packet = Convert.FromBase64String(exported.RootElement.GetProperty("packetBase64").GetString());
        var decoded = MobileTexturePacket.Decode(packet, plan.GetProperty("asset").GetString(), Guid.Parse(generation), plan.GetProperty("archiveSha256").GetString());
        Check(decoded.Width == 44 && decoded.Height == 34);
        string transferId = plan.GetProperty("transferId").GetString();
        using (var blocked = Send(new { operation = "unload" })) Check(blocked.RootElement.GetProperty("error").GetString() == "InvalidOperationException");
        using (var wrong = Send(new { operation = "ack", transferId = Guid.Empty.ToString("D") })) Check(wrong.RootElement.GetProperty("error").GetString() == "ArgumentException");
        using (var gc = Send(new { operation = "gc" })) Check(gc.RootElement.GetProperty("bytes").GetInt32() == 16777216);
        Check(AndroidTextureProbeHost.Request(JsonSerializer.Serialize(new { operation = "read", transferId })) == export);
        // No native resources were created here; this acknowledgement is simulated.
        using (var ack = Send(new { operation = "ack", transferId })) Check(ack.RootElement.GetProperty("pending").GetInt32() == 0);
        using (var unloaded = Send(new { operation = "unload" }))
        {
            Check(unloaded.RootElement.GetProperty("hostChecks").GetInt32() == 29);
            Check(unloaded.RootElement.GetProperty("pending").GetInt32() == 0 && unloaded.RootElement.GetProperty("cacheBytes").GetInt32() == 0);
        }
        using (var stale = Send(new { operation = "read", transferId })) Check(stale.RootElement.GetProperty("error").GetString() == "InvalidOperationException");
        string root = AppContext.BaseDirectory;
        File.WriteAllText(Path.Combine(root, "host-export.json"), export);
        var result = new { status = "passed", checks, native_graphics_executed = false, native_ack_simulated = true,
            original_mod_code_executed = false, packet_sha256 = Convert.ToHexString(SHA256.HashData(packet)).ToLowerInvariant() };
        File.WriteAllText(Path.Combine(root, "host-result.json"), JsonSerializer.Serialize(result));
        Console.WriteLine(JsonSerializer.Serialize(result)); return 0;
    }
}
