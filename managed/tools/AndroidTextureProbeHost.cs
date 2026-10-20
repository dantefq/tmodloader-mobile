using System;
using System.Text.Json;
using TerrariaMobile.Managed;

// Own mod types; fixed own or hash-pinned private image data. No game/save files.
namespace TerrariaMobile.TextureLab;
public static class AndroidTextureProbeHost
{
    private static readonly object Gate = new();
    private static MobileContentRegistry registry;
    private static MobileTextureBridge bridge;
    private static int hostChecks;
    private static int profileChecks;
    public static string Request(string request)
    {
        try { return Handle(request); }
        catch (Exception error) { return JsonSerializer.Serialize(new { error = error.GetType().Name, message = error.Message }); }
    }
    private static string Handle(string request)
    {
        lock (Gate)
        {
            if (request == null || request.Length > 1024) throw new ArgumentException("Bounded probe request required");
            using var json = JsonDocument.Parse(request);
            string operation = json.RootElement.GetProperty("operation").GetString();
            if (operation == "initialize")
            {
                if (bridge != null) throw new InvalidOperationException("Probe already initialized");
                string profile = json.RootElement.TryGetProperty("profile", out var selected) ? selected.GetString() : "own-2x2";
                if (profile != "own-2x2" && profile != PinnedTextureLab.Profile) throw new ArgumentException("Unknown texture lab profile");
                hostChecks = TextureBridgeChecks.Run();
                profileChecks = PinnedTextureLab.NegativeChecks();
                registry = profile == "own-2x2" ? TextureBridgeChecks.Create() : PinnedTextureLab.Create();
                bridge = new MobileTextureBridge(registry, Gate);
                return JsonSerializer.Serialize(new { format = "tmal-texture-bridge-v1", generation = registry.ContentGeneration,
                    pending = 0, profile, profileChecks, originalModCodeExecuted = false });
            }
            if (bridge == null) throw new InvalidOperationException("Probe not initialized");
            if (operation == "begin") return bridge.BeginItem(6196);
            if (operation == "read") return bridge.ReadExport(json.RootElement.GetProperty("transferId").GetString());
            if (operation == "ack")
            {
                bridge.CompleteNativeTeardown(json.RootElement.GetProperty("transferId").GetString());
                return bridge.Describe();
            }
            if (operation == "unload")
            {
                bridge.Unload();
                return JsonSerializer.Serialize(new { status = "unloaded", hostChecks, profileChecks,
                    pending = registry.PendingTextureTransferCount, cacheBytes = registry.ImageCacheResidentBytes });
            }
            if (operation == "gc")
            {
                int bytes = 0;
                for (int i = 0; i < 2048; i++) { var data = new byte[8192]; data[i % data.Length] = (byte)i; bytes += data.Length; }
                GC.Collect(); GC.WaitForPendingFinalizers();
                return JsonSerializer.Serialize(new { bytes, generation = registry.ContentGeneration });
            }
            throw new ArgumentException("Unknown probe request");
        }
    }
}
