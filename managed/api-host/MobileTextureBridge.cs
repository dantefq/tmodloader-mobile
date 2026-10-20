using System;
using System.Text.Json;

namespace TerrariaMobile.Managed;

// Bounded, single-flight exports for a trusted native backend. Every other user
// of this registry must use the SAME gate. This does not infer GPU completion.
public sealed class MobileTextureBridge
{
    public const int MaxExportChars = 94208;
    private readonly MobileContentRegistry registry;
    private readonly object gate;
    private MobileTextureTransfer active;
    public MobileTextureBridge(MobileContentRegistry owner, object synchronizationGate)
    {
        registry = owner ?? throw new ArgumentNullException(nameof(owner));
        gate = synchronizationGate ?? throw new ArgumentNullException(nameof(synchronizationGate));
    }
    public string Describe()
    {
        lock (gate)
        {
            registry.ValidateActive();
            return JsonSerializer.Serialize(new { format = "tmal-texture-bridge-v1", generation = registry.ContentGeneration,
                pending = active == null ? 0 : 1 });
        }
    }
    public string BeginItem(int itemType)
    {
        lock (gate)
        {
            registry.ValidateActive();
            if (active != null) throw new InvalidOperationException("A texture export is already pending");
            var next = registry.BeginTextureTransfer(registry.PrepareItemTextureBinding(itemType));
            try
            {
                string result = Export(next);
                active = next;
                return result;
            }
            catch
            {
                // Nothing has escaped to the native caller, so there cannot yet
                // be a native resource or reference belonging to this request.
                next.CompleteNativeTeardown(next.TransferId);
                throw;
            }
        }
    }
    private static Guid Token(string value)
    {
        if (!Guid.TryParseExact(value, "D", out var token) || token == Guid.Empty || token.ToString("D") != value)
            throw new ArgumentException("Canonical nonzero transfer ID required");
        return token;
    }
    private MobileTextureTransfer Find(string transferId)
    {
        var token = Token(transferId);
        if (active == null || active.TransferId != token)
            throw new InvalidOperationException("Texture export does not belong to the active transfer");
        return active;
    }
    private static string Export(MobileTextureTransfer transfer)
    {
        using var plan = JsonDocument.Parse(transfer.PlanJson());
        string result = JsonSerializer.Serialize(new { format = "tmal-texture-export-v1", plan = plan.RootElement,
            packetBase64 = Convert.ToBase64String(transfer.CopyPacket()) });
        if (result.Length > MaxExportChars) throw new NotSupportedException("Texture export exceeds native bridge budget");
        return result;
    }
    public string ReadExport(string transferId)
    {
        lock (gate) return Export(Find(transferId));
    }
    // Only the trusted backend may call this, AFTER native teardown. The ID is
    // correlation, not authentication. A changed texture key must not block it.
    public void CompleteNativeTeardown(string transferId)
    {
        lock (gate)
        {
            var transfer = Find(transferId);
            transfer.CompleteNativeTeardown(transfer.TransferId);
            active = null;
        }
    }
    public void Unload()
    {
        lock (gate) registry.Dispose();
    }
}
