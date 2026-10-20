using System;

namespace TerrariaMobile.Managed;

// Host-side unload barrier. The trusted backend may acknowledge this transfer
// only after native references, observers and graphics resources are released.
// The correlation ID prevents accidental cross-acks; it is not authentication.
public sealed class MobileTextureTransfer
{
    private readonly MobileContentRegistry owner;
    public Guid TransferId { get; } = Guid.NewGuid();
    public MobileItemTextureBinding Binding { get; }
    public bool IsComplete { get; private set; }
    internal MobileTextureTransfer(MobileContentRegistry registry, MobileItemTextureBinding binding)
    { owner = registry; Binding = binding; }
    public string PlanJson() { owner.ValidateTextureTransfer(this); return Binding.PlanJson(TransferId); }
    public byte[] CopyPacket() { owner.ValidateTextureTransfer(this); return Binding.CopyPacket(); }
    public void CompleteNativeTeardown(Guid acknowledgedTransfer)
    {
        if (acknowledgedTransfer != TransferId) throw new ArgumentException("Native teardown acknowledgement belongs to another transfer");
        owner.CompleteTextureTransfer(this); IsComplete = true;
    }
}
