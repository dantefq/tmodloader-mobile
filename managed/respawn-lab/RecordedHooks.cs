using System;
using MonoMod.Cil;

namespace Terraria;

// Explicitly records a mod's IL request. Apply only to a caller-supplied private
// Cecil body. This is not a native hook and does not alter a loaded game method.
public static class IL_Player
{
    private static ILContext.Manipulator updateDead;
    public static event ILContext.Manipulator UpdateDead
    {
        add { updateDead += value; }
        remove { updateDead -= value; }
    }
    public static int RecordedCount => updateDead?.GetInvocationList().Length ?? 0;
    public static void ApplyRecorded(ILContext context)
    {
        if (RecordedCount != 1) throw new InvalidOperationException("Expected exactly one UpdateDead request");
        context.Invoke(updateDead);
    }
    public static void ClearRecorded() => updateDead = null;
}
