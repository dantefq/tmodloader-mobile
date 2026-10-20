extern alias ReferenceStats;
using System;
using System.Runtime.InteropServices;
using Own = Terraria.ModLoader;
using Reference = ReferenceStats::Terraria.ModLoader;

// Differential test against four pinned public upstream arithmetic sources.
// No game implementation, mod DLL or device is loaded.
static class StatsConformance
{
    static int checks;
    static bool Same(float a, float b) => float.IsNaN(a) && float.IsNaN(b) ||
        BitConverter.SingleToInt32Bits(a) == BitConverter.SingleToInt32Bits(b);
    static void Check(bool value, string message)
    {
        if (!value) throw new Exception(message);
        checks++;
    }
    static void Modifier(Own.StatModifier own, Reference.StatModifier reference)
    {
        Check(Same(own.Additive, reference.Additive) && Same(own.Multiplicative, reference.Multiplicative) &&
              Same(own.Base, reference.Base) && Same(own.Flat, reference.Flat), "Modifier component mismatch");
        Check(own.GetHashCode() == reference.GetHashCode(), "Modifier hash mismatch");
    }
    static int Main()
    {
        Modifier(new Own.StatModifier(), new Reference.StatModifier());
        Modifier(default, default);
        Modifier(Own.StatModifier.Default, Reference.StatModifier.Default);
        Check(Marshal.SizeOf<Own.StatModifier>() == Marshal.SizeOf<Reference.StatModifier>() &&
              Marshal.OffsetOf<Own.StatModifier>("Flat") == Marshal.OffsetOf<Reference.StatModifier>("Flat"),
              "Stat struct layout mismatch");
        var random = new Random(825);
        for (int i = 0; i < 128; i++)
        {
            float additive = (float)random.NextDouble() * 3 + 0.1f;
            float multiplicative = (float)random.NextDouble() * 3 + 0.1f;
            float flat = (float)random.NextDouble() * 20 - 10;
            float baseOffset = (float)random.NextDouble() * 20 - 10;
            float value = (float)random.NextDouble() * 100;
            float scale = (float)random.NextDouble();
            var own = new Own.StatModifier(additive, multiplicative, flat, baseOffset);
            var reference = new Reference.StatModifier(additive, multiplicative, flat, baseOffset);
            Modifier(own, reference);
            Modifier(own + scale, reference + scale); Modifier(own - scale, reference - scale);
            Modifier(own * scale, reference * scale); Modifier(own / scale, reference / scale);
            Modifier(scale + own, scale + reference); Modifier(scale * own, scale * reference);
            Modifier(own.Scale(scale), reference.Scale(scale));
            Modifier(own.CombineWith(new Own.StatModifier(1.2f, 2, 3, 4)),
                     reference.CombineWith(new Reference.StatModifier(1.2f, 2, 3, 4)));
            Check(Same(own.ApplyTo(value), reference.ApplyTo(value)), "ApplyTo mismatch");
            Check(Same(own.Undo(value), reference.Undo(value)), "Undo mismatch");
            Check(Same(((Own.MultipliableFloat.One * value) / 2).Value,
                       ((Reference.MultipliableFloat.One * value) / 2).Value), "Multiplier mismatch");
            Check(Same(((Own.AddableFloat.Zero + value) + (Own.AddableFloat.Zero + scale)).Value,
                       ((Reference.AddableFloat.Zero + value) + (Reference.AddableFloat.Zero + scale)).Value), "Additive wrapper mismatch");
        }
        Check(new Own.MultipliableFloat().Value == new Reference.MultipliableFloat().Value, "Multiplier constructor mismatch");
        Check(Own.StatInheritanceData.Full.damageInheritance == Reference.StatInheritanceData.Full.damageInheritance &&
              Own.StatInheritanceData.None.attackSpeedInheritance == Reference.StatInheritanceData.None.attackSpeedInheritance,
              "Inheritance defaults mismatch");
        Console.WriteLine($"PASS {checks} upstream arithmetic conformance checks; pinned reference sources only");
        return 0;
    }
}
