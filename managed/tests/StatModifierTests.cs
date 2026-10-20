using System;
using Terraria.ModLoader;

static class StatModifierTests
{
    static int checks;
    static void Check(bool value, string message)
    {
        if (!value) throw new Exception(message);
        checks++;
    }
    static bool Near(float actual, float expected) => Math.Abs(actual - expected) <= 0.0001f;
    public static void Run()
    {
        Check(StatModifier.Default.ApplyTo(100) == 100, "Default stat is unchanged");
        Check(new StatModifier().ApplyTo(100) == 100, "Explicit constructor is identity");
        Check(default(StatModifier).ApplyTo(100) == 0, "CLR zero-init remains distinct from explicit default");
        var additive = StatModifier.Default + 0.2f + 0.3f;
        Check(Near(additive.ApplyTo(100), 150), "Percentage boosts add");
        var multiplicative = StatModifier.Default * 1.2f * 1.3f;
        Check(Near(multiplicative.ApplyTo(100), 156), "Rare multiplicative boosts compound");
        var offsets = new StatModifier(1.5f, 2, flat: 7, @base: 3);
        Check(offsets.ApplyTo(10) == 46, "Base offset precedes multipliers and flat follows them");
        Check(Near(offsets.Undo(offsets.ApplyTo(10)), 10), "Undo recovers base stat");
        Check(Near((0.2f + StatModifier.Default).ApplyTo(100), 120), "Reverse additive operator");
        Check((2f * StatModifier.Default).ApplyTo(100) == 200, "Reverse multiplicative operator");
        Check(Near((additive - 0.5f).ApplyTo(100), 100), "Subtractive modifier");
        Check((offsets / 2).ApplyTo(10) == 26.5f, "Division only affects multiplicative component");
        var combined = new StatModifier(1.2f, 2, 3, 4).CombineWith(new StatModifier(1.3f, 3, 4, 5));
        Check(Near(combined.ApplyTo(10), 178), "Combined stat preserves all components");
        Check(offsets.Scale(0) == StatModifier.Default && offsets.Scale(1) == offsets, "Inheritance endpoints");
        Check(offsets.Scale(0.5f).ApplyTo(10) == 25.0625f, "Partial inheritance scales each component");
        Check(offsets.Equals(new StatModifier(1.5f, 2, 7, 3)) && offsets != StatModifier.Default, "Value equality");
        Check(offsets.GetHashCode() == new StatModifier(1.5f, 2, 7, 3).GetHashCode(), "Equal values hash equally");
        Check(!float.IsFinite((StatModifier.Default / 0).ApplyTo(10)), "IEEE division behavior is preserved");
        Check(StatInheritanceData.Full.damageInheritance == 1 && StatInheritanceData.Full.knockbackInheritance == 1,
              "Full damage inheritance");
        Check(StatInheritanceData.None.critChanceInheritance == 0 && new StatInheritanceData().attackSpeedInheritance == 0,
              "Empty inheritance is zero");
        var inheritance = new StatInheritanceData(0.5f, 0.25f, 0.75f, 0.125f, 0.875f);
        Check(inheritance.armorPenInheritance == 0.125f && inheritance.knockbackInheritance == 0.875f,
              "Independent inheritance channels");
        Check(new MultipliableFloat().Value == 1 && default(MultipliableFloat).Value == 0,
              "Multipliable explicit default is identity");
        Check(((MultipliableFloat.One * 2) * (MultipliableFloat.One * 3)).Value == 6,
              "Typed multiplicative modifiers");
        Check((MultipliableFloat.One * 6 / 2).Value == 3, "Typed multiplier division");
        Check(((AddableFloat.Zero + 2) + (AddableFloat.Zero + 3)).Value == 5, "Typed additive accumulation");
        Check(new AddableFloat().Value == 0 && AddableFloat.Zero.Value == 0, "Typed additive zero");
        Console.WriteLine($"PASS {checks} stat modifier checks; no game or Android device used");
    }
}
