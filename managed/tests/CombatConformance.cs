extern alias ReferenceCombat;
using System;
using Terraria;
using Terraria.ModLoader;
using TerrariaMobile.Managed;
using Ref = ReferenceCombat::Terraria.ModLoader;
using RefPlayer = ReferenceCombat::Terraria.Player;

static class CombatConformance
{
    static int checks;
    static void Same(float actual, float reference, string message)
    {
        if (float.IsNaN(actual) != float.IsNaN(reference) || (!float.IsNaN(actual) && Math.Abs(actual - reference) > 0.00001f))
            throw new Exception(message + $": {actual} != {reference}");
        checks++;
    }
    static void Same(bool actual, bool reference, string message)
    {
        if (actual != reference) throw new Exception(message);
        checks++;
    }
    static void Same(StatModifier actual, Ref.StatModifier reference, string message)
    {
        Same(actual.Additive, reference.Additive, message); Same(actual.Multiplicative, reference.Multiplicative, message);
        Same(actual.Base, reference.Base, message); Same(actual.Flat, reference.Flat, message);
    }
    public static void Main()
    {
        Ref.CombatReferenceHarness.Add(new RefRogue());
        using var registry = new MobileContentRegistry();
        registry.Add(new ConformanceMod(), new[] { typeof(OurRogue), typeof(ConformanceBlade) });
        registry.Initialize(7000);
        var ours = registry.CreatePlayer(); var reference = new RefPlayer();
        var ourRogue = registry.Create(7000).DamageType;
        var random = new Random(54018);
        float Next() => (float)(random.NextDouble() * 4 - 1);
        for (int iteration = 0; iteration < 96; iteration++)
        {
            for (int i = 0; i < 11; i++)
            {
                var a = i == 10 ? ourRogue : DamageClassLoader.GetDamageClass(i);
                var b = Ref.DamageClassLoader.GetDamageClass(i);
                float additive = Next(), multiplier = Next(), flat = Next(), baseValue = Next();
                ours.GetDamage(a) = new(additive, multiplier, flat, baseValue);
                reference.GetDamage(b) = new(additive, multiplier, flat, baseValue);
                additive = Next(); multiplier = Next(); flat = Next(); baseValue = Next();
                ours.GetKnockback(a) = new(additive, multiplier, flat, baseValue);
                reference.GetKnockback(b) = new(additive, multiplier, flat, baseValue);
                ours.GetCritChance(a) = reference.GetCritChance(b) = Next();
                ours.GetAttackSpeed(a) = reference.GetAttackSpeed(b) = Next();
                ours.GetArmorPenetration(a) = reference.GetArmorPenetration(b) = Next();
            }
            for (int i = 0; i < 11; i++)
            {
                var a = i == 10 ? ourRogue : DamageClassLoader.GetDamageClass(i);
                var b = Ref.DamageClassLoader.GetDamageClass(i);
                Same(ours.GetTotalDamage(a), reference.GetTotalDamage(b), "Damage aggregate");
                Same(ours.GetTotalKnockback(a), reference.GetTotalKnockback(b), "Knockback aggregate");
                Same(ours.GetTotalCritChance(a), reference.GetTotalCritChance(b), "Crit aggregate");
                Same(ours.GetTotalAttackSpeed(a), reference.GetTotalAttackSpeed(b), "Speed aggregate");
                Same(ours.GetTotalArmorPenetration(a), reference.GetTotalArmorPenetration(b), "Armor aggregate");
                for (int j = 0; j < 11; j++)
                {
                    var c = j == 10 ? ourRogue : DamageClassLoader.GetDamageClass(j);
                    var d = Ref.DamageClassLoader.GetDamageClass(j);
                    var inheritance = a.GetModifierInheritance(c); var refInheritance = b.GetModifierInheritance(d);
                    Same(inheritance.damageInheritance, refInheritance.damageInheritance, "Damage inheritance");
                    Same(inheritance.critChanceInheritance, refInheritance.critChanceInheritance, "Crit inheritance");
                    Same(inheritance.attackSpeedInheritance, refInheritance.attackSpeedInheritance, "Speed inheritance");
                    Same(inheritance.armorPenInheritance, refInheritance.armorPenInheritance, "Armor inheritance");
                    Same(inheritance.knockbackInheritance, refInheritance.knockbackInheritance, "Knockback inheritance");
                    Same(a.CountsAsClass(c), b.CountsAsClass(d), "Effect classification");
                    Same(a.GetsPrefixesFor(c), b.GetsPrefixesFor(d), "Prefix classification");
                }
                Same(a.UseStandardCritCalcs, b.UseStandardCritCalcs, "Crit policy");
                foreach (var line in new[] { "Damage", "CritChance", "Speed", "Knockback" })
                    Same(a.ShowStatTooltipLine(ours, line), b.ShowStatTooltipLine(reference, line), "Tooltip policy");
            }
        }
        Console.WriteLine($"PASS {checks} upstream combat comparisons; public combat/stat sections with test-only scaffolding");
        NpcHitConformance.Run();
    }
}
sealed class ConformanceMod : Mod { public override string Name => "Conformance"; }
sealed class ConformanceBlade : ModItem
{
    public override void SetDefaults() => Item.DamageType = ModContent.GetInstance<OurRogue>();
}
sealed class OurRogue : DamageClass
{
    public override StatInheritanceData GetModifierInheritance(DamageClass value) => value == Generic ? StatInheritanceData.Full :
        value == Throwing ? new(0.5f, 1, 0, 0.25f, 0.75f) : StatInheritanceData.None;
    public override bool GetEffectInheritance(DamageClass value) => value == Throwing;
    public override bool GetPrefixInheritance(DamageClass value) => value == Ranged;
}
sealed class RefRogue : Ref.DamageClass
{
    public override Ref.StatInheritanceData GetModifierInheritance(Ref.DamageClass value) => value == Generic ? Ref.StatInheritanceData.Full :
        value == Throwing ? new(0.5f, 1, 0, 0.25f, 0.75f) : Ref.StatInheritanceData.None;
    public override bool GetEffectInheritance(Ref.DamageClass value) => value == Throwing;
    public override bool GetPrefixInheritance(Ref.DamageClass value) => value == Ranged;
}
