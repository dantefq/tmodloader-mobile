extern alias ReferenceCombat;
using System;
using Terraria;
using Terraria.ModLoader;
using Ref = ReferenceCombat::Terraria.ModLoader;
using RefNpc = ReferenceCombat::Terraria.NPC;

static class NpcHitConformance
{
    static int checks;
    static void Same(float ours, float reference, string message)
    {
        if (float.IsNaN(ours) != float.IsNaN(reference) || (!float.IsNaN(ours) && Math.Abs(ours - reference) > 0.00001f))
            throw new Exception(message + $": {ours} != {reference}");
        checks++;
    }
    static void Same(bool ours, bool reference, string message)
    {
        if (ours != reference) throw new Exception(message);
        checks++;
    }
    public static void Run()
    {
        var random = new Random(18355);
        float Next() => (float)(random.NextDouble() * 4 - 1);
        for (int iteration = 0; iteration < 128; iteration++)
        {
            var source = new StatModifier(Next(), Next(), Next(), Next());
            var defense = new StatModifier(Next(), Next(), Next(), Next() * 20);
            var final = new StatModifier(Next(), Next(), Next(), Next());
            var critical = new StatModifier(Next(), Next(), Next(), Next());
            var noncritical = new StatModifier(Next(), Next(), Next(), Next());
            var knockback = new StatModifier(Next(), Next(), Next(), Next());
            Ref.StatModifier Convert(StatModifier value) => new(value.Additive, value.Multiplicative, value.Flat, value.Base);
            for (int mode = 0; mode < 8; mode++)
            {
                var a = new NPC.HitModifiers { DamageType = DamageClass.Magic, HitDirection = -1, SuperArmor = mode == 6,
                    SourceDamage = source, Defense = defense, FinalDamage = final,
                    CritDamage = critical, NonCritDamage = noncritical, Knockback = knockback };
                var b = new RefNpc.HitModifiers { DamageType = Ref.DamageClass.Magic, HitDirection = -1, SuperArmor = mode == 6,
                    SourceDamage = Convert(source), Defense = Convert(defense), FinalDamage = Convert(final),
                    CritDamage = Convert(critical), NonCritDamage = Convert(noncritical), Knockback = Convert(knockback) };
                float flat = Next(), scaling = Next(), target = Next(), armor = Next() * 10, scalingArmor = Next(), effectiveness = Next();
                a.FlatBonusDamage += flat; b.FlatBonusDamage += flat;
                a.ScalingBonusDamage += scaling; b.ScalingBonusDamage += scaling;
                a.TargetDamageMultiplier *= target; b.TargetDamageMultiplier *= target;
                a.ArmorPenetration += armor; b.ArmorPenetration += armor;
                a.ScalingArmorPenetration += scalingArmor; b.ScalingArmorPenetration += scalingArmor;
                a.DefenseEffectiveness *= effectiveness; b.DefenseEffectiveness *= effectiveness;
                // Only deterministic damage is in scope. Spread zero also checks the
                // damageVariation=true branch without substituting game random values.
                a.DamageVariationScale *= 0; b.DamageVariationScale *= 0;
                if (mode == 1) { a.SetCrit(); b.SetCrit(); }
                if (mode == 2) { a.SetCrit(); a.DisableCrit(); a.SetCrit(); b.SetCrit(); b.DisableCrit(); b.SetCrit(); }
                if (mode == 3) { a.SetMaxDamage(17); a.SetMaxDamage(30); b.SetMaxDamage(17); b.SetMaxDamage(30); }
                if (mode == 4) { a.DisableKnockback(); b.DisableKnockback(); }
                if (mode == 5) { a.SetInstantKill(); b.SetInstantKill(); }
                if (mode == 7) { a.SetMaxDamage(0); b.SetMaxDamage(0); }
                a.HideCombatText(); b.HideCombatText();
                a.HitDirectionOverride = 1; b.HitDirectionOverride = 1;
                float damage = Next() * 100, force = Next() * 10;
                bool crit = iteration % 2 == 0;
                Same(a.GetDamage(damage, crit, true), b.GetDamage(damage, crit, true), "Deterministic damage calculation");
                Same(a.GetKnockback(force), b.GetKnockback(force), "Knockback calculation");
                a.ModifyHitInfo += (ref NPC.HitInfo info) => { info.SourceDamage += 3; info.Damage += 2; };
                b.ModifyHitInfo += (ref RefNpc.HitInfo info) => { info.SourceDamage += 3; info.Damage += 2; };
                Compare(a.ToHitInfo(damage, crit, force, true), b.ToHitInfo(damage, crit, force, true));
                Compare(a.ToHitInfo(damage, crit, force, true), b.ToHitInfo(damage, crit, force, true));
            }
        }
        Console.WriteLine($"PASS {checks} upstream NPC hit comparisons; RNG/native combat excluded");
    }
    static void Compare(NPC.HitInfo a, RefNpc.HitInfo b)
    {
        Same(a.SourceDamage, b.SourceDamage, "Source damage"); Same(a.Damage, b.Damage, "Final damage");
        Same(a.Crit, b.Crit, "Crit flag"); Same(a.HitDirection, b.HitDirection, "Direction");
        Same(a.Knockback, b.Knockback, "Knockback"); Same(a.InstantKill, b.InstantKill, "Instant kill flag");
        Same(a.HideCombatText, b.HideCombatText, "Combat text flag");
        Same(a.DamageType.Type, b.DamageType.Type, "Damage class");
    }
}
