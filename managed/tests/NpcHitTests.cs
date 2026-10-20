using System;
using Terraria;
using Terraria.ModLoader;

static class NpcHitTests
{
    static int checks;
    static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
        checks++;
    }
    static void Reject<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { checks++; return; }
        throw new Exception("Expected " + typeof(T));
    }
    public static void Run()
    {
        var hit = new NPC.HitInfo();
        Check(hit.Damage == 1 && hit.SourceDamage == 1 && hit.DamageType == DamageClass.Default, "HitInfo constructor defaults");
        Check(default(NPC.HitInfo).Damage == 0 && default(NPC.HitInfo).DamageType == null, "Zero-init differs from explicit constructor");
        hit.Damage = -9; hit.SourceDamage = 0;
        Check(hit.Damage == 1 && hit.SourceDamage == 1, "HitInfo setter floor");
        var modifiers = new NPC.HitModifiers { DamageType = DamageClass.Melee, HitDirection = -1 };
        Check(modifiers.GetDamage(100, false) == 100 && modifiers.GetDamage(100, true) == 200, "Neutral and critical defaults");
        Check(modifiers.GetDamage(0, false) == 1 && modifiers.GetKnockback(-2) == 0, "Damage and knockback floors");
        modifiers.Defense.Base = 40;
        Check(modifiers.GetDamage(100, false) == 80, "Base defense effectiveness");
        modifiers.ArmorPenetration += 10;
        modifiers.ScalingArmorPenetration += 0.25f;
        Check(modifiers.GetDamage(100, false) == 90, "Flat and scaling armor penetration");
        modifiers.ScalingArmorPenetration += 2;
        Check(modifiers.GetDamage(100, false) == 100, "Scaling armor penetration clamps at one");
        modifiers.ScalingArmorPenetration += -5;
        Check(modifiers.GetDamage(100, false) == 85, "Scaling penetration clamps at zero");
        modifiers.SourceDamage *= 2;
        modifiers.FlatBonusDamage += 10;
        modifiers.ScalingBonusDamage += 0.5f;
        modifiers.TargetDamageMultiplier *= 0.5f;
        modifiers.FinalDamage.Flat = 7;
        Check(modifiers.GetDamage(100, false) == 147, "Damage order: source/bonus/target/defense/final");
        hit = modifiers.ToHitInfo(100, false, 3);
        Check(hit.SourceDamage == 200 && hit.Damage == 147 && hit.DamageType == DamageClass.Melee && hit.HitDirection == -1,
            "SourceDamage excludes bonus/defense/final modifiers");
        modifiers.SetMaxDamage(20); modifiers.SetMaxDamage(40);
        Check(modifiers.GetDamage(100, true) == 20, "Damage limits only tighten");
        modifiers.SetMaxDamage(-10);
        Check(modifiers.GetDamage(100, true) == 1, "Damage limit lower bound");
        modifiers = new NPC.HitModifiers(); modifiers.SetCrit(); modifiers.DisableCrit(); modifiers.SetCrit();
        Check(!modifiers.ToHitInfo(100, true, 1).Crit && modifiers.GetDamage(100, true) == 100, "DisableCrit takes priority over SetCrit");
        modifiers = new NPC.HitModifiers(); modifiers.SetCrit();
        Check(modifiers.ToHitInfo(100, false, 1).Crit && modifiers.GetDamage(100, false) == 200, "Forced crit");
        modifiers.DisableKnockback(); modifiers.Knockback.Flat = 99;
        Check(modifiers.GetKnockback(4) == 0, "Disable knockback priority");
        modifiers = new NPC.HitModifiers { SuperArmor = true };
        modifiers.CritDamage = new(3, 2, 999, 999); modifiers.SourceDamage *= 999;
        Check(modifiers.GetDamage(100, true) == 4 && modifiers.GetDamage(100, false) == 1, "Super armor crit cap ignores base/flat");
        modifiers.SetMaxDamage(2);
        Check(modifiers.GetDamage(100, true) == 2, "Super armor respects damage limit");
        // Super armor does not need a random draw.
        Check(modifiers.GetDamage(100, true, true) == 2, "Super armor bypasses variation");
        modifiers = new NPC.HitModifiers { HitDirection = 1, HitDirectionOverride = -1 };
        modifiers.SetInstantKill(); modifiers.HideCombatText();
        hit = modifiers.ToHitInfo(100, false, 1, true);
        Check(hit.Damage == 1 && hit.InstantKill && hit.HideCombatText && hit.HitDirection == -1, "Instant kill bypasses damage calculation and keeps flags");
        modifiers = new NPC.HitModifiers();
        int calls = 0;
        modifiers.ModifyHitInfo += (ref NPC.HitInfo info) => { calls++; info.Damage = 19; };
        modifiers.ModifyHitInfo += (ref NPC.HitInfo info) => { calls++; info.Damage += 2; };
        Check(modifiers.ToHitInfo(100, false, 1).Damage == 21 && calls == 2, "HitInfo delegates ordered with ref mutation");
        Check(modifiers.ToHitInfo(100, false, 1).Damage == 100 && calls == 2, "HitInfo callbacks consumed after successful conversion");
        modifiers.ModifyHitInfo += (ref NPC.HitInfo info) => throw new ApplicationException("callback failure");
        Reject<ApplicationException>(() => modifiers.ToHitInfo(100, false, 1));
        Reject<ApplicationException>(() => modifiers.ToHitInfo(100, false, 1));
        modifiers = new NPC.HitModifiers();
        Reject<NotSupportedException>(() => modifiers.GetDamage(100, false, true));
        Reject<NotSupportedException>(() => modifiers.ToHitInfo(100, false, 1, true));
        modifiers.DamageVariationScale *= 0;
        Check(modifiers.GetDamage(100, false, true) == 100, "Zero spread needs no RNG");
        Console.WriteLine($"PASS {checks} NPC hit checks; numerical contracts only, no Android device used");
    }
}
