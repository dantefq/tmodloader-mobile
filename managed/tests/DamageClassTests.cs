using System;
using System.Collections.Generic;
using Terraria;
using Terraria.ModLoader;
using TerrariaMobile.Managed;

static class DamageClassTests
{
    static int checks;
    static void Check(bool value, string message)
    {
        if (!value) throw new Exception(message);
        checks++;
    }
    static void Near(float actual, float expected, string message) =>
        Check(Math.Abs(actual - expected) < 0.0001f, message + $": {actual} != {expected}");
    static void Reject<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { checks++; return; }
        throw new Exception("Expected " + typeof(T).Name);
    }
    static MobileContentRegistry Registry(bool reverse = false)
    {
        var registry = new MobileContentRegistry();
        registry.Add(new CombatMod(), reverse ? new[] { typeof(ZEffectDamage), typeof(RogueDamage), typeof(RogueBlade) } :
            new[] { typeof(RogueBlade), typeof(RogueDamage), typeof(ZEffectDamage) });
        registry.Initialize(7000);
        return registry;
    }
    public static void Run()
    {
        var defaults = new[] { DamageClass.Default, DamageClass.Generic, DamageClass.Melee, DamageClass.MeleeNoSpeed,
            DamageClass.Ranged, DamageClass.Magic, DamageClass.Summon, DamageClass.SummonMeleeSpeed,
            DamageClass.MagicSummonHybrid, DamageClass.Throwing };
        var vanilla = new Player();
        for (int i = 0; i < defaults.Length; i++)
        {
            Check(defaults[i].Type == i && ReferenceEquals(DamageClassLoader.GetDamageClass(i), defaults[i]), "Vanilla class IDs");
            Check(defaults[i].CountsAsClass(defaults[i]) && defaults[i].GetsPrefixesFor(defaults[i]), "Self classification");
            Near(vanilla.GetTotalDamage(defaults[i]).ApplyTo(100), 100, "Default damage neutral");
            Near(vanilla.GetTotalAttackSpeed(defaults[i]), 1, "Default speed neutral");
            Near(vanilla.GetTotalCritChance(defaults[i]), i == 0 ? 0 : 4, "Generic default crit");
        }
        Check(DamageClassLoader.DamageClassCount == 10 && DamageClassLoader.GetDamageClass(-1) == null &&
            DamageClassLoader.GetDamageClass(10) == null, "Loader bounds");
        Check(DamageClass.MeleeNoSpeed.CountsAsClass(DamageClass.Melee) &&
            !DamageClass.Melee.CountsAsClass(DamageClass.MeleeNoSpeed), "Directional effect inheritance");
        Check(DamageClass.MagicSummonHybrid.CountsAsClass(DamageClass.Magic) &&
            DamageClass.MagicSummonHybrid.CountsAsClass(DamageClass.Summon), "Hybrid effects");
        Check(!DamageClass.Summon.UseStandardCritCalcs && !DamageClass.Summon.ShowStatTooltipLine(vanilla, "CritChance") &&
            !DamageClass.Summon.ShowStatTooltipLine(vanilla, "Speed") && DamageClass.Summon.ShowStatTooltipLine(vanilla, "Damage"), "Summon stat visibility");
        Check(!DamageClass.SummonMeleeSpeed.UseStandardCritCalcs &&
            DamageClass.SummonMeleeSpeed.ShowStatTooltipLine(vanilla, "Speed"), "Whip speed visibility");
        Check(DamageClass.Summon.GetsPrefixesFor(DamageClass.Magic) &&
            !DamageClass.Summon.CountsAsClass(DamageClass.Magic), "Prefixes distinct from effects");
        Check(DamageClass.Throwing.GetsPrefixesFor(DamageClass.Ranged) &&
            DamageClass.SummonMeleeSpeed.GetsPrefixesFor(DamageClass.Melee) &&
            !DamageClass.SummonMeleeSpeed.GetsPrefixesFor(DamageClass.Summon), "Class-specific prefix overrides");
        vanilla.GetAttackSpeed(DamageClass.Generic) += 0.2f;
        vanilla.GetAttackSpeed(DamageClass.Melee) += 0.5f;
        vanilla.GetAttackSpeed(DamageClass.Summon) += 0.3f;
        Near(vanilla.GetTotalAttackSpeed(DamageClass.MeleeNoSpeed), 1, "MeleeNoSpeed excludes both speed channels");
        Near(vanilla.GetTotalAttackSpeed(DamageClass.SummonMeleeSpeed), 2, "Whip combines speed once per source");
        vanilla.GetDamage(DamageClass.Generic) += 0.2f;
        vanilla.GetDamage(DamageClass.Magic) += 0.4f;
        vanilla.GetDamage(DamageClass.Summon) += 0.6f;
        Near(vanilla.GetTotalDamage(DamageClass.MagicSummonHybrid).ApplyTo(100), 220, "Hybrid does not recursively double generic bonuses");
        Near(vanilla.GetTotalDamage(DamageClass.Default).ApplyTo(100), 100, "Default excludes Generic");
        ref var reference = ref vanilla.GetDamage<MeleeDamageClass>();
        reference.Flat = 7;
        Near(vanilla.GetDamage(DamageClass.Melee).Flat, 7, "Ref-return mutation");
        Reject<ArgumentNullException>(() => vanilla.GetDamage(null));
        Reject<ArgumentException>(() => vanilla.GetDamage(new RogueDamage()));
        Reject<KeyNotFoundException>(() => vanilla.GetDamage<RogueDamage>());
        Reject<ArgumentNullException>(() => new Item().DamageType = null);
        Reject<NotSupportedException>(() => ModContent.GetInstance<RogueDamage>());

        var first = Registry(); var firstPlayer = first.CreatePlayer();
        var firstItem = first.Create(first.ItemType("Combat/RogueBlade"));
        var rogue = firstItem.DamageType;
        Check(rogue.Type == 10 && firstPlayer.GetCritChance<RogueDamage>() == 2, "Custom ID and default callback");
        Check(firstItem.CountsAsClass(DamageClass.Throwing) && !firstItem.CountsAsClass(DamageClass.Ranged), "Item classification");
        Check(ReferenceEquals(first.Clone(firstItem).DamageType, rogue), "Clone preserves damage class");
        Check(rogue.GetsPrefixesFor(DamageClass.Ranged) && !rogue.GetsPrefixesFor(DamageClass.Throwing), "Custom prefix policy");
        // Deliberately nonuniform values exercise all five independent inheritance weights.
        firstPlayer.GetDamage(DamageClass.Generic) = new(1.2f, 1.5f, 3, 2);
        firstPlayer.GetDamage(DamageClass.Throwing) = new(1.4f, 1.2f, 6, 4);
        firstPlayer.GetDamage(rogue) = new(1.1f, 1.1f, 2, 1);
        firstPlayer.GetKnockback(DamageClass.Generic) = firstPlayer.GetDamage(DamageClass.Generic);
        firstPlayer.GetKnockback(DamageClass.Throwing) = firstPlayer.GetDamage(DamageClass.Throwing);
        firstPlayer.GetKnockback(rogue) = firstPlayer.GetDamage(rogue);
        firstPlayer.GetCritChance(DamageClass.Throwing) = 6;
        firstPlayer.GetAttackSpeed(DamageClass.Generic) = 1.2f;
        firstPlayer.GetAttackSpeed(DamageClass.Throwing) = 9;
        firstPlayer.GetAttackSpeed(rogue) = 1.25f;
        firstPlayer.GetArmorPenetration(DamageClass.Generic) = 2;
        firstPlayer.GetArmorPenetration(DamageClass.Throwing) = 8;
        firstPlayer.GetArmorPenetration(rogue) = 1;
        Near(firstPlayer.GetTotalDamage<RogueDamage>().ApplyTo(100), 293.8625f, "Partial damage modifier inheritance");
        Near(firstPlayer.GetTotalKnockback<RogueDamage>().ApplyTo(10), 58.076f, "Independent knockback inheritance");
        Near(firstPlayer.GetTotalCritChance<RogueDamage>(), 12, "Independent crit inheritance");
        Near(firstPlayer.GetTotalAttackSpeed<RogueDamage>(), 1.45f, "Zero throwing speed inheritance");
        Near(firstPlayer.GetTotalArmorPenetration<RogueDamage>(), 5, "Partial armor penetration");
        Check(firstPlayer.GetDamage<ZEffectDamage>() == StatModifier.Default, "Separate custom class stats");
        // The cached effect relation is direct, not transitive through Rogue to Throwing.
        Check(!CombatMod.LastEffect.CountsAsClass(DamageClass.Throwing) && CombatMod.LastEffect.CountsAsClass(rogue), "No transitive effect closure");
        CombatMod.LastEffect.Enabled = false;
        Check(CombatMod.LastEffect.CountsAsClass(rogue), "Effect cache frozen after setup");
        Check(!CombatMod.LastEffect.GetsPrefixesFor(rogue), "Prefix hook remains dynamic");
        using (var second = Registry(true))
        {
            var secondPlayer = second.CreatePlayer();
            var secondRogue = second.Create(7000).DamageType;
            Check(secondRogue.Type == rogue.Type && !ReferenceEquals(secondRogue, rogue), "Stable IDs and isolated class instances");
            Near(secondPlayer.GetTotalDamage<RogueDamage>().ApplyTo(100), 100, "Separate players do not share stats");
            Reject<ArgumentException>(() => secondPlayer.GetDamage(rogue));
            Reject<ArgumentException>(() => rogue.CountsAsClass(secondRogue));
            Reject<ArgumentException>(() => second.ResetPlayerStats(firstPlayer));
            first.ResetPlayerStats(firstPlayer);
            Near(firstPlayer.GetTotalDamage<RogueDamage>().ApplyTo(100), 100, "Reset removes transient bonuses");
            Near(firstPlayer.GetTotalCritChance<RogueDamage>(), 6, "Reset replays custom and generic defaults");
        }
        Check(DamageClassLoader.DamageClassCount == 10, "No leaked global loader context");
        first.Dispose();
        Reject<InvalidOperationException>(() => firstPlayer.GetDamage(rogue));
        Reject<InvalidOperationException>(() => rogue.CountsAsClass(DamageClass.Throwing));
        Check(DamageClass.MeleeNoSpeed.CountsAsClass(DamageClass.Melee), "Vanilla cache unaffected by unload");
        Check(CombatMod.Unloads >= 2 && CombatMod.ClassUnloads >= 4, "Mod and custom-class cleanup");
        using (var failure = new MobileContentRegistry())
        {
            failure.Add(new CombatMod(), new[] { typeof(BadDamage) });
            Reject<ApplicationException>(() => failure.Initialize(7000));
            Reject<InvalidOperationException>(() => failure.CreatePlayer());
            Reject<InvalidOperationException>(() => BadDamage.Instance.CountsAsClass(DamageClass.Generic));
        }
        Console.WriteLine($"PASS {checks} damage class/player checks; managed snapshots only, no Android device used");
    }
}

sealed class CombatMod : Mod
{
    internal static ZEffectDamage LastEffect;
    internal static int Unloads, ClassUnloads;
    public override string Name => "Combat";
    public override void PostSetupContent()
    {
        if (DamageClassLoader.DamageClassCount != 12 || DamageClassLoader.GetDamageClass(10) != ModContent.GetInstance<RogueDamage>() ||
            ModContent.Find<DamageClass>("Terraria/MeleeDamageClass") != DamageClass.Melee)
            throw new Exception("Scoped class lookup");
        LastEffect = ModContent.GetInstance<ZEffectDamage>();
    }
    public override void Unload() => Unloads++;
}
sealed class RogueDamage : DamageClass
{
    public override StatInheritanceData GetModifierInheritance(DamageClass damageClass)
    {
        if (ModContent.GetInstance<RogueDamage>() != this) throw new Exception("Missing registry context in stat hook");
        return damageClass == Generic ? StatInheritanceData.Full : damageClass == Throwing ? new(0.5f, 1, 0, 0.25f, 0.75f) : StatInheritanceData.None;
    }
    public override bool GetEffectInheritance(DamageClass damageClass) => damageClass == Throwing;
    public override bool GetPrefixInheritance(DamageClass damageClass) => damageClass == Ranged;
    public override void SetDefaultStats(Player player)
    {
        if (ModContent.GetInstance<RogueDamage>() != this) throw new Exception("Missing registry context in defaults hook");
        player.GetCritChance(this) = 2;
    }
    public override void Unload() => CombatMod.ClassUnloads++;
}
sealed class ZEffectDamage : DamageClass
{
    internal bool Enabled = true;
    public override bool GetEffectInheritance(DamageClass damageClass) => Enabled && damageClass == ModContent.GetInstance<RogueDamage>();
    public override void Unload() => CombatMod.ClassUnloads++;
}
sealed class RogueBlade : ModItem
{
    public override void SetDefaults() => Item.DamageType = ModContent.GetInstance<RogueDamage>();
}
sealed class BadDamage : DamageClass
{
    internal static BadDamage Instance;
    public override void Load() => Instance = this;
    public override bool GetEffectInheritance(DamageClass damageClass) => throw new ApplicationException("Failed effect cache");
}
