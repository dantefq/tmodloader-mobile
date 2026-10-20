using System;
using System.Collections.Generic;
using Terraria;

namespace Terraria.ModLoader;

// Managed numerical contracts only. IDs do not index any native Terraria array.
public abstract class DamageClass : ModType
{
    public static DamageClass Default { get; } = new DefaultDamageClass { Type = 0 };
    public static DamageClass Generic { get; } = new GenericDamageClass { Type = 1 };
    public static DamageClass Melee { get; } = new MeleeDamageClass { Type = 2 };
    public static DamageClass MeleeNoSpeed { get; } = new MeleeNoSpeedDamageClass { Type = 3 };
    public static DamageClass Ranged { get; } = new RangedDamageClass { Type = 4 };
    public static DamageClass Magic { get; } = new MagicDamageClass { Type = 5 };
    public static DamageClass Summon { get; } = new SummonDamageClass { Type = 6 };
    public static DamageClass SummonMeleeSpeed { get; } = new SummonMeleeSpeedDamageClass { Type = 7 };
    public static DamageClass MagicSummonHybrid { get; } = new MagicSummonHybridDamageClass { Type = 8 };
    public static DamageClass Throwing { get; } = new ThrowingDamageClass { Type = 9 };
    public int Type { get; internal set; } = -1;
    internal MobileDamageClassCatalog Catalog;
    public virtual string LocalizationCategory => "DamageClasses";
    public virtual StatInheritanceData GetModifierInheritance(DamageClass damageClass) =>
        damageClass == Generic ? StatInheritanceData.Full : StatInheritanceData.None;
    public virtual bool GetEffectInheritance(DamageClass damageClass) => false;
    public virtual bool GetPrefixInheritance(DamageClass damageClass) => GetEffectInheritance(damageClass);
    public virtual void SetDefaultStats(Player player) { }
    public virtual bool UseStandardCritCalcs => true;
    public virtual bool ShowStatTooltipLine(Player player, string lineName) => true;
    public bool CountsAsClass<T>() where T : DamageClass => CountsAsClass(ModContent.GetInstance<T>());
    public bool CountsAsClass(DamageClass damageClass) => SelectCatalog(damageClass).CountsAs(this, damageClass);
    public bool GetsPrefixesFor<T>() where T : DamageClass => GetsPrefixesFor(ModContent.GetInstance<T>());
    public bool GetsPrefixesFor(DamageClass damageClass)
    {
        var catalog = SelectCatalog(damageClass);
        catalog.Validate(this); catalog.Validate(damageClass);
        using var scope = catalog.Enter();
        return this == damageClass || GetPrefixInheritance(damageClass);
    }
    private MobileDamageClassCatalog SelectCatalog(DamageClass other) => Catalog ?? other?.Catalog ??
        MobileApiContext.Current?.DamageClasses ?? MobileDamageClassCatalog.Vanilla;
}

public abstract class VanillaDamageClass : DamageClass { }
public class DefaultDamageClass : VanillaDamageClass
{
    public override StatInheritanceData GetModifierInheritance(DamageClass damageClass) => StatInheritanceData.None;
}
public class GenericDamageClass : VanillaDamageClass
{
    public override StatInheritanceData GetModifierInheritance(DamageClass damageClass) => StatInheritanceData.None;
    public override void SetDefaultStats(Player player) => player.GetCritChance(this) = 4;
}
public class MeleeDamageClass : VanillaDamageClass { }
public class MeleeNoSpeedDamageClass : VanillaDamageClass
{
    public override StatInheritanceData GetModifierInheritance(DamageClass damageClass) =>
        damageClass == Generic || damageClass == Melee ? new(1, 1, 0, 1, 1) : StatInheritanceData.None;
    public override bool GetEffectInheritance(DamageClass damageClass) => damageClass == Melee;
}
public class RangedDamageClass : VanillaDamageClass { }
public class MagicDamageClass : VanillaDamageClass { }
public class SummonDamageClass : VanillaDamageClass
{
    public override bool UseStandardCritCalcs => false;
    public override bool ShowStatTooltipLine(Player player, string lineName) => lineName != "CritChance" && lineName != "Speed";
    public override bool GetPrefixInheritance(DamageClass damageClass) => damageClass == Magic;
}
public class SummonMeleeSpeedDamageClass : VanillaDamageClass
{
    public override StatInheritanceData GetModifierInheritance(DamageClass damageClass) =>
        damageClass == Melee ? new(attackSpeedInheritance: 1) :
        damageClass == Generic || damageClass == Summon ? StatInheritanceData.Full : StatInheritanceData.None;
    public override bool GetEffectInheritance(DamageClass damageClass) => damageClass == Summon;
    public override bool UseStandardCritCalcs => false;
    public override bool ShowStatTooltipLine(Player player, string lineName) => lineName != "CritChance";
    public override bool GetPrefixInheritance(DamageClass damageClass) => damageClass == Melee;
}
public class MagicSummonHybridDamageClass : VanillaDamageClass
{
    public override StatInheritanceData GetModifierInheritance(DamageClass damageClass) =>
        damageClass == Generic || damageClass == Magic || damageClass == Summon ? StatInheritanceData.Full : StatInheritanceData.None;
    public override bool GetEffectInheritance(DamageClass damageClass) => damageClass == Magic || damageClass == Summon;
}
public class ThrowingDamageClass : VanillaDamageClass
{
    public override bool GetPrefixInheritance(DamageClass damageClass) => damageClass == Ranged;
}

public static class DamageClassLoader
{
    private static MobileDamageClassCatalog Current => MobileApiContext.Current?.DamageClasses ?? MobileDamageClassCatalog.Vanilla;
    public static int DamageClassCount => Current.Classes.Count;
    public static DamageClass GetDamageClass(int type) => type >= 0 && type < Current.Classes.Count ? Current.Classes[type] : null;
}

// Each registry owns its custom classes and cached effect relations. Shared vanilla
// singletons are never rewritten during registry load/unload.
internal sealed class MobileDamageClassCatalog
{
    internal static readonly MobileDamageClassCatalog Vanilla = CreateVanilla();
    internal readonly List<DamageClass> Classes = new()
    {
        DamageClass.Default, DamageClass.Generic, DamageClass.Melee, DamageClass.MeleeNoSpeed,
        DamageClass.Ranged, DamageClass.Magic, DamageClass.Summon, DamageClass.SummonMeleeSpeed,
        DamageClass.MagicSummonHybrid, DamageClass.Throwing
    };
    internal Func<MobileApiContext> Scope;
    internal bool Active = true;
    private bool[,] effects;
    private static MobileDamageClassCatalog CreateVanilla()
    {
        var result = new MobileDamageClassCatalog(); result.BuildEffects(); return result;
    }
    internal MobileApiContext Enter()
    {
        if (!Active) throw new InvalidOperationException("Damage class registry is unloaded");
        return Scope?.Invoke();
    }
    internal void Validate(DamageClass value)
    {
        if (!Active) throw new InvalidOperationException("Damage class registry is unloaded");
        if (value == null) throw new ArgumentNullException(nameof(value));
        if (value.Type < 0 || value.Type >= Classes.Count || !ReferenceEquals(Classes[value.Type], value))
            throw new ArgumentException("Damage class is not owned by this registry");
    }
    internal void BuildEffects()
    {
        using var scope = Enter();
        var cache = new bool[Classes.Count, Classes.Count];
        for (int i = 0; i < Classes.Count; i++)
            for (int j = 0; j < Classes.Count; j++)
                cache[i, j] = i == j || Classes[i].GetEffectInheritance(Classes[j]);
        effects = cache;
    }
    internal bool CountsAs(DamageClass source, DamageClass target)
    {
        Validate(source); Validate(target);
        if (effects == null) throw new InvalidOperationException("Damage class effects are not initialized");
        return effects[source.Type, target.Type];
    }
}
