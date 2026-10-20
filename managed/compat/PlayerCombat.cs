using System;
using Terraria.ModLoader;

namespace Terraria;

// Combat-stat snapshot only: no inventory, NPC combat, world or native player binding.
public class Player
{
    private sealed class DamageData
    {
        internal StatModifier Damage = StatModifier.Default, Knockback = StatModifier.Default;
        internal float Crit, Speed = 1, Armor;
    }
    private readonly MobileDamageClassCatalog catalog;
    private DamageData[] data;
    public Player() : this(MobileApiContext.Current?.DamageClasses ?? MobileDamageClassCatalog.Vanilla) { }
    internal Player(MobileDamageClassCatalog catalog)
    {
        this.catalog = catalog;
        ResetDamageClassData();
    }
    internal bool BelongsTo(MobileDamageClassCatalog value) => ReferenceEquals(catalog, value);
    internal void ResetDamageClassData()
    {
        using var scope = catalog.Enter();
        data = new DamageData[catalog.Classes.Count];
        for (int i = 0; i < data.Length; i++) data[i] = new DamageData();
        foreach (var damageClass in catalog.Classes) damageClass.SetDefaultStats(this);
    }
    private DamageData For(DamageClass damageClass)
    {
        catalog.Validate(damageClass); return data[damageClass.Type];
    }
    private T Find<T>() where T : DamageClass
    {
        using var scope = catalog.Enter();
        foreach (var value in catalog.Classes) if (value.GetType() == typeof(T)) return (T)value;
        throw new System.Collections.Generic.KeyNotFoundException(typeof(T).FullName);
    }
    public ref StatModifier GetDamage(DamageClass damageClass) => ref For(damageClass).Damage;
    public ref StatModifier GetDamage<T>() where T : DamageClass => ref GetDamage(Find<T>());
    public ref float GetCritChance(DamageClass damageClass) => ref For(damageClass).Crit;
    public ref float GetCritChance<T>() where T : DamageClass => ref GetCritChance(Find<T>());
    public ref float GetAttackSpeed(DamageClass damageClass) => ref For(damageClass).Speed;
    public ref float GetAttackSpeed<T>() where T : DamageClass => ref GetAttackSpeed(Find<T>());
    public ref float GetArmorPenetration(DamageClass damageClass) => ref For(damageClass).Armor;
    public ref float GetArmorPenetration<T>() where T : DamageClass => ref GetArmorPenetration(Find<T>());
    public ref StatModifier GetKnockback(DamageClass damageClass) => ref For(damageClass).Knockback;
    public ref StatModifier GetKnockback<T>() where T : DamageClass => ref GetKnockback(Find<T>());
    private StatModifier TotalModifier(DamageClass damageClass, bool knockback)
    {
        var own = For(damageClass);
        using var scope = catalog.Enter();
        var result = knockback ? own.Knockback : own.Damage;
        for (int i = 0; i < data.Length; i++)
        {
            if (i == damageClass.Type) continue;
            var inheritance = damageClass.GetModifierInheritance(catalog.Classes[i]);
            result = result.CombineWith((knockback ? data[i].Knockback : data[i].Damage)
                .Scale(knockback ? inheritance.knockbackInheritance : inheritance.damageInheritance));
        }
        return result;
    }
    private float TotalScalar(DamageClass damageClass, int channel)
    {
        var own = For(damageClass);
        using var scope = catalog.Enter();
        float result = channel == 0 ? own.Crit : channel == 1 ? own.Speed : own.Armor;
        for (int i = 0; i < data.Length; i++)
        {
            if (i == damageClass.Type) continue;
            var inheritance = damageClass.GetModifierInheritance(catalog.Classes[i]);
            result += channel == 0 ? data[i].Crit * inheritance.critChanceInheritance :
                channel == 1 ? (data[i].Speed - 1) * inheritance.attackSpeedInheritance :
                data[i].Armor * inheritance.armorPenInheritance;
        }
        return result;
    }
    public StatModifier GetTotalDamage(DamageClass damageClass) => TotalModifier(damageClass, false);
    public StatModifier GetTotalDamage<T>() where T : DamageClass => GetTotalDamage(Find<T>());
    public StatModifier GetTotalKnockback(DamageClass damageClass) => TotalModifier(damageClass, true);
    public StatModifier GetTotalKnockback<T>() where T : DamageClass => GetTotalKnockback(Find<T>());
    public float GetTotalCritChance(DamageClass damageClass) => TotalScalar(damageClass, 0);
    public float GetTotalCritChance<T>() where T : DamageClass => GetTotalCritChance(Find<T>());
    public float GetTotalAttackSpeed(DamageClass damageClass) => TotalScalar(damageClass, 1);
    public float GetTotalAttackSpeed<T>() where T : DamageClass => GetTotalAttackSpeed(Find<T>());
    public float GetTotalArmorPenetration(DamageClass damageClass) => TotalScalar(damageClass, 2);
    public float GetTotalArmorPenetration<T>() where T : DamageClass => GetTotalArmorPenetration(Find<T>());
}
