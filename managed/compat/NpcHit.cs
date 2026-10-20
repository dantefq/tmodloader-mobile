using System;
using Terraria.ModLoader;

namespace Terraria;

// NPC currently exposes only numerical hit contracts. No spawn/AI/native state.
public partial class NPC
{
    public struct HitModifiers
    {
        public DamageClass DamageType { get; init; } = DamageClass.Default;
        public int HitDirection { get; init; }
        public bool SuperArmor { get; init; }
        public StatModifier SourceDamage = StatModifier.Default;
        public AddableFloat FlatBonusDamage = AddableFloat.Zero, ScalingBonusDamage = AddableFloat.Zero;
        public MultipliableFloat TargetDamageMultiplier = MultipliableFloat.One;
        public StatModifier Defense = StatModifier.Default;
        public AddableFloat ArmorPenetration = AddableFloat.Zero, ScalingArmorPenetration = AddableFloat.Zero;
        public MultipliableFloat DefenseEffectiveness = MultipliableFloat.One * 0.5f;
        public StatModifier CritDamage = new(2, 1), NonCritDamage = StatModifier.Default, FinalDamage = StatModifier.Default;
        public MultipliableFloat DamageVariationScale = MultipliableFloat.One;
        public StatModifier Knockback = StatModifier.Default;
        public int? HitDirectionOverride { private get; set; }
        private int damageLimit = int.MaxValue;
        private bool? critOverride;
        private bool knockbackDisabled, instantKill, combatTextHidden;
        public delegate void HitInfoModifier(ref HitInfo info);
        public event HitInfoModifier ModifyHitInfo;
        public HitModifiers() { }
        public void SetMaxDamage(int limit) => damageLimit = Math.Min(damageLimit, Math.Max(1, limit));
        public void DisableCrit() => critOverride = false;
        public void SetCrit() => critOverride ??= true;
        public void DisableKnockback() => knockbackDisabled = true;
        public void SetInstantKill() => instantKill = true;
        public void HideCombatText() => combatTextHidden = true;
        public readonly int GetDamage(float baseDamage, bool crit, bool damageVariation = false, float luck = 0f)
        {
            crit = critOverride ?? crit;
            if (SuperArmor)
            {
                float result = crit ? CritDamage.Additive * CritDamage.Multiplicative : 1;
                return Math.Clamp((int)result, 1, Math.Min(damageLimit, 4));
            }
            float damage = SourceDamage.ApplyTo(baseDamage);
            damage += FlatBonusDamage.Value + ScalingBonusDamage.Value * damage;
            damage *= TargetDamageMultiplier.Value;
            // tML's default spread is 15%; game RNG/luck is deliberately unbound.
            int spread = Math.Clamp((int)Math.Round(15 * DamageVariationScale.Value), 0, 100);
            if (damageVariation && spread > 0)
                throw new NotSupportedException("Damage variation requires a game RNG/luck binding");
            float defense = Math.Max(0, Defense.ApplyTo(0));
            float penetration = defense * Math.Clamp(ScalingArmorPenetration.Value, 0, 1) + ArmorPenetration.Value;
            defense = Math.Max(0, defense - penetration);
            damage = Math.Max(1, damage - defense * DefenseEffectiveness.Value);
            damage = (crit ? CritDamage : NonCritDamage).ApplyTo(damage);
            return Math.Clamp((int)FinalDamage.ApplyTo(damage), 1, damageLimit);
        }
        public readonly float GetKnockback(float baseKnockback) =>
            knockbackDisabled ? 0 : Math.Max(0, Knockback.ApplyTo(baseKnockback));
        public HitInfo ToHitInfo(float baseDamage, bool crit, float baseKnockback, bool damageVariation = false, float luck = 0f)
        {
            var result = new HitInfo
            {
                DamageType = DamageType ?? DamageClass.Default,
                SourceDamage = Math.Max(1, (int)SourceDamage.ApplyTo(baseDamage)),
                Damage = instantKill ? 1 : GetDamage(baseDamage, crit, damageVariation, luck),
                Crit = critOverride ?? crit,
                Knockback = GetKnockback(baseKnockback), HitDirection = HitDirectionOverride ?? HitDirection,
                InstantKill = instantKill, HideCombatText = combatTextHidden
            };
            ModifyHitInfo?.Invoke(ref result);
            ModifyHitInfo = null;
            return result;
        }
    }
    public struct HitInfo
    {
        public DamageClass DamageType = DamageClass.Default;
        private int sourceDamage = 1, damage = 1;
        public int SourceDamage { readonly get => sourceDamage; set => sourceDamage = Math.Max(1, value); }
        public int Damage { readonly get => damage; set => damage = Math.Max(1, value); }
        public bool Crit, InstantKill, HideCombatText;
        public int HitDirection;
        public float Knockback;
        public HitInfo() { }
    }
}
