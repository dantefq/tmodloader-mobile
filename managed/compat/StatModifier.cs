using System;

namespace Terraria.ModLoader;

// Public arithmetic contract; independent of game objects or rendering backends.
public struct StatModifier : IEquatable<StatModifier>
{
    public static readonly StatModifier Default = new();
    public float Base;
    public float Additive { get; private set; }
    public float Multiplicative { get; private set; }
    public float Flat;
    public StatModifier() : this(1, 1) { }
    public StatModifier(float additive, float multiplicative, float flat = 0, float @base = 0)
    {
        Additive = additive; Multiplicative = multiplicative; Flat = flat; Base = @base;
    }
    public float ApplyTo(float baseValue) => (baseValue + Base) * Additive * Multiplicative + Flat;
    public float Undo(float currentValue) => (currentValue - Flat) / (Multiplicative * Additive) - Base;
    public StatModifier CombineWith(StatModifier other) => new(Additive + other.Additive - 1,
        Multiplicative * other.Multiplicative, Flat + other.Flat, Base + other.Base);
    public StatModifier Scale(float scale) => new(1 + (Additive - 1) * scale,
        1 + (Multiplicative - 1) * scale, Flat * scale, Base * scale);
    public static StatModifier operator +(StatModifier value, float amount) =>
        new(value.Additive + amount, value.Multiplicative, value.Flat, value.Base);
    public static StatModifier operator -(StatModifier value, float amount) => value + -amount;
    public static StatModifier operator *(StatModifier value, float factor) =>
        new(value.Additive, value.Multiplicative * factor, value.Flat, value.Base);
    public static StatModifier operator /(StatModifier value, float divisor) =>
        new(value.Additive, value.Multiplicative / divisor, value.Flat, value.Base);
    public static StatModifier operator +(float amount, StatModifier value) => value + amount;
    public static StatModifier operator *(float factor, StatModifier value) => value * factor;
    public static bool operator ==(StatModifier a, StatModifier b) => a.Additive == b.Additive &&
        a.Multiplicative == b.Multiplicative && a.Base == b.Base && a.Flat == b.Flat;
    public static bool operator !=(StatModifier a, StatModifier b) => !(a == b);
    public bool Equals(StatModifier other) => this == other;
    public override bool Equals(object other) => other is StatModifier value && Equals(value);
    public override int GetHashCode()
    {
        static int Mix(int hash, float value) => unchecked(hash * -1521134295 + value.GetHashCode());
        return Mix(Mix(Mix(Mix(1713062080, Additive), Multiplicative), Flat), Base);
    }
}
