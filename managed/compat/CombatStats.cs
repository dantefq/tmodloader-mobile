namespace Terraria.ModLoader;

// Numerical value contracts used by damage inheritance and hit modifiers.
public struct StatInheritanceData
{
    public static readonly StatInheritanceData Full = new(1, 1, 1, 1, 1);
    public static readonly StatInheritanceData None = new();
    public float damageInheritance, critChanceInheritance, attackSpeedInheritance, armorPenInheritance, knockbackInheritance;
    public StatInheritanceData(float damageInheritance = 0, float critChanceInheritance = 0,
        float attackSpeedInheritance = 0, float armorPenInheritance = 0, float knockbackInheritance = 0)
    {
        this.damageInheritance = damageInheritance; this.critChanceInheritance = critChanceInheritance;
        this.attackSpeedInheritance = attackSpeedInheritance; this.armorPenInheritance = armorPenInheritance;
        this.knockbackInheritance = knockbackInheritance;
    }
}
public readonly struct MultipliableFloat
{
    public static MultipliableFloat One = new(1);
    public float Value { get; }
    public MultipliableFloat() => Value = 1;
    private MultipliableFloat(float value) => Value = value;
    public static MultipliableFloat operator *(MultipliableFloat a, MultipliableFloat b) => new(a.Value * b.Value);
    public static MultipliableFloat operator *(MultipliableFloat a, float b) => new(a.Value * b);
    public static MultipliableFloat operator /(MultipliableFloat a, float b) => new(a.Value / b);
}
public readonly struct AddableFloat
{
    public static AddableFloat Zero = new(0);
    public float Value { get; }
    private AddableFloat(float value) => Value = value;
    public static AddableFloat operator +(AddableFloat a, AddableFloat b) => new(a.Value + b.Value);
    public static AddableFloat operator +(AddableFloat a, float b) => new(a.Value + b);
}
