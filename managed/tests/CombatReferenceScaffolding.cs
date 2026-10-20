// Test-only dependencies for compiling pinned upstream public combat sources.
// None of these types is compiled into the mobile API. Localization, content
// registration/search and asset sets are scaffolding, excluded from conformance.
using System;

namespace Terraria.Localization
{
    public class LocalizedText { }
    public static class Language
    {
        public static LocalizedText GetText(string key) => new();
    }
}
namespace ReLogic.Reflection
{
    public class IdDictionary
    {
        public static IdDictionary Create<T, V>() => new();
        public void Add(string name, int value) { }
    }
}
namespace Terraria.ID
{
    public class SetFactory
    {
        public SetFactory(int size, string name, ReLogic.Reflection.IdDictionary search) { }
    }
}
namespace Terraria.ModLoader.Core
{
    public static class LoaderUtils
    {
        public static void ResetStaticMembers(Type type) { }
    }
}
namespace Terraria.ModLoader
{
    public class Mod { }
    public abstract class ModType
    {
        public string FullName => "Terraria/" + GetType().Name;
        public string Name => GetType().Name;
        public virtual void SetStaticDefaults() { }
        protected virtual void Register() { }
        public virtual void SetupContent() { }
        protected string PrettyPrintName() => Name;
    }
    public interface ILocalizedModType { }
    [AttributeUsage(AttributeTargets.Class)]
    public class AutoloadAttribute : Attribute
    {
        public AutoloadAttribute(bool value) { }
    }
    public static class LocalizationExtensions
    {
        public static Terraria.Localization.LocalizedText GetLocalization(this DamageClass value, string key, Func<string> fallback) => new();
    }
    public static class ContentInstance
    {
        public static void Register(object value) { }
    }
    public static class ModTypeLookup<T>
    {
        public static void Register(T value) { }
    }
    public static class ModContent
    {
        public static T GetInstance<T>() where T : class
        {
            foreach (var value in DamageClassLoader.DamageClasses)
                if (value.GetType() == typeof(T)) return (T)(object)value;
            throw new InvalidOperationException();
        }
    }
    public static class CombatReferenceHarness
    {
        public static void Add(DamageClass value)
        {
            value.Type = DamageClassLoader.Add(value);
            DamageClassLoader.ResizeArrays();
        }
    }
}
namespace Terraria
{
    public static class Main
    {
        public static int DefaultDamageVariationPercent = 15;
        public static int DamageVar(float damage, int percent, float luck) =>
            throw new NotSupportedException("Game RNG is excluded from reference tests");
    }
    public static class Utils
    {
        public static int Clamp(int value, int min, int max) => Math.Clamp(value, min, max);
    }
    public partial class Player
    {
        private class DamageClassData
        {
            public ModLoader.StatModifier damage = ModLoader.StatModifier.Default, knockback = ModLoader.StatModifier.Default;
            public float critChance, attackSpeed = 1, armorPen;
        }
        public Player() => ResetDamageClassData();
    }
}
