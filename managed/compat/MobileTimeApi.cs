using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Reflection;

// Own snapshot API for the audited time contract. No native objects or clock
// writes live here. The registry scopes these fields around each callback.
namespace Terraria
{
    public static class Main
    {
        [ThreadStatic] public static bool gameMenu;
        public static class CurrentFrameFlags
        {
            [ThreadStatic] public static int ActivePlayersCount;
            [ThreadStatic] public static int SleepingPlayersCount;
        }
    }
}

namespace Terraria.ModLoader
{
    public abstract class ModSystem : ModType
    {
        public virtual void ModifyTimeRate(ref double timeRate, ref double tileUpdateRate, ref double eventUpdateRate) { }
    }

    internal static class MobileConfigDefaults
    {
        internal static Config.ModConfig Create(Type type)
        {
            var instance = (Config.ModConfig)Activator.CreateInstance(type, true);
            foreach (var field in type.GetFields(BindingFlags.Public | BindingFlags.Instance))
            {
                var value = field.GetCustomAttribute<DefaultValueAttribute>();
                if (value == null) continue;
                if (field.IsInitOnly || field.IsLiteral ||
                    (value.Value != null && !field.FieldType.IsInstanceOfType(value.Value)))
                    throw new NotSupportedException("Unsupported config default: " + field.Name);
                field.SetValue(instance, value.Value);
            }
            foreach (var property in type.GetProperties(BindingFlags.Public | BindingFlags.Instance))
            {
                var value = property.GetCustomAttribute<DefaultValueAttribute>();
                if (value == null) continue;
                if (property.GetIndexParameters().Length != 0 || property.SetMethod == null || !property.SetMethod.IsPublic ||
                    (value.Value != null && !property.PropertyType.IsInstanceOfType(value.Value)))
                    throw new NotSupportedException("Unsupported config default: " + property.Name);
                property.SetValue(instance, value.Value);
            }
            return instance;
        }
    }
}

namespace Terraria.ModLoader.Config
{
    public enum ConfigScope { ClientSide, ServerSide }
    public abstract class ModConfig { public abstract ConfigScope Mode { get; } }
    [AttributeUsage(AttributeTargets.Field | AttributeTargets.Property)]
    public sealed class RangeAttribute : Attribute
    {
        public readonly int Min, Max;
        public RangeAttribute(int min, int max) { Min = min; Max = max; }
    }
}

namespace Terraria.GameContent.Creative
{
    public static class CreativePowers
    {
        public abstract class ASharedTogglePower { public bool Enabled { get; set; } }
        public sealed class FreezeTime : ASharedTogglePower { }
        public sealed class ModifyTimeRate { public int TargetTimeRate { get; set; } = 1; }
    }
    public sealed class CreativePowerManager
    {
        public static readonly CreativePowerManager Instance = new CreativePowerManager();
        private CreativePowerManager() { }
        public T GetPower<T>()
        {
            var context = Terraria.ModLoader.MobileApiContext.Current ??
                throw new NotSupportedException("Creative snapshot requires a managed registry callback");
            if (typeof(T) != typeof(CreativePowers.FreezeTime) && typeof(T) != typeof(CreativePowers.ModifyTimeRate))
                throw new NotSupportedException("Creative power is not bridged: " + typeof(T));
            return (T)context.TimePowers[typeof(T)];
        }
    }
}
