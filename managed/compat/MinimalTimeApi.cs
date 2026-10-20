using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Reflection;

[assembly: AssemblyVersion("1.4.4.9")]

// Independently implemented snapshots for the audited ChangeSleepTime DLL.
// This is not a general Terraria object model or config loader.
namespace Terraria
{
    public static class Main
    {
        public static bool gameMenu;
        public static class CurrentFrameFlags
        {
            public static int ActivePlayersCount;
            public static int SleepingPlayersCount;
        }
    }
}

namespace Terraria.ModLoader
{
    public abstract class Mod { }
    public abstract class ModSystem
    {
        public virtual void ModifyTimeRate(ref double timeRate, ref double tileUpdateRate, ref double eventUpdateRate) { }
    }
    public static class ModContent
    {
        private static readonly Dictionary<Type, object> Instances = new Dictionary<Type, object>();
        public static T GetInstance<T>()
        {
            Type type = typeof(T);
            if (!Instances.TryGetValue(type, out object value))
            {
                value = Activator.CreateInstance(type);
                if (value is Config.ModConfig)
                    foreach (FieldInfo field in type.GetFields(BindingFlags.Public | BindingFlags.Instance))
                    {
                        var attribute = field.GetCustomAttribute<DefaultValueAttribute>();
                        if (attribute != null) field.SetValue(value, attribute.Value);
                    }
                Instances.Add(type, value);
            }
            return (T)value;
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
        public readonly int Min;
        public readonly int Max;
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
        private readonly Dictionary<Type, object> powers = new Dictionary<Type, object>();
        public T GetPower<T>()
        {
            if (!powers.TryGetValue(typeof(T), out object value))
            {
                value = Activator.CreateInstance(typeof(T));
                powers.Add(typeof(T), value);
            }
            return (T)value;
        }
    }
}
