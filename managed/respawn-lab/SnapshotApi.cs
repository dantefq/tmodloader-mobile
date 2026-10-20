using System;
using System.Collections.Generic;
using System.Reflection;
using Microsoft.Xna.Framework;

[assembly: AssemblyVersion("1.4.4.9")]

// Isolated research surface. These objects never refer to live Terraria state.
// Keep this out of the common API until native semantics have been verified.
namespace Terraria
{
    public class Entity { public bool active; public Vector2 Center { get; set; } }
    public class Player : Entity { public int respawnTimer; }
    public class NPC : Entity { public bool boss; public int type; }
    public static class Main
    {
        public static bool dedServ;
        public static bool expertMode { get; set; }
        public static NPC[] npc = Array.Empty<NPC>();
    }
}
namespace Terraria.DataStructures { public class PlayerDeathReason { } }
namespace Terraria.Localization
{
    public class LocalizedText
    {
        public string Format(params object[] args) => throw new NotSupportedException("Localization is not bound");
    }
    public static class Language
    {
        public static string GetTextValue(string key) => throw new NotSupportedException("Localization is not bound");
    }
}
namespace Terraria.ModLoader
{
    public interface ILocalizedModType { }
    public static class ILocalizedModTypeExtensions
    {
        public static Terraria.Localization.LocalizedText GetLocalization(this ILocalizedModType value,
            string suffix, Func<string> makeDefaultValue = null) => throw new NotSupportedException("Localization is not bound");
    }
    [AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
    public sealed class JITWhenModsEnabledAttribute : Attribute
    {
        public JITWhenModsEnabledAttribute(params string[] mods) { }
    }
    public class Mod
    {
        public Version Version => new Version(1, 2, 1, 1);
        public ReLogic.Content.AssetRepository Assets => throw new NotSupportedException("Assets are not bound");
        public log4net.ILog Logger => throw new NotSupportedException("Logging is not bound");
        public string GetLocalizationKey(string suffix) => throw new NotSupportedException("Localization is not bound");
        public virtual object Call(params object[] args) => throw new NotSupportedException("External mod calls are not bound");
        public virtual void Load() { }
        public virtual void Unload() { }
        public virtual void PostSetupContent() { }
    }
    public static class ModLoader
    {
        // The isolated harness deliberately has no optional companion mods.
        public static bool TryGetMod(string name, out Mod mod) { mod = null; return false; }
    }
    public class ModPlayer : ILocalizedModType
    {
        public Terraria.Player Player { get; set; }
        public virtual void Kill(double damage, int hitDirection, bool pvp, Terraria.DataStructures.PlayerDeathReason damageSource) { }
        public virtual void UpdateDead() { }
    }
    public static class ModContent
    {
        private static readonly Dictionary<Type, object> instances = new();
        public static T GetInstance<T>() => instances.TryGetValue(typeof(T), out var value)
            ? (T)value : throw new InvalidOperationException("Unregistered snapshot config: " + typeof(T));
        public static void RegisterSnapshot(object value) => instances.Add(value.GetType(), value);
        public static void ClearSnapshots() => instances.Clear();
    }
}
namespace Terraria.ModLoader.Config
{
    public enum ConfigScope { ClientSide, ServerSide }
    public abstract class ModConfig
    {
        public abstract ConfigScope Mode { get; }
        public virtual bool AcceptClientChanges(ModConfig pendingConfig, int whoAmI, ref string message) =>
            throw new NotSupportedException("Network config is not bound");
    }
    public sealed class HeaderAttribute : Attribute { public HeaderAttribute(string value) { } }
    public sealed class ShowDespiteJsonIgnoreAttribute : Attribute { }
    public sealed class RangeAttribute : Attribute { public RangeAttribute(float min, float max) { } }
    public sealed class TooltipKeyAttribute : Attribute { public TooltipKeyAttribute(string value) { } }
    public sealed class TooltipArgsAttribute : Attribute { public TooltipArgsAttribute(params object[] args) { } }
}
