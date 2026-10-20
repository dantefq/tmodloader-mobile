using System;
using System.Collections.Generic;
using System.Reflection;
using Terraria.ModLoader;
using Terraria.ModLoader.IO;

[assembly: AssemblyVersion("1.4.4.9")]
[assembly: System.Runtime.CompilerServices.InternalsVisibleTo("TerrariaMobile.ManagedDemo")]

// Independently written managed item surface. These are snapshots, not IL2CPP objects.
namespace Terraria
{
    // Recipe descriptions only; the mobile crafting tables are not yet bound.
    public sealed class Recipe
    {
        public int ResultType { get; }
        public int ResultStack { get; }
        public IReadOnlyDictionary<int, int> Ingredients => new System.Collections.ObjectModel.ReadOnlyDictionary<int, int>(ingredients);
        public IReadOnlyList<int> Tiles => tiles.AsReadOnly();
        private readonly Dictionary<int, int> ingredients = new Dictionary<int, int>();
        private readonly List<int> tiles = new List<int>();
        private bool registered;
        private Recipe(int type, int stack)
        {
            if (type <= 0 || stack <= 0) throw new ArgumentOutOfRangeException();
            ResultType = type; ResultStack = stack;
        }
        public static Recipe Create(int result, int amount = 1) => new Recipe(result, amount);
        public Recipe AddIngredient(int itemID, int stack = 1)
        {
            if (registered) throw new InvalidOperationException("Recipe is registered");
            if (itemID <= 0 || stack <= 0) throw new ArgumentOutOfRangeException();
            ingredients[itemID] = checked((ingredients.TryGetValue(itemID, out var old) ? old : 0) + stack);
            return this;
        }
        public Recipe AddTile(int tileID)
        {
            if (registered) throw new InvalidOperationException("Recipe is registered");
            if (tileID < 0) throw new ArgumentOutOfRangeException();
            if (!tiles.Contains(tileID)) tiles.Add(tileID);
            return this;
        }
        public void Register()
        {
            if (registered) throw new InvalidOperationException("Recipe is registered");
            var sink = MobileApiContext.Current?.Recipes;
            if (sink == null) throw new NotSupportedException("Recipe registration is only available during AddRecipes");
            sink(this); registered = true;
        }
    }
    public class Entity
    {
        public int width, height;
    }
    public partial class Item : Entity
    {
        public int type, damage, stack = 1, maxStack = 1, prefix, value, rare;
        public int useTime, useAnimation, useStyle, shoot;
        public float knockBack, shootSpeed, scale = 1;
        public bool favorited, autoReuse, consumable, noMelee, noUseGraphic;
        public bool favorite { get => favorited; set => favorited = value; }
        private string nameOverride = "";
        public string Name => nameOverride;
        private DamageClass damageType = DamageClass.Default;
        public DamageClass DamageType { get => damageType; set => damageType = value ?? throw new ArgumentNullException(nameof(value)); }
        public bool CountsAsClass(DamageClass damageClass) => DamageType.CountsAsClass(damageClass);
        public bool CountsAsClass<T>() where T : DamageClass => DamageType.CountsAsClass<T>();
        public ModItem ModItem { get; internal set; }
        internal Dictionary<Type, GlobalItem> Globals = new Dictionary<Type, GlobalItem>();
        public void SetNameOverride(string name) => nameOverride = name ?? "";
        public void ClearNameOverride() => nameOverride = "";
        public T GetGlobalItem<T>() where T : GlobalItem
        {
            if (Globals.TryGetValue(typeof(T), out var value)) return (T)value;
            throw new InvalidOperationException("GlobalItem is not bound to this snapshot: " + typeof(T));
        }
        public bool TryGetGlobalItem<T>(out T result) where T : GlobalItem
        {
            if (Globals.TryGetValue(typeof(T), out var value)) { result = (T)value; return true; }
            result = null; return false;
        }
        public Item Clone()
        {
            var result = (Item)MemberwiseClone();
            result.Globals = new Dictionary<Type, GlobalItem>();
            result.ModItem = ModItem?.Clone(result);
            if (ModItem != null && (result.ModItem == null || !ReferenceEquals(result.ModItem.Item, result)))
                throw new InvalidOperationException("ModItem.Clone must bind the cloned entity");
            foreach (var entry in Globals)
            {
                var global = entry.Value.InstancePerEntity ? entry.Value.Clone(this, result) : entry.Value;
                if (global == null) throw new InvalidOperationException("GlobalItem.Clone returned null");
                result.Globals.Add(entry.Key, global);
            }
            return result;
        }
    }
}

namespace Terraria.ID
{
    public static class ItemID { public const short CopperShortsword = 3507; }
}

namespace Terraria.ModLoader
{
    public interface IModType
    {
        Mod Mod { get; }
        string Name { get; }
        string FullName { get; }
    }
    public class Mod
    {
        private TerrariaMobile.Serialization.MobileTmodArchive resources;
        internal TerrariaMobile.Serialization.MobileTmodArchive ResourceArchive => resources;
        internal TerrariaMobile.Serialization.MobileModManifest Manifest { get; set; }
        public ModSide Side => Manifest?.Side ?? ModSide.Both;
        internal object RegistryOwner { get; set; }
        internal void BindResources(TerrariaMobile.Serialization.MobileTmodArchive archive) => resources = archive;
        public virtual string Name => GetType().Assembly.GetName().Name;
        public virtual Version Version => Manifest?.Version ?? resources?.Version ?? GetType().Assembly.GetName().Version;
        public Version TModLoaderVersion => resources?.TModLoaderVersion;
        public virtual void Load() { }
        public virtual void PostSetupContent() { }
        public virtual void AddRecipes() { }
        public Terraria.Recipe CreateRecipe(int result, int amount = 1) => Terraria.Recipe.Create(result, amount);
        public T Find<T>(string name) where T : IModType => ModContent.Find<T>(Name, name);
        public bool TryFind<T>(string name, out T result) where T : IModType => ModContent.TryFind(Name, name, out result);
        public List<string> GetFileNames() => resources?.GetFileNames();
        public byte[] GetFileBytes(string name) => resources?.GetBytes(name);
        public System.IO.Stream GetFileStream(string name, bool newFileStream = false) => resources?.GetStream(name);
        public bool FileExists(string name) => resources != null && resources.HasFile(name);
        public virtual object Call(params object[] args) => null;
        public virtual void Unload() { }
    }
    public abstract class ModType : IModType
    {
        public Mod Mod { get; internal set; }
        public virtual string Name => GetType().Name;
        public string FullName => (Mod?.Name ?? "Terraria") + "/" + Name;
        public virtual bool IsLoadingEnabled(Mod mod) => true;
        public virtual void Load() { }
        public virtual void Unload() { }
        public virtual void SetStaticDefaults() { }
    }
    public abstract class ModType<TEntity> : ModType where TEntity : class
    {
        public TEntity Entity { get; private set; }
        public void Bind(TEntity entity) => Entity = entity ?? throw new ArgumentNullException(nameof(entity));
    }
    public abstract class ModType<TEntity, TModType> : ModType<TEntity>
        where TEntity : class where TModType : ModType<TEntity, TModType>
    {
        protected virtual bool CloneNewInstances => false;
        public virtual TModType NewInstance(TEntity entity)
        {
            if (CloneNewInstances) return Clone(entity);
            var result = (TModType)Activator.CreateInstance(GetType(), true);
            result.Mod = Mod; result.Bind(entity); return result;
        }
        public virtual TModType Clone(TEntity newEntity)
        {
            var result = (TModType)MemberwiseClone(); result.Bind(newEntity); return result;
        }
    }
    public abstract class ModItem : ModType<Terraria.Item, ModItem>
    {
        public Terraria.Item Item => Entity;
        public int Type => Item.type;
        public virtual string Texture => ((GetType().Namespace ?? "") + "." + Name).Replace('.', '/');
        public virtual void SetDefaults() { }
        public virtual void AddRecipes() { }
        public Terraria.Recipe CreateRecipe(int amount = 1) => Terraria.Recipe.Create(Type, amount);
        public virtual void SaveData(TagCompound tag) { }
        public virtual void LoadData(TagCompound tag) { }
    }
    public abstract class GlobalType<TGlobal> : ModType where TGlobal : GlobalType<TGlobal>
    {
        public virtual bool InstancePerEntity => false;
        protected virtual bool CloneNewInstances => false;
    }
    public abstract class GlobalType<TEntity, TGlobal> : GlobalType<TGlobal>
        where TEntity : class where TGlobal : GlobalType<TEntity, TGlobal>
    {
        public virtual bool AppliesToEntity(TEntity entity, bool lateInstantiation) => true;
        public virtual void SetDefaults(TEntity entity) { }
        public virtual TGlobal Clone(TEntity from, TEntity to) => (TGlobal)MemberwiseClone();
        public virtual TGlobal NewInstance(TEntity entity)
        {
            if (CloneNewInstances) return Clone(null, entity);
            var result = (TGlobal)Activator.CreateInstance(GetType(), true);
            result.Mod = Mod; return result;
        }
    }
    public abstract class GlobalItem : GlobalType<Terraria.Item, GlobalItem>
    {
        public virtual void SaveData(Terraria.Item item, TagCompound tag) { }
        public virtual void LoadData(Terraria.Item item, TagCompound tag) { }
    }
    internal sealed class MobileApiContext : IDisposable
    {
        [ThreadStatic] internal static MobileApiContext Current;
        internal readonly Func<Type, ModType> ByType;
        internal readonly Func<string, ModType> ByName;
        internal readonly Action<Terraria.Recipe> Recipes;
        internal readonly Func<string, Mod> ByMod;
        internal readonly Func<Mod[]> Mods;
        internal readonly MobileDamageClassCatalog DamageClasses;
        internal readonly Func<Type, object> ByInstance;
        internal readonly Dictionary<Type, object> TimePowers;
        private readonly MobileApiContext previous;
        internal MobileApiContext(Func<Type, ModType> byType, Func<string, ModType> byName,
                                  Action<Terraria.Recipe> recipes = null, Func<string, Mod> byMod = null, Func<Mod[]> mods = null, MobileDamageClassCatalog damageClasses = null,
                                  Func<Type, object> byInstance = null, Dictionary<Type, object> timePowers = null)
        {
            previous = Current; ByType = byType; ByName = byName; Recipes = recipes; Current = this;
            ByMod = byMod; Mods = mods; DamageClasses = damageClasses;
            ByInstance = byInstance; TimePowers = timePowers;
        }
        public void Dispose() => Current = previous;
    }
    public static class ModContent
    {
        private static MobileApiContext Context => MobileApiContext.Current ??
            throw new NotSupportedException("Content lookup requires a managed registry callback");
        public static T GetInstance<T>() where T : class => (T)(Context.ByInstance != null ? Context.ByInstance(typeof(T)) : (object)Context.ByType(typeof(T)));
        public static int ItemType<T>() where T : ModItem => GetInstance<T>().Type;
        public static T Find<T>(string fullname) where T : IModType
        {
            if (Context.ByName(fullname) is T result) return result;
            throw new KeyNotFoundException(fullname);
        }
        public static T Find<T>(string modName, string name) where T : IModType => Find<T>(modName + "/" + name);
        public static bool TryFind<T>(string fullname, out T value) where T : IModType
        {
            try { value = Find<T>(fullname); return true; }
            catch (KeyNotFoundException) { value = default(T); return false; }
        }
        public static bool TryFind<T>(string modName, string name, out T value) where T : IModType =>
            TryFind(modName + "/" + name, out value);
        public static void SplitName(string name, out string domain, out string subName)
        {
            int separator = name?.IndexOfAny(new[] { '/', ':', ' ' }) ?? -1;
            if (separator < 1 || separator == name.Length - 1) throw new ArgumentException("Expected a qualified resource name");
            domain = name.Substring(0, separator); subName = name.Substring(separator + 1);
        }
        public static byte[] GetFileBytes(string name)
        {
            SplitName(name, out var mod, out var resource); return ModLoader.GetMod(mod).GetFileBytes(resource);
        }
        public static bool FileExists(string name)
        {
            if (name == null || !name.Contains('/')) return false;
            SplitName(name, out var mod, out var resource);
            return ModLoader.TryGetMod(mod, out var owner) && owner.FileExists(resource);
        }
    }
    public static class ModLoader
    {
        private static MobileApiContext Context => MobileApiContext.Current ??
            throw new NotSupportedException("Mod lookup requires a managed registry callback");
        public static Mod[] Mods => Context.Mods();
        public static Mod GetMod(string name) => Context.ByMod(name) ?? throw new KeyNotFoundException(name);
        public static bool TryGetMod(string name, out Mod result)
        {
            result = Context.ByMod(name); return result != null;
        }
        public static bool HasMod(string name) => Context.ByMod(name) != null;
    }
}

namespace Terraria.ModLoader.IO
{
    // Typed tag data; MobileTagCodec is an own format, not tML TagIO/NBT.
    public class TagCompound : IEnumerable<KeyValuePair<string, object>>, ICloneable
    {
        private readonly Dictionary<string, object> values = new Dictionary<string, object>(StringComparer.Ordinal);
        public int Count => values.Count;
        public ICollection<string> Keys => values.Keys;
        public bool ContainsKey(string key) => values.ContainsKey(key);
        public bool Remove(string key) => values.Remove(key);
        public void Clear() => values.Clear();
        public IEnumerator<KeyValuePair<string, object>> GetEnumerator() => values.GetEnumerator();
        System.Collections.IEnumerator System.Collections.IEnumerable.GetEnumerator() => GetEnumerator();
        public T Get<T>(string key)
        {
            if (!values.TryGetValue(key, out var value))
            {
                if (typeof(T) == typeof(string)) return (T)(object)"";
                if (typeof(T) == typeof(TagCompound)) return (T)(object)new TagCompound();
                if (typeof(T).IsArray) return (T)(object)Array.CreateInstance(typeof(T).GetElementType(), 0);
                if (typeof(T).IsGenericType && typeof(T).GetGenericTypeDefinition() == typeof(List<>))
                    return (T)Activator.CreateInstance(typeof(T));
                return default(T);
            }
            if (value is T typed) return typed;
            throw new System.IO.IOException("Tag type differs for " + key);
        }
        public int GetInt(string key) => Get<int>(key);
        public byte GetByte(string key) => Get<byte>(key);
        public short GetShort(string key) => Get<short>(key);
        public long GetLong(string key) => Get<long>(key);
        public double GetDouble(string key) => Get<double>(key);
        public byte[] GetByteArray(string key) => Get<byte[]>(key);
        public int[] GetIntArray(string key) => Get<int[]>(key);
        public string GetString(string key) => Get<string>(key) ?? "";
        public bool GetBool(string key) => Get<bool>(key);
        public float GetFloat(string key) => Get<float>(key);
        public TagCompound GetCompound(string key) => Get<TagCompound>(key) ?? new TagCompound();
        public IList<T> GetList<T>(string key) => Get<IList<T>>(key) ?? new List<T>();
        public bool TryGet<T>(string key, out T value)
        {
            if (!ContainsKey(key)) { value = default(T); return false; }
            value = Get<T>(key); return true;
        }
        public void Set(string key, object value, bool replace = false)
        {
            if (value == null) { Remove(key); return; }
            if (replace) values[key] = value; else values.Add(key, value);
        }
        public object this[string key] { get => Get<object>(key); set => Set(key, value, true); }
        public void Add(string key, object value) => Set(key, value);
        public void Add(KeyValuePair<string, object> value) => Set(value.Key, value.Value);
        public short GetAsShort(string key) => this[key] switch { short n => n, byte n => n, _ => 0 };
        public int GetAsInt(string key) => this[key] switch { int n => n, short n => n, byte n => n, _ => 0 };
        public long GetAsLong(string key) => this[key] switch { long n => n, int n => n, short n => n, byte n => n, _ => 0 };
        public double GetAsDouble(string key) => this[key] switch { double n => n, float n => n, _ => 0 };
        public object Clone() => TerrariaMobile.Serialization.MobileTagCodec.Copy(this);
    }
}
