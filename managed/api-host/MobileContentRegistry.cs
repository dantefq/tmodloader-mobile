using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.IO;
using Terraria;
using Terraria.ModLoader;
using Terraria.ModLoader.IO;
using Terraria.ModLoader.Config;
using Terraria.GameContent.Creative;
using TerrariaMobile.Serialization;

namespace TerrariaMobile.Managed;

// Managed-only registry. Registering IDs here never resizes mobile content tables.
public sealed class MobileContentRegistry : IDisposable
{
    private readonly MobileRawImageCache imageCache;
    public MobileContentRegistry() : this(16 * 1024 * 1024) { }
    public MobileContentRegistry(int maxImageCacheBytes) => imageCache = new MobileRawImageCache(maxImageCacheBytes);
    public int ImageCacheResidentBytes => imageCache.ResidentBytes;
    public Guid ContentGeneration { get; } = Guid.NewGuid();
    private readonly SortedDictionary<string, ModItem> items = new(StringComparer.Ordinal);
    private readonly List<Mod> mods = new();
    private readonly List<Mod> loadOrder = new();
    private readonly Dictionary<string, MobileModManifest> manifests = new(StringComparer.Ordinal);
    public MobileModLoadPlan LoadPlan { get; private set; }
    private readonly Dictionary<string, Mod> modsByName = new(StringComparer.Ordinal);
    private readonly List<GlobalItem> globals = new();
    private readonly List<ModSystem> systems = new();
    private readonly Dictionary<Type, ModConfig> configs = new();
    private readonly Dictionary<Type, object> timePowers = new()
    {
        [typeof(CreativePowers.FreezeTime)] = new CreativePowers.FreezeTime(),
        [typeof(CreativePowers.ModifyTimeRate)] = new CreativePowers.ModifyTimeRate()
    };
    private readonly SortedDictionary<string, DamageClass> damageClasses = new(StringComparer.Ordinal);
    private readonly MobileDamageClassCatalog damageCatalog = new();
    private readonly List<ModType> loaded = new();
    private readonly List<Mod> startedMods = new();
    private readonly Dictionary<int, ModItem> byId = new();
    private readonly Dictionary<Type, ModType> byType = new();
    private readonly Dictionary<string, ModType> byName = new(StringComparer.Ordinal);
    private readonly List<Recipe> recipes = new();
    private bool ready, disposed;
    private readonly Dictionary<int, MobileTextureTransfer> textureTransfers = new();
    public int PendingTextureTransferCount => textureTransfers.Count;
    public IReadOnlyCollection<string> ItemNames => items.Keys;
    public int GlobalCount => globals.Count;
    public int SystemCount => systems.Count;
    public IReadOnlyList<Recipe> Recipes => recipes.AsReadOnly();

    private object Instance(Type type, Dictionary<Type, ModConfig> pending = null)
    {
        if (pending != null && pending.TryGetValue(type, out var staged)) return staged;
        if (configs.TryGetValue(type, out var config)) return config;
        if (byType.TryGetValue(type, out var content)) return content;
        return (object)damageCatalog.Classes.FirstOrDefault(c => c.GetType() == type) ?? throw new KeyNotFoundException(type.FullName);
    }
    private MobileApiContext Enter(bool recipePhase = false, Dictionary<Type, ModConfig> pendingConfigs = null) => new(
        type => byType.TryGetValue(type, out var value) ? value : damageCatalog.Classes.FirstOrDefault(c => c.GetType() == type) ?? throw new KeyNotFoundException(type.FullName),
        name => byName.TryGetValue(name, out var value) ? value : damageCatalog.Classes.FirstOrDefault(c => c.FullName == name) ?? throw new KeyNotFoundException(name),
        recipePhase ? recipes.Add : null,
        name => modsByName.TryGetValue(name, out var mod) ? mod : null,
        () => (loadOrder.Count == 0 ? mods.OrderBy(m => m.Name, StringComparer.Ordinal) : loadOrder.AsEnumerable()).ToArray(), damageCatalog,
        type => Instance(type, pendingConfigs), timePowers);

    public static MobileContentRegistry FromAssembly(Assembly assembly, int firstItemId)
    {
        var types = assembly.GetTypes();
        var modTypes = types.Where(t => !t.IsAbstract && typeof(Mod).IsAssignableFrom(t)).ToArray();
        if (modTypes.Length != 1) throw new NotSupportedException("Expected one mod per managed demo assembly");
        var registry = new MobileContentRegistry();
        registry.Add((Mod)Activator.CreateInstance(modTypes[0]),
            types.Where(t => !t.IsAbstract && (typeof(ModType).IsAssignableFrom(t) || typeof(ModConfig).IsAssignableFrom(t))));
        registry.Initialize(firstItemId);
        return registry;
    }

    public void Add(Mod mod, IEnumerable<Type> contentTypes, MobileTmodArchive resources = null, MobileModManifest manifest = null)
    {
        if (ready || disposed) throw new InvalidOperationException("Registry is sealed");
        if (mod == null || contentTypes == null) throw new ArgumentNullException();
        if (mod.RegistryOwner != null) throw new InvalidOperationException("Mod instance is already registered");
        if (string.IsNullOrWhiteSpace(mod.Name) || mod.Name.Contains('/'))
            throw new ArgumentException("Invalid mod identity");
        if (modsByName.ContainsKey(mod.Name)) throw new InvalidOperationException("Duplicate mod: " + mod.Name);
        if (resources != null && resources.Name != mod.Name) throw new ArgumentException("Resource archive belongs to another mod");
        if (manifest != null && resources != null && resources.HasFile("Info"))
            throw new ArgumentException("Archive Info is authoritative; do not override it with an own manifest");
        var metadata = manifest ?? (resources != null && resources.HasFile("Info") ? MobileModManifest.FromArchive(resources) :
            new MobileModManifest(mod.Name, resources?.Version ?? mod.Version ?? new Version(1, 0)));
        if (metadata.Name != mod.Name || (resources != null && metadata.Version != resources.Version))
            throw new ArgumentException("Manifest belongs to another mod or version");
        var candidates = new List<ModType>();
        var configCandidates = new Dictionary<Type, ModConfig>();
        var names = new HashSet<string>(StringComparer.Ordinal);
        mod.BindResources(resources); mod.Manifest = metadata;
        try
        {
            var types = contentTypes.OrderBy(t => t.FullName, StringComparer.Ordinal).ToArray();
            // A third-party type initializer may cache GetInstance<Config>().
            // Construct configs first and expose the exact staged instances to
            // content constructors, then publish everything only on success.
            foreach (var type in types.Where(t => !t.IsAbstract && !t.ContainsGenericParameters && typeof(ModConfig).IsAssignableFrom(t)))
            {
                if (configs.ContainsKey(type) || configCandidates.ContainsKey(type))
                    throw new InvalidOperationException("Config class is already registered");
                var config = MobileConfigDefaults.Create(type);
                if (config.Mode != ConfigScope.ClientSide && config.Mode != ConfigScope.ServerSide)
                    throw new NotSupportedException("Unsupported config scope");
                configCandidates.Add(type, config);
            }
            using var context = Enter(pendingConfigs: configCandidates);
            foreach (var type in types)
            {
                if (type.IsAbstract || type.ContainsGenericParameters) continue;
                if (typeof(ModConfig).IsAssignableFrom(type)) continue;
                if (!typeof(ModItem).IsAssignableFrom(type) && !typeof(GlobalItem).IsAssignableFrom(type) &&
                    !typeof(DamageClass).IsAssignableFrom(type) && !typeof(ModSystem).IsAssignableFrom(type))
                    throw new NotSupportedException("Unsupported content type: " + type.FullName);
                if (typeof(VanillaDamageClass).IsAssignableFrom(type))
                    throw new NotSupportedException("Vanilla damage classes use shared builtin instances");
                var content = (ModType)Activator.CreateInstance(type, true);
                content.Mod = mod;
                if (!content.IsLoadingEnabled(mod)) continue;
                if (byType.ContainsKey(type)) throw new InvalidOperationException("Content class is already registered");
                if (string.IsNullOrWhiteSpace(content.Name) || content.Name.Contains('/'))
                    throw new ArgumentException("Invalid content identity");
                if (!names.Add(content.FullName)) throw new InvalidOperationException("Duplicate content: " + content.FullName);
                candidates.Add(content);
            }
        }
        catch { mod.BindResources(null); mod.Manifest = null; throw; }
        // No lifecycle callbacks until every mod and content identity has been validated.
        mods.Add(mod);
        modsByName.Add(mod.Name, mod); manifests.Add(mod.Name, metadata);
        mod.RegistryOwner = this;
        foreach (var content in candidates)
        {
            byType.Add(content.GetType(), content); byName.Add(content.FullName, content);
            if (content is ModItem item) items.Add(content.FullName, item);
            else if (content is DamageClass damageClass) damageClasses.Add(content.FullName, damageClass);
            else if (content is ModSystem system) systems.Add(system);
            else globals.Add((GlobalItem)content);
        }
        foreach (var entry in configCandidates) configs.Add(entry.Key, entry.Value);
    }

    public void Initialize(int firstItemId, MobileLoadRole role = MobileLoadRole.Client)
    {
        if (ready || disposed) throw new InvalidOperationException("Registry is sealed");
        if (firstItemId <= 0 || (long)firstItemId + items.Count > int.MaxValue)
            throw new ArgumentOutOfRangeException(nameof(firstItemId));
        LoadPlan = MobileModLoadPlan.Build(manifests.Values, role);
        LoadPlan.RequireValid(); // No IDs or Load callbacks on an invalid plan; caller may add a missing provider and retry.
        loadOrder.AddRange(LoadPlan.Order.Select(m => modsByName[m.Name]));
        ready = true; // Seal before callbacks; recursive registration is rejected.
        var rank = loadOrder.Select((mod, index) => (mod.Name, index)).ToDictionary(p => p.Name, p => p.index, StringComparer.Ordinal);
        var orderedContent = byName.Values.OrderBy(c => rank[c.Mod.Name]).ThenBy(c => c.FullName, StringComparer.Ordinal).ToArray();
        globals.Sort((a, b) => rank[a.Mod.Name] != rank[b.Mod.Name] ? rank[a.Mod.Name].CompareTo(rank[b.Mod.Name]) :
            StringComparer.Ordinal.Compare(a.FullName, b.FullName));
        systems.Sort((a, b) => rank[a.Mod.Name] != rank[b.Mod.Name] ? rank[a.Mod.Name].CompareTo(rank[b.Mod.Name]) :
            StringComparer.Ordinal.Compare(a.FullName, b.FullName));
        damageCatalog.Scope = () => Enter();
        foreach (var damageClass in damageClasses.Values)
        {
            damageClass.Type = damageCatalog.Classes.Count;
            damageClass.Catalog = damageCatalog;
            damageCatalog.Classes.Add(damageClass);
        }
        int id = firstItemId;
        foreach (var item in items.Values)
        {
            var entity = new Item { type = id };
            item.Bind(entity); entity.ModItem = item; byId.Add(id++, item);
        }
        try
        {
            using var context = Enter();
            foreach (var mod in loadOrder)
            {
                startedMods.Add(mod); mod.Load();
            }
            foreach (var content in orderedContent)
            {
                loaded.Add(content); content.Load();
            }
            foreach (var content in loaded)
            {
                if (content is ModItem item) item.SetDefaults();
                content.SetStaticDefaults();
            }
            damageCatalog.BuildEffects();
            foreach (var mod in loadOrder) mod.PostSetupContent();
            using (Enter(recipePhase: true))
            {
                foreach (var item in orderedContent.OfType<ModItem>()) item.AddRecipes();
                foreach (var mod in loadOrder) mod.AddRecipes();
            }
        }
        catch (Exception error)
        {
            try { Dispose(); }
            catch (Exception cleanup) { throw new AggregateException("Initialization and cleanup failed", error, cleanup); }
            throw;
        }
    }

    private void RequireReady()
    {
        if (!ready || disposed) throw new InvalidOperationException("Registry is not active");
    }
    internal void ValidateActive() => RequireReady();

    // CPU-side only. Vanilla atlas aliases require the separate native renderer.
    public MobileRawImage ReadItemImage(int itemType)
    {
        var resource = ResolveItemImage(itemType);
        return imageCache.Get(resource.Archive, resource.Entry);
    }
    public MobileTexturePacket PrepareItemTexture(int itemType)
    {
        var resource = ResolveItemImage(itemType);
        var image = imageCache.Get(resource.Archive, resource.Entry);
        return MobileTexturePacket.Create(resource.Archive.Name + "/" + resource.Entry.Replace('\\', '/'),
            ContentGeneration, resource.Archive.Sha256, image);
    }
    public MobileItemTextureBinding PrepareItemTextureBinding(int itemType)
    {
        var resource = ResolveItemImage(itemType);
        var image = imageCache.Get(resource.Archive, resource.Entry);
        if (image.Width > MobileItemTextureBinding.NativeMaxDimension || image.Height > MobileItemTextureBinding.NativeMaxDimension)
            throw new NotSupportedException("Texture exceeds the small native backend dimensions");
        var packet = MobileTexturePacket.Create(resource.Archive.Name + "/" + resource.Entry.Replace('\\', '/'),
            ContentGeneration, resource.Archive.Sha256, image);
        return new MobileItemTextureBinding(this, itemType, byId[itemType].FullName, packet);
    }
    public void ValidateTextureBinding(MobileItemTextureBinding binding)
    {
        RequireReady();
        if (binding == null) throw new ArgumentNullException(nameof(binding));
        if (!binding.HasOwner(this) || binding.Generation != ContentGeneration)
            throw new ArgumentException("Texture binding belongs to another registry generation");
        if (!byId.TryGetValue(binding.ItemType, out var item) || item.FullName != binding.Item)
            throw new InvalidOperationException("Texture binding item is no longer registered");
        var resource = ResolveItemImage(binding.ItemType);
        if (resource.Archive.Name + "/" + resource.Entry.Replace('\\', '/') != binding.Asset ||
            resource.Archive.Sha256 != binding.ArchiveSha256)
            throw new InvalidOperationException("Texture binding resource identity changed");
    }
    public MobileTextureTransfer BeginTextureTransfer(MobileItemTextureBinding binding)
    {
        ValidateTextureBinding(binding);
        if (textureTransfers.ContainsKey(binding.ItemType)) throw new InvalidOperationException("Item texture transfer already active");
        var transfer = new MobileTextureTransfer(this, binding);
        textureTransfers.Add(binding.ItemType, transfer);
        return transfer;
    }
    internal void ValidateTextureTransfer(MobileTextureTransfer transfer)
    {
        RequireReady();
        if (transfer == null || !textureTransfers.TryGetValue(transfer.Binding.ItemType, out var active) || !ReferenceEquals(active, transfer))
            throw new InvalidOperationException("Texture transfer is not active in this registry");
        ValidateTextureBinding(transfer.Binding);
    }
    internal void CompleteTextureTransfer(MobileTextureTransfer transfer)
    {
        // Teardown must still be acknowledged if a configurable texture key
        // changed. It must not require preparing/installing the old image again.
        RequireReady();
        if (transfer == null || !textureTransfers.TryGetValue(transfer.Binding.ItemType, out var active) || !ReferenceEquals(active, transfer))
            throw new InvalidOperationException("Texture transfer is not active in this registry");
        textureTransfers.Remove(transfer.Binding.ItemType);
    }
    private (MobileTmodArchive Archive, string Entry) ResolveItemImage(int itemType)
    {
        RequireReady();
        if (!byId.TryGetValue(itemType, out var item)) throw new KeyNotFoundException("Unregistered mod item");
        using var context = Enter();
        ModContent.SplitName(item.Texture, out string domain, out string resource);
        if (domain == "Terraria") throw new NotSupportedException("Vanilla atlas aliases require a native texture binding");
        if (!modsByName.TryGetValue(domain, out var provider)) throw new KeyNotFoundException("Texture provider is not loaded");
        if (provider.ResourceArchive == null) throw new FileNotFoundException("Texture provider has no resource archive");
        if (!resource.EndsWith(".rawimg", StringComparison.Ordinal)) resource += ".rawimg";
        return (provider.ResourceArchive, resource);
    }

    public void Configure(Type configType, Action<ModConfig> apply)
    {
        RequireReady();
        if (configType == null || apply == null) throw new ArgumentNullException();
        if (!configs.TryGetValue(configType, out var config)) throw new KeyNotFoundException(configType.FullName);
        using var context = Enter();
        apply(config);
    }
    public void Configure<T>(Action<T> apply) where T : ModConfig
    {
        if (apply == null) throw new ArgumentNullException(nameof(apply));
        Configure(typeof(T), value => apply((T)value));
    }

    // Pure managed snapshots. A native host must separately validate/apply the
    // result and must not pretend eventUpdateRate has a mobile binding.
    public (double Time, double Tile, double Event) EvaluateTimeRate(bool gameMenu, int active, int sleeping,
        int targetRate = 1, bool freeze = false)
    {
        RequireReady();
        if (active < 0 || active > 256 || sleeping < 0 || sleeping > active || targetRate < 1 || targetRate > 1000)
            throw new ArgumentOutOfRangeException("Invalid time snapshot");
        using var context = Enter();
        var freezePower = (CreativePowers.FreezeTime)timePowers[typeof(CreativePowers.FreezeTime)];
        var ratePower = (CreativePowers.ModifyTimeRate)timePowers[typeof(CreativePowers.ModifyTimeRate)];
        var previous = (Terraria.Main.gameMenu, Terraria.Main.CurrentFrameFlags.ActivePlayersCount,
            Terraria.Main.CurrentFrameFlags.SleepingPlayersCount, freezePower.Enabled, ratePower.TargetTimeRate);
        try
        {
            Terraria.Main.gameMenu = gameMenu;
            Terraria.Main.CurrentFrameFlags.ActivePlayersCount = active;
            Terraria.Main.CurrentFrameFlags.SleepingPlayersCount = sleeping;
            freezePower.Enabled = freeze; ratePower.TargetTimeRate = targetRate;
            double time = 1, tile = 1, events = 1;
            foreach (var system in systems) system.ModifyTimeRate(ref time, ref tile, ref events);
            return (time, tile, events);
        }
        finally
        {
            (Terraria.Main.gameMenu, Terraria.Main.CurrentFrameFlags.ActivePlayersCount,
                Terraria.Main.CurrentFrameFlags.SleepingPlayersCount, freezePower.Enabled, ratePower.TargetTimeRate) = previous;
        }
    }
    public Player CreatePlayer()
    {
        RequireReady();
        return new Player(damageCatalog);
    }
    public void ResetPlayerStats(Player player)
    {
        RequireReady();
        if (player == null) throw new ArgumentNullException(nameof(player));
        // Reset validates the retained player registry; no native player is affected.
        if (!player.BelongsTo(damageCatalog)) throw new ArgumentException("Player belongs to another registry");
        player.ResetDamageClassData();
    }
    public int ItemType(string fullName)
    {
        RequireReady();
        if (!items.TryGetValue(fullName, out var item)) throw new KeyNotFoundException(fullName);
        return item.Type;
    }
    public Item Create(int type, int vanillaDamage = 0)
    {
        RequireReady();
        using var context = Enter();
        var entity = new Item { type = type, damage = vanillaDamage };
        if (byId.TryGetValue(type, out var prototype))
        {
            var content = prototype.NewInstance(entity);
            if (content == null || !ReferenceEquals(content.Item, entity))
                throw new InvalidOperationException("ModItem.NewInstance must bind the requested entity");
            entity.ModItem = content;
            content.SetDefaults();
            if (entity.type != type) throw new InvalidOperationException("SetDefaults changed registered content identity");
        }
        foreach (var globalPrototype in globals)
        {
            if (!globalPrototype.AppliesToEntity(entity, false)) continue;
            var content = globalPrototype;
            if (globalPrototype.InstancePerEntity)
            {
                content = globalPrototype.NewInstance(entity);
                if (content == null) continue;
            }
            entity.Globals.Add(content.GetType(), content); content.SetDefaults(entity);
        }
        return entity;
    }

    public TagCompound Save(Item item)
    {
        RequireReady();
        if (item == null) throw new ArgumentNullException(nameof(item));
        using var context = Enter();
        if (item.ModItem == null) throw new NotSupportedException("Vanilla persistence requires a mobile defaults bridge");
        if (!byId.TryGetValue(item.type, out var prototype) || prototype.FullName != item.ModItem.FullName)
            throw new ArgumentException("Item does not belong to this registry");
        var tag = new TagCompound { ["format"] = 1, ["stack"] = item.stack,
            ["prefix"] = item.prefix, ["favorite"] = item.favorite };
        if (item.ModItem != null)
        {
            tag["content"] = item.ModItem.FullName;
            var data = new TagCompound(); item.ModItem.SaveData(data); tag["data"] = data;
        }
        var globalData = new TagCompound();
        foreach (var global in item.Globals.Values)
        {
            var data = new TagCompound(); global.SaveData(item, data);
            if (data.Count != 0) globalData[global.FullName] = data;
        }
        tag["globals"] = globalData;
        return tag;
    }

    public Item Clone(Item item)
    {
        RequireReady();
        if (item == null) throw new ArgumentNullException(nameof(item));
        using var context = Enter();
        return item.Clone();
    }

    // Missing mod data is returned intact; callers must retain it, not overwrite a save.
    public bool TryRestore(TagCompound tag, out Item item)
    {
        RequireReady(); item = null;
        using var context = Enter();
        if (tag == null || tag.GetInt("format") != 1) throw new ArgumentException("Unsupported item snapshot");
        int type;
        if (tag.ContainsKey("content"))
        {
            if (!items.TryGetValue(tag.GetString("content"), out var prototype)) return false;
            type = prototype.Type;
        }
        else
        {
            throw new NotSupportedException("Vanilla persistence requires a mobile defaults bridge");
        }
        var result = Create(type);
        var data = tag.GetCompound("globals");
        // Reject a partial restore if a previously saved GlobalItem is unavailable.
        foreach (var key in data.Keys)
            if (!result.Globals.Values.Any(g => g.FullName == key)) return false;
        result.stack = tag.GetInt("stack"); result.prefix = tag.GetInt("prefix"); result.favorite = tag.GetBool("favorite");
        if (result.stack < 1 || result.stack > result.maxStack) throw new ArgumentException("Invalid stack");
        result.ModItem?.LoadData(tag.GetCompound("data"));
        foreach (var global in result.Globals.Values)
            if (data.ContainsKey(global.FullName)) global.LoadData(result, data.GetCompound(global.FullName));
        item = result; return true;
    }

    public void Dispose()
    {
        if (disposed) return;
        if (textureTransfers.Count != 0) throw new InvalidOperationException("Native texture teardown must finish before registry unload");
        disposed = true;
        using var context = Enter();
        var errors = new List<Exception>();
        foreach (var content in loaded.AsEnumerable().Reverse())
            try { content.Unload(); } catch (Exception e) { errors.Add(e); }
        foreach (var mod in startedMods.AsEnumerable().Reverse())
            try { mod.Unload(); } catch (Exception e) { errors.Add(e); }
        foreach (var mod in mods) { mod.BindResources(null); mod.Manifest = null; mod.RegistryOwner = null; }
        damageCatalog.Active = false; damageCatalog.Scope = null; damageClasses.Clear();
        loaded.Clear(); startedMods.Clear(); byId.Clear(); byName.Clear(); byType.Clear(); recipes.Clear();
        items.Clear(); globals.Clear(); mods.Clear(); modsByName.Clear(); manifests.Clear(); loadOrder.Clear();
        systems.Clear(); configs.Clear(); timePowers.Clear();
        imageCache.Dispose();
        if (errors.Count != 0) throw new AggregateException("Unload failed", errors);
    }
}
