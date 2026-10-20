using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Terraria;
using Terraria.ModLoader;
using TerrariaMobile.Managed;
using TerrariaMobile.Serialization;

static class ModLoadTests
{
    static int checks;
    internal static readonly List<string> Events = new();
    internal static bool BaseReady, FailChild;
    static void Check(bool condition, string message)
    {
        if (!condition) throw new Exception(message);
        checks++;
    }
    static void Reject<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { checks++; return; }
        throw new Exception("Expected " + typeof(T));
    }
    static byte[] Info(Action<BinaryWriter> content = null, string version = "1.0")
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, true))
        {
            writer.Write("version"); writer.Write(version); content?.Invoke(writer); writer.Write("");
        }
        return stream.ToArray();
    }
    static MobileTmodArchive Archive(string name, byte[] info, bool includeInfo = true)
    {
        using var payload = new MemoryStream();
        using (var writer = new BinaryWriter(payload, Encoding.UTF8, true))
        {
            writer.Write(name); writer.Write("1.0"); writer.Write(includeInfo ? 1 : 0);
            if (includeInfo) { writer.Write("Info"); writer.Write(info.Length); writer.Write(info.Length); writer.Write(info); }
        }
        byte[] data = payload.ToArray();
        using var output = new MemoryStream();
        using (var writer = new BinaryWriter(output, Encoding.UTF8, true))
        {
            writer.Write(new byte[] { 84, 77, 79, 68 }); writer.Write("2026.8.3.0");
            writer.Write(SHA1.HashData(data)); writer.Write(new byte[256]); writer.Write(data.Length); writer.Write(data);
        }
        return MobileTmodArchive.FromBytes(output.ToArray());
    }
    static MobileModManifest Manifest(string name, string version = "1.0", string required = null, string weak = null,
        string[] after = null, string[] before = null, ModSide side = ModSide.Both) =>
        new(name, Version.Parse(version), required == null ? null : new[] { MobileModReference.Parse(required) },
            weak == null ? null : new[] { MobileModReference.Parse(weak) }, after, before, side: side);
    static string Order(MobileModLoadPlan plan) => string.Join(",", plan.Order.Select(m => m.Name));
    public static void Run()
    {
        byte[] bytes = Info(w =>
        {
            w.Write("modReferences"); w.Write("ZBase@1.2"); w.Write("");
            w.Write("weakReferences"); w.Write("Optional"); w.Write("");
            w.Write("sortAfter"); w.Write("ZBase"); w.Write("");
            w.Write("dllReferences"); w.Write("Helper"); w.Write("");
            w.Write("side"); w.Write((byte)ModSide.Client);
            w.Write("author"); w.Write("Автор"); w.Write("displayName"); w.Write("Тестовый мод");
            w.Write("description"); w.Write("Описание"); w.Write("homepage"); w.Write("https://example.invalid");
            w.Write("buildVersion"); w.Write("2026.8.3.0");
            w.Write("noCompile"); w.Write("libraryMod"); w.Write("translationMod"); w.Write("!playableOnPreview");
            w.Write("!hideCode"); w.Write("!hideResources"); w.Write("includeSource");
            w.Write("eacPath"); w.Write("unused"); w.Write("modSource"); w.Write("unused");
        });
        var archive = Archive("AChild", bytes);
        var parsed = MobileModManifest.FromArchive(archive);
        Check(parsed.Name == "AChild" && parsed.Version == new Version(1, 0) && parsed.BuildVersion == new Version(2026, 8, 3, 0), "Archive/Info identity");
        Check(parsed.Required[0].ToString() == "ZBase@1.2" && parsed.Weak[0].Name == "Optional", "Strong and weak references");
        Check(parsed.SortAfter.SequenceEqual(new[] { "ZBase" }) && parsed.SortBefore.Count == 0 && parsed.DllReferences[0] == "Helper", "Serialized lists");
        Check(parsed.Side == ModSide.Client && parsed.Author == "Автор" && parsed.DisplayName == "Тестовый мод" && parsed.Description == "Описание", "UTF8 metadata");
        Check(parsed.NoCompile && parsed.LibraryMod && parsed.TranslationMod && !parsed.PlayableOnPreview && !parsed.HideCode && !parsed.HideResources && parsed.IncludeSource,
            "Zero-payload flags");
        Check(parsed.EacPath == "unused" && parsed.ModSource == "unused" && parsed.Homepage == "https://example.invalid", "String payloads are data only");
        Check(archive.GetEntryLength("Info") == bytes.Length && archive.GetEntryLength("missing") == null, "Entry length without expansion");
        var defaults = MobileModManifest.FromInfo("Plain", new Version(1, 0), new byte[] { 0 });
        Check(defaults.HideCode && defaults.HideResources && defaults.PlayableOnPreview && defaults.Side == ModSide.Both && defaults.BuildVersion == null, "Info defaults");
        Check(MobileModManifest.FromArchive(Archive("Plain", Info())).BuildVersion == new Version(2026, 8, 3, 0), "Loader fallback for buildVersion");
        var list = new List<MobileModReference> { new("ZBase") };
        var immutable = new MobileModManifest("AChild", new(1, 0), list); list.Clear();
        Check(immutable.Required.Count == 1 && immutable.SortAfter[0] == "ZBase", "Manifest owns lists and build.txt default order");
        Reject<NotSupportedException>(() => ((IList<MobileModReference>)immutable.Required).Clear());
        Check(MobileModManifest.FromInfo("AChild", new Version(1, 0), Info(w => { w.Write("modReferences"); w.Write("ZBase"); w.Write(""); })).SortAfter.Count == 0,
            "Parsed Info does not invent omitted sort constraints");
        Reject<InvalidDataException>(() => MobileModManifest.FromArchive(Archive("Plain", null, false)));
        Reject<InvalidDataException>(() => MobileModManifest.FromInfo("Plain", new Version(2, 0), Info()));
        Reject<InvalidDataException>(() => MobileModManifest.FromInfo("Plain", new Version(1, 0), Info()[..^1]));
        Reject<InvalidDataException>(() => MobileModManifest.FromInfo("Plain", new Version(1, 0), Info().Append((byte)9).ToArray()));
        Reject<InvalidDataException>(() => MobileModManifest.FromInfo("Plain", new Version(1, 0), Info(w => { w.Write("side"); w.Write((byte)9); })));
        Reject<InvalidDataException>(() => MobileModManifest.FromInfo("Plain", new Version(1, 0), Info(w => { w.Write("author"); w.Write("A"); w.Write("author"); w.Write("B"); })));
        Reject<NotSupportedException>(() => MobileModManifest.FromInfo("Plain", new Version(1, 0), Info(w => w.Write("futureTag"))));
        Reject<InvalidDataException>(() => MobileModManifest.FromInfo("Plain", new Version(1, 0), Info(w => { w.Write("buildVersion"); w.Write("bad"); })));
        Reject<InvalidDataException>(() => MobileModManifest.FromInfo("Plain", new Version(1, 0), Info(w => { w.Write("modReferences"); w.Write("A@bad"); w.Write(""); })));
        Reject<InvalidDataException>(() => MobileModManifest.FromInfo("Plain", new Version(1, 0), new byte[] { 1, 255, 0 }));
        Reject<InvalidDataException>(() => MobileModManifest.FromInfo("Plain", new Version(1, 0), new byte[] { 255, 255, 255, 255, 255 }));
        Reject<InvalidDataException>(() => MobileModManifest.FromInfo("Plain", new Version(1, 0), new byte[MobileModManifest.MaxInfoBytes + 1]));
        Reject<InvalidDataException>(() => MobileModManifest.FromArchive(Archive("Plain", new byte[MobileModManifest.MaxInfoBytes + 1])));
        Reject<InvalidDataException>(() => MobileModManifest.FromInfo("Plain", new Version(1, 0), Info(w => { w.Write("description"); w.Write(new string('a', MobileModManifest.MaxStringBytes + 1)); })));
        Reject<InvalidDataException>(() => MobileModManifest.FromInfo("Plain", new Version(1, 0), Info(w =>
        { w.Write("sortAfter"); for (int i = 0; i <= MobileModManifest.MaxListEntries; i++) w.Write("N" + i); w.Write(""); })));
        Reject<ArgumentException>(() => MobileModReference.Parse("A@1.0@2.0"));
        Reject<ArgumentException>(() => Manifest("Terraria"));
        Reject<ArgumentException>(() => Manifest("../escape"));
        Reject<ArgumentException>(() => Manifest("A", required: "A"));
        Reject<ArgumentException>(() => Manifest("A", required: "B", weak: "B"));
        Reject<ArgumentException>(() => Manifest("A", after: new[] { "B", "B" }));
        Reject<ArgumentException>(() => Manifest("A", after: new[] { "B" }, before: new[] { "B" }));
        Reject<ArgumentException>(() => new MobileModManifest("A", new(1, 0), dllReferences: new[] { "../Helper" }));

        var child = Manifest("AChild", required: "ZBase@1.2", weak: "Optional@3.0"); var provider = Manifest("ZBase", "1.5");
        var plan = MobileModLoadPlan.Build(new[] { child, provider });
        Check(plan.IsValid && Order(plan) == "ZBase,AChild", "Dependency default order defeats alphabetic order");
        Check(Order(MobileModLoadPlan.Build(new[] { provider, child })) == Order(plan), "Input order independence");
        Check(MobileModLoadPlan.Build(new[] { child }).Issues.Single().Code == "missing-dependency", "Missing strong provider");
        Check(MobileModLoadPlan.Build(new[] { child, Manifest("ZBase", "1.1") }).Issues.Single().Code == "dependency-too-old", "Minimum version");
        Check(MobileModLoadPlan.Build(new[] { child, Manifest("ZBase", "2.0") }).Issues.Single().Code == "dependency-major-mismatch", "New major is not automatically compatible");
        Check(MobileModLoadPlan.Build(new[] { child, provider, Manifest("Optional", "2.0") }).Issues.Single().Code == "dependency-too-old", "Present weak provider version checked");
        Check(MobileModLoadPlan.Build(new[] { child, provider, Manifest("Optional", "4.0") }).Issues.Single().Code == "dependency-major-mismatch", "Present weak major checked");
        Check(MobileModLoadPlan.Build(new[] { child, provider, Manifest("Optional", "3.0") }).IsValid, "Exact weak version accepted");
        Check(Order(MobileModLoadPlan.Build(new[] { Manifest("A", required: "Z", before: new[] { "Z" }), Manifest("Z") })) == "A,Z", "SortBefore can reverse default dependency ordering");
        Check(Order(MobileModLoadPlan.Build(new[] { Manifest("A", after: new[] { "Missing" }), Manifest("B") })) == "A,B", "Absent sort-only target ignored");
        var cycle = MobileModLoadPlan.Build(new[] { Manifest("A", after: new[] { "C" }), Manifest("B", after: new[] { "A" }),
            Manifest("C", after: new[] { "B" }), Manifest("D", after: new[] { "C" }) });
        Check(!cycle.IsValid && cycle.Order.Count == 0 && cycle.Issues.Single().Message == "Mod ordering cycle: A -> B -> C -> A", "Actual cycle excludes blocked downstream node");
        Reject<MobileModDependencyException>(() => cycle.RequireValid());
        Check(MobileModLoadPlan.Build(new[] { provider, Manifest("ZBase", "9.0") }).Issues.Single().Code == "duplicate-mod", "Duplicate identity");
        Check(MobileModLoadPlan.Build(new[] { Manifest("ServerOnly", side: ModSide.Server) }).Issues.Single().Code == "wrong-side", "Wrong client side rejected");
        Check(MobileModLoadPlan.Build(new[] { Manifest("ServerOnly", side: ModSide.Server) }, MobileLoadRole.Server).IsValid, "Server planning metadata");
        Check(MobileModLoadPlan.Build(new[] { Manifest("ClientOnly", side: ModSide.Client) }, MobileLoadRole.Server).Issues.Single().Code == "wrong-side", "Wrong server side rejected");
        Check(MobileModLoadPlan.Build(new[] { Manifest("BothConsumer", required: "ClientProvider"), Manifest("ClientProvider", side: ModSide.Client) })
            .Issues.Single().Code == "dependency-side-incompatible", "Both cannot strongly require Client-only provider");
        Check(MobileModLoadPlan.Build(new[] { Manifest("ClientConsumer", required: "ClientProvider", side: ModSide.Client), Manifest("ClientProvider", side: ModSide.Client) }).IsValid,
            "Client can strongly require Client-only provider");
        Check(MobileModLoadPlan.Build(new[] { Manifest("BothConsumer", weak: "ClientProvider"), Manifest("ClientProvider", side: ModSide.Client) }).IsValid,
            "Side restriction does not reject weak provider");
        Check(MobileModLoadPlan.Build(Array.Empty<MobileModManifest>()).IsValid, "Empty selected set");
        Reject<ArgumentException>(() => MobileModLoadPlan.Build(Enumerable.Repeat(provider, MobileModLoadPlan.MaxMods + 1)));
        var longChain = Enumerable.Range(0, MobileModLoadPlan.MaxMods).Select(i => Manifest("N" + i.ToString("D4"),
            after: i == 0 ? Array.Empty<string>() : new[] { "N" + (i - 1).ToString("D4") })).ToArray();
        Check(MobileModLoadPlan.Build(longChain.Reverse()).Order.Count == MobileModLoadPlan.MaxMods, "Long chain without recursive stack growth");
        longChain[0] = Manifest("N0000", after: new[] { "N1023" });
        Check(MobileModLoadPlan.Build(longChain).Issues.Single().Code == "ordering-cycle", "Long cycle without recursive stack growth");
        RegistryLifecycle();
        Console.WriteLine($"PASS {checks} manifest/dependency lifecycle checks; synthetic TMOD/own mods only, no Android device used");
    }
    static void RegistryLifecycle()
    {
        Events.Clear(); BaseReady = false; FailChild = false;
        using (var registry = new MobileContentRegistry())
        {
            registry.Add(new ChildLoadMod(), new[] { typeof(ChildLoadBlade), typeof(ChildLoadGlobal) }, manifest: Manifest("AChild", required: "ZBase"));
            Reject<MobileModDependencyException>(() => registry.Initialize(7000));
            Check(Events.Count == 0 && !registry.LoadPlan.IsValid, "No Load callbacks on invalid plan");
            registry.Add(new BaseLoadMod(), new[] { typeof(BaseLoadBlade), typeof(BaseLoadGlobal) });
            registry.Initialize(7000);
            Check(Events.Take(2).SequenceEqual(new[] { "mod-load:ZBase", "mod-load:AChild" }), "Dependency lifecycle order on retry");
            Check(Order(registry.LoadPlan) == "ZBase,AChild", "Registry retains reviewed plan");
            Check(registry.ItemType("AChild/ChildLoadBlade") == 7000 && registry.ItemType("ZBase/BaseLoadBlade") == 7001, "Item IDs stay canonical by name");
            Check(registry.Create(7000).damage == 50, "GlobalItem chain follows dependency order");
            Check(registry.Recipes.Select(r => r.ResultType).SequenceEqual(new[] { 7001, 7000 }), "Recipes follow dependency lifecycle");
            Check(Events.IndexOf("static:ZBase") < Events.IndexOf("static:AChild"), "Static defaults dependency order");
        }
        Check(Events.TakeLast(2).SequenceEqual(new[] { "mod-unload:AChild", "mod-unload:ZBase" }), "Reverse mod unload");
        Check(Events.Where(e => e.StartsWith("content-unload:")).SequenceEqual(new[] { "content-unload:AChild/global", "content-unload:AChild/item",
            "content-unload:ZBase/global", "content-unload:ZBase/item" }), "Reverse content unload");
        Events.Clear(); FailChild = true;
        var failure = new MobileContentRegistry();
        failure.Add(new ChildLoadMod(), Array.Empty<Type>(), manifest: Manifest("AChild", required: "ZBase"));
        failure.Add(new BaseLoadMod(), Array.Empty<Type>());
        Reject<ApplicationException>(() => failure.Initialize(7000));
        failure.Dispose();
        Check(Events.SequenceEqual(new[] { "mod-load:ZBase", "mod-load:AChild", "mod-unload:AChild", "mod-unload:ZBase" }), "Failed Load cleans started mods once in reverse order");
        FailChild = false;
        var info = Archive("InfoMod", Info(w => { w.Write("side"); w.Write((byte)ModSide.Client); }));
        var mod = new InfoLoadMod();
        using (var registry = new MobileContentRegistry())
        {
            registry.Add(mod, new[] { typeof(InfoLoadGlobal) }, info); registry.Initialize(7000);
            Check(mod.Side == ModSide.Client && mod.Version == new Version(1, 0) && InfoLoadGlobal.SawMetadata, "Info bound before loading filter");
        }
        Check(mod.Side == ModSide.Both && !mod.FileExists("Info"), "Metadata/resources released on unload");
        using (var registry = new MobileContentRegistry())
        {
            Reject<ArgumentException>(() => registry.Add(new InfoLoadMod(), Array.Empty<Type>(), info, Manifest("Other")));
            Reject<ArgumentException>(() => registry.Add(new InfoLoadMod(), Array.Empty<Type>(), info, Manifest("InfoMod")));
            Reject<NotSupportedException>(() => registry.Add(new InfoLoadMod(), Array.Empty<Type>(), Archive("InfoMod", Info(w => w.Write("futureTag")))));
            // A failed metadata parse did not reserve the mod identity.
            registry.Add(new InfoLoadMod(), Array.Empty<Type>(), info); registry.Initialize(7000);
            Check(registry.LoadPlan.IsValid, "Retry Add after rejected metadata");
        }
    }
}
sealed class BaseLoadMod : Mod
{
    public override string Name => "ZBase";
    public override void Load() => ModLoadTests.Events.Add("mod-load:ZBase");
    public override void Unload() => ModLoadTests.Events.Add("mod-unload:ZBase");
}
sealed class ChildLoadMod : Mod
{
    public override string Name => "AChild";
    public override void Load()
    {
        ModLoadTests.Events.Add("mod-load:AChild");
        if (!ModLoader.Mods.Select(m => m.Name).SequenceEqual(new[] { "ZBase", "AChild" }) || !ModLoader.HasMod("ZBase"))
            throw new Exception("Scoped loader order/lookup");
        if (ModLoadTests.FailChild) throw new ApplicationException("Failed child Load");
    }
    public override void Unload() => ModLoadTests.Events.Add("mod-unload:AChild");
}
sealed class BaseLoadBlade : ModItem
{
    public override void SetDefaults() => Item.damage = 10;
    public override void SetStaticDefaults() { ModLoadTests.BaseReady = true; ModLoadTests.Events.Add("static:ZBase"); }
    public override void AddRecipes() => CreateRecipe().AddIngredient(1).Register();
    public override void Unload() => ModLoadTests.Events.Add("content-unload:ZBase/item");
}
sealed class ChildLoadBlade : ModItem
{
    public override void SetDefaults() => Item.damage = 20;
    public override void SetStaticDefaults()
    {
        if (!ModLoadTests.BaseReady) throw new Exception("Provider content not initialized");
        ModLoadTests.Events.Add("static:AChild");
    }
    public override void AddRecipes() => CreateRecipe().AddIngredient(1).Register();
    public override void Unload() => ModLoadTests.Events.Add("content-unload:AChild/item");
}
sealed class BaseLoadGlobal : GlobalItem
{
    public override void SetDefaults(Item item) => item.damage += 5;
    public override void Unload() => ModLoadTests.Events.Add("content-unload:ZBase/global");
}
sealed class ChildLoadGlobal : GlobalItem
{
    public override void SetDefaults(Item item) => item.damage *= 2;
    public override void Unload() => ModLoadTests.Events.Add("content-unload:AChild/global");
}
sealed class InfoLoadMod : Mod { public override string Name => "InfoMod"; }
sealed class InfoLoadGlobal : GlobalItem
{
    internal static bool SawMetadata;
    public override bool IsLoadingEnabled(Mod mod) => SawMetadata = mod.Side == ModSide.Client && mod.Version == new Version(1, 0);
}
