using System;
using System.Collections.Generic;
using Terraria;
using Terraria.ModLoader;
using Terraria.ModLoader.IO;
using TerrariaMobile.Managed;

static class RegistryTests
{
    static int checks;
    public static readonly List<string> Events = new();
    static void Check(bool value, string message)
    {
        if (!value) throw new Exception(message);
        checks++;
    }
    static void Reject<T>(Action action) where T : Exception
    {
        try { action(); } catch (T) { checks++; return; }
        throw new Exception("Expected " + typeof(T));
    }
    static MobileContentRegistry Registry(int start, bool reverse = false)
    {
        var r = new MobileContentRegistry();
        r.Add(new TestMod(), reverse ? new[] { typeof(ZBlade), typeof(ABlade), typeof(StatefulGlobal) }
                                   : new[] { typeof(StatefulGlobal), typeof(ABlade), typeof(ZBlade) });
        r.Initialize(start); return r;
    }
    public static int Main()
    {
        TextureBridgeChecks.Run();
        using (var r = Registry(6196))
        {
            Check(r.ItemType("Test/ABlade") == 6196 && r.ItemType("Test/ZBlade") == 6197, "Canonical content order");
            Check(Events[0] == "mod-load" && Events[^1] == "post-setup", "Lifecycle order");
            Check(r.Recipes.Count == 1 && r.Recipes[0].ResultType == 6196, "Recipe content lookup");
            Check(r.Recipes[0].Ingredients[3507] == 2 && r.Recipes[0].Tiles[0] == 16, "Recipe graph data");
            Reject<InvalidOperationException>(() => r.Recipes[0].AddIngredient(1));
            Reject<NotSupportedException>(() => Recipe.Create(1).Register());
            Reject<NotSupportedException>(() => ModContent.ItemType<ABlade>());
            Reject<NotSupportedException>(() => r.Save(r.Create(3507, 5)));
            Reject<NotSupportedException>(() => r.TryRestore(new TagCompound { ["format"] = 1, ["vanillaType"] = 3507 }, out _));
            Reject<InvalidOperationException>(() => r.Add(new TestMod(), Array.Empty<Type>()));
            var a = r.Create(6196); var b = r.Create(6196);
            Check(a.damage == 40 && a.Name == "Portable Blade", "Defaults and global chain");
            Check(a.ModItem != b.ModItem && ReferenceEquals(a.ModItem.Item, a), "Bound entity identity");
            a.GetGlobalItem<StatefulGlobal>().Counter = 17;
            Check(b.GetGlobalItem<StatefulGlobal>().Counter == 0, "Per-entity GlobalItem isolation");
            ((ABlade)a.ModItem).Charges = 9; a.stack = 2; a.prefix = 3; a.favorite = true;
            var cloned = r.Clone(a);
            Check(cloned != a && cloned.ModItem != a.ModItem && ReferenceEquals(cloned.ModItem.Item, cloned), "Item clone owns bound ModItem");
            Check(((ABlade)cloned.ModItem).Charges == 9 && cloned.GetGlobalItem<StatefulGlobal>().Counter == 17,
                  "Clone preserves custom item/global data");
            cloned.GetGlobalItem<StatefulGlobal>().Counter = 99;
            Check(a.GetGlobalItem<StatefulGlobal>().Counter == 17 && cloned.stack == 2 && cloned.favorite,
                  "Clone isolates per-entity state and preserves base fields");
            var saved = r.Save(a);
            Check(saved.GetString("content") == "Test/ABlade" && !saved.ContainsKey("vanillaType"), "Stable save identity");
            using (var next = Registry(7000, true))
            {
                Check(next.TryRestore(saved, out var restored) && restored.type == 7000, "Restore after runtime ID change");
                Check(((ABlade)restored.ModItem).Charges == 9 && restored.GetGlobalItem<StatefulGlobal>().Counter == 17, "Custom save hooks");
                Check(restored.stack == 2 && restored.prefix == 3 && restored.favorite, "Item state restoration");
            }
            using (var missing = new MobileContentRegistry())
            {
                missing.Initialize(6196);
                Check(!missing.TryRestore(saved, out var absent) && absent == null, "Missing mod fails without substitution");
                Check(saved.GetCompound("data").GetInt("charges") == 9, "Missing mod data retained");
            }
            var invalid = new TagCompound { ["format"] = 2 };
            Reject<ArgumentException>(() => r.TryRestore(invalid, out _));
            saved["stack"] = 100;
            Reject<ArgumentException>(() => r.TryRestore(saved, out _));
            saved["stack"] = 2;
            saved.GetCompound("globals")["Missing/Global"] = new TagCompound();
            Check(!r.TryRestore(saved, out _), "Missing GlobalItem rejects partial restore");
            r.Dispose(); r.Dispose();
            Reject<InvalidOperationException>(() => r.Create(6196));
        }
        using (var r = new MobileContentRegistry())
        {
            Reject<NotSupportedException>(() => r.Add(new TestMod(), new[] { typeof(Unsupported) }));
            r.Add(new TestMod(), new[] { typeof(ABlade) }); // Rejected add did not leave a mod behind.
            Reject<InvalidOperationException>(() => r.Add(new TestMod(), Array.Empty<Type>()));
            Reject<ArgumentOutOfRangeException>(() => r.Initialize(int.MaxValue));
            r.Initialize(6196);
            Check(r.ItemType("Test/ABlade") == 6196, "Failed initialization remains recoverable");
        }
        var tag = new TagCompound { ["n"] = 2 };
        Check(tag.GetInt("missing") == 0 && tag.GetString("missing") == "", "Absent tag defaults");
        Reject<System.IO.IOException>(() => tag.GetString("n"));
        FailureMod.Unloads = FailureItem.Unloads = 0;
        using (var failing = new MobileContentRegistry())
        {
            failing.Add(new FailureMod(), new[] { typeof(FailureItem) });
            Reject<ApplicationException>(() => failing.Initialize(6196));
            Check(FailureMod.Unloads == 1 && FailureItem.Unloads == 1, "Failed load invokes cleanup exactly once");
            Reject<InvalidOperationException>(() => failing.Create(6196));
        }
        Check(FailureMod.Unloads == 1 && FailureItem.Unloads == 1, "Cleanup is idempotent after load failure");
        using (var r = new MobileContentRegistry())
        {
            r.Add(new TestMod(), new[] { typeof(CloneBlade), typeof(DisabledBlade), typeof(SharedGlobal), typeof(FilteredGlobal) });
            r.Initialize(6196);
            Check(r.ItemNames.Count == 1, "Disabled content excluded before ID assignment");
            var a = r.Create(6196); var b = r.Create(6196);
            Check(((CloneBlade)a.ModItem).TemplateValue == 23 && ((CloneBlade)b.ModItem).TemplateValue == 23,
                  "CloneNewInstances preserves initialized template data");
            Check(ReferenceEquals(a.GetGlobalItem<SharedGlobal>(), b.GetGlobalItem<SharedGlobal>()), "Singleton global shared");
            Check(ReferenceEquals(a.GetGlobalItem<SharedGlobal>(), r.Clone(a).GetGlobalItem<SharedGlobal>()), "Clone retains shared global singleton");
            Check(!a.TryGetGlobalItem<FilteredGlobal>(out _), "Conditional global excluded");
            Reject<InvalidOperationException>(() => a.GetGlobalItem<FilteredGlobal>());
        }
        Console.WriteLine($"PASS {checks} managed registry checks; no Android device used");
        PersistenceTests.Run();
        StatModifierTests.Run();
        ArchiveTests.Run();
        RegistryImageTests.Run();
        TexturePacketTests.Run();
        DamageClassTests.Run();
        NpcHitTests.Run();
        ModLoadTests.Run();
        TimeLifecycleTests.Run();
        return 0;
    }
}
sealed class TestMod : Mod
{
    public override string Name => "Test";
    public override void Load() => RegistryTests.Events.Add("mod-load");
    public override void PostSetupContent() => RegistryTests.Events.Add("post-setup");
}
sealed class ABlade : ModItem
{
    public int Charges;
    public override void SetDefaults() { Item.damage = 37; Item.maxStack = 3; Item.SetNameOverride("Portable Blade"); }
    public override void SaveData(TagCompound tag) => tag["charges"] = Charges;
    public override void LoadData(TagCompound tag) => Charges = tag.GetInt("charges");
    public override void AddRecipes()
    {
        if (ModContent.Find<ABlade>("Test", "ABlade") != this || ModContent.ItemType<ABlade>() != Type)
            throw new Exception("Content resolver differs");
        if (!Mod.TryFind<ABlade>("ABlade", out var found) || found != this || ModContent.TryFind<ABlade>("Test/ZBlade", out _))
            throw new Exception("Typed lookup differs");
        if (ModContent.GetInstance<ABlade>().Item.damage != 37)
            throw new Exception("Template defaults missing");
        CreateRecipe().AddIngredient(3507).AddIngredient(3507).AddTile(16).Register();
    }
}
sealed class ZBlade : ModItem { }
sealed class StatefulGlobal : GlobalItem
{
    public int Counter;
    public override bool InstancePerEntity => true;
    public override void SetDefaults(Item item) => item.damage += 3;
    public override void SaveData(Item item, TagCompound tag) => tag["counter"] = Counter;
    public override void LoadData(Item item, TagCompound tag) => Counter = tag.GetInt("counter");
}
sealed class Unsupported { }
sealed class FailureMod : Mod
{
    public static int Unloads;
    public override string Name => "Failure";
    public override void Unload() => Unloads++;
}
sealed class FailureItem : ModItem
{
    public static int Unloads;
    public override void Load() => throw new ApplicationException("Intentional failure");
    public override void Unload() => Unloads++;
}
sealed class CloneBlade : ModItem
{
    public int TemplateValue;
    protected override bool CloneNewInstances => true;
    public override void SetStaticDefaults() => TemplateValue = 23;
}
sealed class DisabledBlade : ModItem
{
    public override bool IsLoadingEnabled(Mod mod) => false;
}
sealed class SharedGlobal : GlobalItem { }
sealed class FilteredGlobal : GlobalItem
{
    public override bool AppliesToEntity(Item entity, bool lateInstantiation) => false;
}
