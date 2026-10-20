using System;
using System.Reflection;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using Terraria;
using Terraria.ModLoader;
using Terraria.ModLoader.IO;
using TerrariaMobile.Serialization;

namespace TerrariaMobile.Managed;

// One own ModItem backed by the common managed registry; mobile IDs stay pinned.
public static class ManagedSwordDemo
{
    private static MobileContentRegistry registry;
    private static MobileContentRegistry GetRegistry()
    {
#if TMAL_COMBINED_CONTENT
        return ManagedTimeHost.GetRegistry();
#else
        if (registry != null) return registry;
        var assembly = Assembly.Load(new AssemblyName("PcModItemDemo"));
        var next = MobileContentRegistry.FromAssembly(assembly, 6196);
        if (next.ItemNames.Count != 1 || next.GlobalCount != 0)
        {
            next.Dispose(); throw new InvalidOperationException("Expected one own ModItem");
        }
        return registry = next;
#endif
    }
    private static Item Apply(int type, int damage)
    {
        var item = GetRegistry().Create(type, damage);
        if (type == 6196)
        {
            var mod = item.ModItem;
            if (mod.Texture != "Terraria/Images/Item_3507") throw new InvalidOperationException("Unexpected texture alias");
        }
        return item;
    }
    public static int GetDamage(int type, int damage) => Apply(type, damage).damage;
    public static string GetName(int type) => Apply(type, 5).Name;
    public static int GetHandlerCount() { GetRegistry(); return 1; }
    // Isolated probe only: own bundled demo/resources and memory snapshots.
    // This does not read or write Terraria player/world files.
    public static int GetFoundationChecks()
    {
        int count = 0;
        void Check(bool ok) { if (!ok) throw new InvalidOperationException("Foundation check " + count); count++; }
        var root = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        var archive = MobileTmodArchive.FromFile(Path.Combine(root, "PcModItemDemo.tmod"));
        Check(archive.Name == "PcModItemDemo" && archive.HasFile("Info"));
        var manifest = MobileModManifest.FromArchive(archive);
        Check(MobileModLoadPlan.Build(new[] { manifest }).IsValid);
        Check(CryptographicOperations.FixedTimeEquals(SHA256.HashData(archive.GetBytes("PcModItemDemo.dll")),
            SHA256.HashData(File.ReadAllBytes(Path.Combine(root, "PcModItemDemo.dll")))));
        var r = GetRegistry(); var item = r.Create(6196); item.favorited = true;
        var clone = r.Clone(item); clone.favorited = false;
        Check(item.favorite && !clone.favorite && !ReferenceEquals(item.ModItem, clone.ModItem));
        var tag = MobileTagCodec.Decode(MobileTagCodec.Encode(r.Save(item)));
        Check(r.TryRestore(tag, out var restored) && restored.favorited && restored.damage == 37);
        var player = r.CreatePlayer(); player.GetDamage(DamageClass.Generic) += 0.5f;
        Check(player.GetTotalDamage(DamageClass.Melee).ApplyTo(10) == 15);
        var hit = new NPC.HitModifiers(); hit.Defense.Base = 20;
        Check(hit.GetDamage(100, false) == 90);
        var binding = new SidecarBinding(Guid.NewGuid(), Guid.NewGuid(), new byte[32]);
        var document = SidecarDocument.Capture(r, binding, new Dictionary<string, Item> { ["inventory/0"] = item });
        var decoded = SidecarDocument.Decode(document.Encode());
        Check(decoded.Binding.Matches(binding) && decoded.Restore(r).Items["inventory/0"].favorited);
        return count;
    }
    public static int StressGc()
    {
        int total = 0;
        for (int i = 0; i < 2048; i++)
        {
            var buffer = new byte[8192]; buffer[i % buffer.Length] = (byte)i;
            total += buffer.Length;
        }
        GC.Collect(); return total;
    }
}
