using System;
using System.IO;
using System.Reflection;
using System.Runtime.Loader;
using System.Security.Cryptography;
using System.Text.Json;
using Terraria;
using Terraria.ModLoader;

// Narrow host probe. Only the pinned item's constructor and SetDefaults run.
// This is deliberately separate from full mod loading or content registration.
static class OriginalItemDefaultsProbe
{
    static int Main(string[] args)
    {
        try
        {
            if (args.Length != 2) throw new ArgumentException("Expected pinned assembly path and reviewed item type");
            if (args[1] is not ("SOTS.Items.HelicopterParts" or "SOTS.Items.Pyramid.Snakeskin" or "SOTS.Items.Fishing.Curgeon"))
                throw new ArgumentException("Item type has no reviewed defaults profile");
            var bytes = File.ReadAllBytes(args[0]);
            if (Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant() !=
                "e96d7591ec56f5236454931ae0a3045be6072d2a7649f70679131bf0f0ee338f")
                throw new InvalidDataException("Pinned assembly hash differs");
            using var stream = new MemoryStream(bytes, false);
            var assembly = AssemblyLoadContext.Default.LoadFromStream(stream);
            var type = assembly.GetType(args[1], true, false);
            if (type.BaseType != typeof(ModItem)) throw new InvalidDataException("Unexpected item base");
            var snapshots = new object[2];
            for (int i = 0; i < snapshots.Length; i++)
            {
                var modItem = (ModItem)Activator.CreateInstance(type);
                var item = new Item { type = 6196 + i };
                modItem.Bind(item);
                modItem.SetDefaults();
                snapshots[i] = new { item.type, item.width, item.height, item.value, item.rare, item.maxStack };
            }
            Console.WriteLine(JsonSerializer.Serialize(new {
                format = "original-item-defaults-host-v1", content_type = type.FullName,
                original_assembly_executed = true, mod_lifecycle_executed = false,
                static_defaults_executed = false, android_verified = false,
                rendering_verified = false, full_mod_compatible = false, snapshots
            }));
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e.GetType().Name + ": " + e.Message); return 2; }
    }
}
