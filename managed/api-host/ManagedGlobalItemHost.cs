using System;
using System.Reflection;
using System.Collections.Generic;
using Terraria;
using Terraria.ModLoader;

namespace TerrariaMobile.Managed;

// Snapshot adapter: copy supported item fields in, invoke PC-style hooks, copy out.
// No general tModLoader lifecycle, object identity, content or save compatibility.
public static class ManagedSwordDemo
{
    private static GlobalItem[] globals;
    private static GlobalItem[] GetGlobals()
    {
        if (globals != null) return globals;
        var assembly = Assembly.Load(new AssemblyName("PcGlobalItemDemo"));
        var found = new List<GlobalItem>();
        foreach (var type in assembly.GetTypes())
            if (!type.IsAbstract && typeof(GlobalItem).IsAssignableFrom(type))
                found.Add((GlobalItem)Activator.CreateInstance(type));
        if (found.Count != 1) throw new InvalidOperationException("Expected one own GlobalItem handler");
        return globals = found.ToArray();
    }
    private static Item Apply(int type, int damage)
    {
        var item = new Item { type = type, damage = damage };
        foreach (var global in GetGlobals()) global.SetDefaults(item);
        return item;
    }
    public static int GetDamage(int itemType, int vanillaDamage) => Apply(itemType, vanillaDamage).damage;
    public static string GetName(int itemType) => Apply(itemType, 5).Name;
    public static int GetHandlerCount() => GetGlobals().Length;
    public static int StressGc()
    {
        int total = 0;
        for (int i = 0; i < 2048; i++)
        {
            byte[] buffer = new byte[8192];
            buffer[i % buffer.Length] = (byte)i;
            total += buffer.Length;
        }
        GC.Collect();
        return total;
    }
}
