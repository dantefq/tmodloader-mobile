using System;
using System.Reflection;
using System.Collections.Generic;
using Terraria;
using Terraria.ModLoader;

namespace TerrariaMobile.Managed;

// Snapshot adapter: copy supported item fields in, invoke PC-style hooks, copy out.
// Common managed registry supplies lifecycle and per-entity global instances.
// Mobile bridge still transfers only type, damage and name.
public static class ManagedSwordDemo
{
    private static MobileContentRegistry registry;
    private static MobileContentRegistry GetRegistry()
    {
        if (registry != null) return registry;
        var assembly = Assembly.Load(new AssemblyName("PcGlobalItemDemo"));
        var next = MobileContentRegistry.FromAssembly(assembly, 6196);
        if (next.GlobalCount != 1 || next.ItemNames.Count != 0)
        {
            next.Dispose(); throw new InvalidOperationException("Expected one own GlobalItem handler");
        }
        return registry = next;
    }
    private static Item Apply(int type, int damage)
    {
        return GetRegistry().Create(type, damage);
    }
    public static int GetDamage(int itemType, int vanillaDamage) => Apply(itemType, vanillaDamage).damage;
    public static string GetName(int itemType) => Apply(itemType, 5).Name;
    public static int GetHandlerCount() => GetRegistry().GlobalCount;
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
