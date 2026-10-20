using System;
using System.Reflection;
using Terraria;
using Terraria.ModLoader;

namespace TerrariaMobile.Managed;

// Stateless snapshot test for one own ModItem. No arbitrary content lifecycle.
public static class ManagedSwordDemo
{
    private static Type content;
    private static Type GetContent()
    {
        if (content != null) return content;
        var assembly = Assembly.Load(new AssemblyName("PcModItemDemo"));
        foreach (var type in assembly.GetTypes())
            if (!type.IsAbstract && typeof(ModItem).IsAssignableFrom(type))
            {
                if (content != null) throw new InvalidOperationException("Expected one own ModItem");
                content = type;
            }
        return content ?? throw new InvalidOperationException("Own ModItem missing");
    }
    private static Item Apply(int type, int damage)
    {
        var item = new Item { type = type, damage = damage };
        if (type == 6196)
        {
            var mod = (ModItem)Activator.CreateInstance(GetContent());
            mod.Bind(item);
            if (mod.Texture != "Terraria/Images/Item_3507") throw new InvalidOperationException("Unexpected texture alias");
            mod.SetDefaults();
        }
        return item;
    }
    public static int GetDamage(int type, int damage) => Apply(type, damage).damage;
    public static string GetName(int type) => Apply(type, 5).Name;
    public static int GetHandlerCount() { GetContent(); return 1; }
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
