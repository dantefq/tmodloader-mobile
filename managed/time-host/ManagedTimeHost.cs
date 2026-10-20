using System;
using System.Reflection;
using System.Runtime.InteropServices;
using Terraria.GameContent.Creative;
using Terraria.ModLoader;
using Terraria.ModLoader.Config;

namespace TerrariaMobile.Managed;

// The original user-owned ChangeSleepTime DLL supplies the behavior.
public static class ManagedTimeHost
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Rates { public double Time, Tile, Event; }
    private static ModSystem system;
    private static object config;
    private static FieldInfo multiplier;
    private static readonly object Gate = new object();
    private static void Load()
    {
        if (system != null) return;
        Assembly assembly = Assembly.Load(new AssemblyName("ChangeSleepTime"));
        Type systemType = null, configType = null;
        int systems = 0, configs = 0;
        foreach (Type type in assembly.GetTypes())
        {
            if (!type.IsAbstract && typeof(ModSystem).IsAssignableFrom(type)) { systemType = type; systems++; }
            if (!type.IsAbstract && typeof(ModConfig).IsAssignableFrom(type)) { configType = type; configs++; }
        }
        if (systems != 1 || configs != 1 || systemType.FullName != "AdjustTimeRate" || configType.FullName != "Config")
            throw new InvalidOperationException("Audited mod types differ");
        config = typeof(ModContent).GetMethod("GetInstance").MakeGenericMethod(configType).Invoke(null, null);
        multiplier = configType.GetField("SleepTimeMultiplier");
        if (multiplier == null || multiplier.FieldType != typeof(int) || (int)multiplier.GetValue(config) != 5)
            throw new InvalidOperationException("DefaultValue config behavior differs");
        system = (ModSystem)Activator.CreateInstance(systemType);
    }
    // Flags: bit0 game menu, bit1 freeze. Counts are snapshots, never fabricated by a mod hook.
    public static Rates Evaluate(int flags, int active, int sleeping, int targetRate, int configuredMultiplier)
    {
        lock (Gate)
        {
            Load();
            if ((flags & ~3) != 0 || active < 0 || active > 256 || sleeping < 0 || sleeping > active ||
                targetRate < 1 || targetRate > 1000 || configuredMultiplier < 0 || configuredMultiplier > 100)
                throw new ArgumentOutOfRangeException("Invalid time snapshot");
            Terraria.Main.gameMenu = (flags & 1) != 0;
            Terraria.Main.CurrentFrameFlags.ActivePlayersCount = active;
            Terraria.Main.CurrentFrameFlags.SleepingPlayersCount = sleeping;
            CreativePowerManager.Instance.GetPower<CreativePowers.ModifyTimeRate>().TargetTimeRate = targetRate;
            CreativePowerManager.Instance.GetPower<CreativePowers.FreezeTime>().Enabled = (flags & 2) != 0;
            multiplier.SetValue(config, configuredMultiplier);
            double time = 1, tile = 1, events = 1;
            system.ModifyTimeRate(ref time, ref tile, ref events);
            return new Rates { Time = time, Tile = tile, Event = events };
        }
    }
    public static int GetHandlerCount() { lock (Gate) { Load(); return 1; } }
    public static int SelfTest()
    {
        int[][] inputs = {
            new[]{0,1,0,1,5}, new[]{0,1,1,1,5}, new[]{0,2,1,1,5},
            new[]{0,1,1,1,10}, new[]{1,1,1,1,5}, new[]{2,1,1,1,5},
            new[]{3,1,1,1,5}, new[]{0,1,1,3,5}, new[]{0,1,1,1,0},
            new[]{0,1,1,1000,100}
        };
        double[] expected = {1,5,1,10,1,0,1,15,0,86400};
        for (int i = 0; i < inputs.Length; i++)
        {
            int[] p = inputs[i];
            Rates r = Evaluate(p[0], p[1], p[2], p[3], p[4]);
            double other = i == inputs.Length - 1 ? 100000 : expected[i];
            if (r.Time != expected[i] || r.Tile != other || r.Event != other)
                throw new InvalidOperationException("Original mod result differs at case " + i);
        }
        return inputs.Length;
    }
    public static int StressGc()
    {
        int total = 0;
        for (int i = 0; i < 2048; i++) { byte[] b = new byte[8192]; b[i % b.Length] = (byte)i; total += b.Length; }
        GC.Collect();
        if (SelfTest() != 10) throw new InvalidOperationException("Post-GC state differs");
        return total;
    }
}
