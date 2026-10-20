using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Xna.Framework;
using Mono.Cecil;
using Mono.Cecil.Cil;
using MonoMod.Cil;
using Terraria;
using Terraria.ModLoader;

public static class OriginalRespawnChecks
{
    private static readonly List<object> results = new();
    private static string Root => Path.GetDirectoryName(typeof(OriginalRespawnChecks).Assembly.Location);
    private static void Equal(string name, int actual, int expected)
    {
        if (actual != expected) throw new Exception(name + ": " + actual + " != " + expected);
        results.Add(new { name, actual, expected });
    }
    public static void Main(string[] args) => Console.WriteLine(Run(args[0]));
    public static int RunAndroid()
    {
        try { File.WriteAllText(Path.Combine(Root, "callback-result.json"), Run(null)); return results.Count; }
        catch (Exception error)
        {
            File.WriteAllText(Path.Combine(Root, "callback-failure.txt"), error.ToString()); throw;
        }
    }
    public static int StressGc()
    {
        var blocks = new byte[16][];
        for (int i = 0; i < blocks.Length; i++) blocks[i] = new byte[1024 * 1024];
        GC.Collect(); GC.WaitForPendingFinalizers(); GC.KeepAlive(blocks);
        return 16 * 1024 * 1024;
    }
    public static string Run(string pcGamePath)
    {
        results.Clear();
        var dll = Path.Combine(Root, "ShorterRespawn.dll");
        var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(dll))).ToLowerInvariant();
        if (hash != "aeaf65ac9b0699950ebbd033f42891c298f807fa07d665da67c77adf2d4b5e9a")
            throw new Exception("Original mod DLL identity differs");
        if (pcGamePath != null) using (var source = ModuleDefinition.ReadModule(dll))
            File.WriteAllLines(Path.Combine(Root, "shorter-respawn-private-il.txt"),
                source.Types.SelectMany(t => t.Methods).Where(m => m.HasBody)
                    .SelectMany(m => new[] { m.FullName }.Concat(m.Body.Instructions.Select(i => i.ToString()))));
        var assembly = Assembly.LoadFrom(dll);
        var configType = assembly.GetType("ShorterRespawn.ShorterRespawnConfig", true);
        var config = Activator.CreateInstance(configType);
        foreach (var property in configType.GetProperties())
        {
            var defaults = property.GetCustomAttribute<DefaultValueAttribute>();
            if (defaults != null) property.SetValue(config, defaults.Value);
        }
        ModContent.RegisterSnapshot(config);
        var mod = (Mod)Activator.CreateInstance(assembly.GetType("ShorterRespawn.ShorterRespawn", true));
        mod.Load(); // Original entrypoint; the IL request is recorded, not installed.
        Equal("original-load-registered-hook", IL_Player.RecordedCount, 1);
        var playerMod = (ModPlayer)Activator.CreateInstance(assembly.GetType("ShorterRespawn.ShorterRespawnPlayer", true));
        playerMod.Player = new Player { active = true, Center = Vector2.Zero };
        void Set(string name, object value) => configType.GetProperty(name).SetValue(config, value);
        void Kill(string name, bool expert, bool boss, bool pvp, int expected)
        {
            Terraria.Main.expertMode = expert;
            // The original mod excludes the last NPC slot (the game's sentinel).
            Terraria.Main.npc = boss ? new[] { new NPC { active = true, boss = true, Center = Vector2.Zero }, new NPC() } : Array.Empty<NPC>();
            playerMod.Player.respawnTimer = 9999;
            playerMod.Kill(100, 1, pvp, new Terraria.DataStructures.PlayerDeathReason());
            Equal(name, playerMod.Player.respawnTimer, expected);
        }
        // Explicit behavioral expectations: this mod starts from 10s and
        // applies independent global/expert/boss scales.
        Set("UseSeconds", false);
        Set("GlobalRespawnScale", 0.5f); Set("ExpertPenaltyScale", 2f); Set("BossPenaltyScale", 2f);
        Kill("normal-scaled", false, false, false, 300);
        Kill("expert-scaled", true, false, false, 600);
        Kill("boss-scaled", false, true, false, 600);
        Kill("expert-boss-scaled", true, true, false, 1200);
        Kill("pvp-excludes-boss-penalty", false, true, true, 300);
        Set("UseSeconds", true);
        Set("NormalRespawnTime", 3); Set("ExpertRespawnTime", 4);
        Set("NormalBossRespawnTime", 7); Set("ExpertBossRespawnTime", 8);
        Kill("normal-seconds", false, false, false, 180);
        Kill("expert-seconds", true, false, false, 240);
        Kill("boss-seconds", false, true, false, 420);
        Kill("expert-boss-seconds", true, true, false, 480);
        Set("AdjustRespawnTimeWhenBossDespawns", true);
        Terraria.Main.npc = Array.Empty<NPC>();
        playerMod.UpdateDead();
        Equal("despawn-shortens-existing-timer", playerMod.Player.respawnTimer, 240);
        playerMod.Player.respawnTimer = 100; playerMod.UpdateDead();
        Equal("despawn-does-not-lengthen-timer", playerMod.Player.respawnTimer, 100);
        Set("AdjustRespawnTimeWhenBossDespawns", false);
        playerMod.Player.respawnTimer = 480; playerMod.UpdateDead();
        Equal("despawn-adjustment-disabled", playerMod.Player.respawnTimer, 480);
        // Apply the original manipulator to an offline copy of the installed PC
        // method. Never execute or write the PC game assembly.
        int matches = 0;
        if (pcGamePath != null)
        {
        using var game = ModuleDefinition.ReadModule(pcGamePath);
        var method = game.Types.Single(t => t.FullName == "Terraria.Player").Methods.Single(m => m.Name == "UpdateDead");
        var old = method.Body.Instructions.ToArray();
        matches = old.Count(i => i.OpCode == OpCodes.Ldc_I4 && Equals(i.Operand, 3600));
        if (matches == 0) throw new Exception("Audited clamp constant not found in PC UpdateDead");
        using (var context = new ILContext(method)) IL_Player.ApplyRecorded(context);
        var updated = method.Body.Instructions;
        Equal("offline-hook-added-pop-and-max-per-clamp", updated.Count - old.Length, matches * 2);
        foreach (var instruction in old.Where(i => i.OpCode == OpCodes.Ldc_I4 && Equals(i.Operand, 3600)))
        {
            int index = updated.IndexOf(instruction);
            if (updated[index + 1].OpCode != OpCodes.Pop || updated[index + 2].OpCode != OpCodes.Ldc_I4 ||
                !Equals(updated[index + 2].Operand, int.MaxValue)) throw new Exception("Unexpected IL rewrite");
        }
        }
        mod.Unload(); IL_Player.ClearRecorded(); ModContent.ClearSnapshots();
        int liveSnapshotChecks = TerrariaMobile.Managed.LiveRespawnHost.SelfTest();
        return JsonSerializer.Serialize(new { status = "passed-isolated-snapshots-only", dll_sha256 = hash,
            callbacks = results, pc_clamp_occurrences = matches, original_mod_dll_patched = false,
            live_snapshot_checks = liveSnapshotChecks,
            offline_pc_hook_applied = pcGamePath != null,
            native_hook_installed = false, post_setup_content_executed = false });
    }
}
