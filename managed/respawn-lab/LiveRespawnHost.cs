using System;
using System.ComponentModel;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Xna.Framework;
using Mono.Cecil;
using Mono.Cecil.Cil;
using MonoMod.Cil;
using Terraria;
using Terraria.ModLoader;

namespace TerrariaMobile.Managed;

// Snapshot transport for the original DLL. Native pointers never enter Mono.
// The narrow IL request is audited here; a separate native lease implements it.
public static class LiveRespawnHost
{
    private static readonly object Gate = new();
    private static Mod mod;
    private static ModPlayer playerMod;
    private static Type configType, playerType;
    private static object config;
    private static int session;
    public static int Initialize()
    {
        lock (Gate)
        {
            if (mod != null) return int.MaxValue;
            var path = Path.Combine(Path.GetDirectoryName(typeof(LiveRespawnHost).Assembly.Location), "ShorterRespawn.dll");
            if (Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path))).ToLowerInvariant() !=
                "aeaf65ac9b0699950ebbd033f42891c298f807fa07d665da67c77adf2d4b5e9a")
                throw new InvalidOperationException("Original respawn DLL identity differs");
            var source = Assembly.LoadFrom(path);
            configType = source.GetType("ShorterRespawn.ShorterRespawnConfig", true);
            playerType = source.GetType("ShorterRespawn.ShorterRespawnPlayer", true);
            config = Activator.CreateInstance(configType);
            foreach (var property in configType.GetProperties())
            {
                var value = property.GetCustomAttribute<DefaultValueAttribute>();
                if (value != null) property.SetValue(config, value.Value);
            }
            ModContent.RegisterSnapshot(config);
            var next = (Mod)Activator.CreateInstance(source.GetType("ShorterRespawn.ShorterRespawn", true));
            try
            {
                next.Load();
                if (IL_Player.RecordedCount != 1) throw new InvalidOperationException("Unexpected IL request count");
                AuditClampRequest();
                mod = next;
                return int.MaxValue;
            }
            catch { next.Unload(); IL_Player.ClearRecorded(); ModContent.ClearSnapshots(); throw; }
        }
    }
    private static void AuditClampRequest()
    {
        // This is independently written input, not a copy of game IL. The
        // original manipulator must request exactly the audited literal rewrite.
        using var module = ModuleDefinition.CreateModule("MobileRespawnClampAudit", ModuleKind.Dll);
        var type = new TypeDefinition("MobileLab", "Clamp", Mono.Cecil.TypeAttributes.Public, module.TypeSystem.Object);
        module.Types.Add(type);
        var method = new MethodDefinition("AuditOnly", Mono.Cecil.MethodAttributes.Public | Mono.Cecil.MethodAttributes.Static, module.TypeSystem.Void);
        type.Methods.Add(method);
        var body = method.Body.Instructions;
        var first = Instruction.Create(OpCodes.Ldc_I4, 3600);
        var pop1 = Instruction.Create(OpCodes.Pop);
        var second = Instruction.Create(OpCodes.Ldc_I4, 3600);
        var pop2 = Instruction.Create(OpCodes.Pop);
        var ret = Instruction.Create(OpCodes.Ret);
        foreach (var instruction in new[] { first, pop1, second, pop2, ret }) body.Add(instruction);
        using (var context = new ILContext(method)) IL_Player.ApplyRecorded(context);
        if (body.Count != 9 || body[0] != first || body[3] != pop1 || body[4] != second || body[7] != pop2 || body[8] != ret)
            throw new NotSupportedException("Unrecognized original IL rewrite");
        foreach (int index in new[] { 1, 5 })
            if (body[index].OpCode != OpCodes.Pop || body[index + 1].OpCode != OpCodes.Ldc_I4 ||
                !Equals(body[index + 1].Operand, int.MaxValue)) throw new NotSupportedException("Unrecognized clamp replacement");
    }
    public static int Evaluate(string json)
    {
        lock (Gate)
        {
            Initialize();
            if (json == null || json.Length > 65536) throw new ArgumentException("Snapshot size outside bounds");
            using var document = JsonDocument.Parse(json, new JsonDocumentOptions { MaxDepth = 8 });
            var row = document.RootElement;
            int Number(string key, int min, int max)
            {
                int value = row.GetProperty(key).GetInt32();
                if (value < min || value > max) throw new ArgumentOutOfRangeException(key);
                return value;
            }
            float Coordinate(JsonElement value)
            {
                float f = value.GetSingle();
                if (!float.IsFinite(f) || Math.Abs(f) > 1000000000) throw new ArgumentOutOfRangeException("coordinate");
                return f;
            }
            int token = Number("session", 1, int.MaxValue), seconds = Number("seconds", 0, 3600);
            int timer = Number("timer", 0, int.MaxValue), npcCount = Number("npcCount", 1, 512);
            string phase = row.GetProperty("phase").GetString();
            if (phase != "kill" && phase != "dead") throw new ArgumentException("Unknown callback phase");
            int direction = Number("direction", -1, 1);
            double damage = row.GetProperty("damage").GetDouble();
            if (!double.IsFinite(damage) || damage < 0 || damage > 1000000000) throw new ArgumentOutOfRangeException("damage");
            if (playerMod == null || session != token)
            {
                playerMod = (ModPlayer)Activator.CreateInstance(playerType);
                playerMod.Player = new Player { active = true };
                session = token;
            }
            void Set(string name, object value) => configType.GetProperty(name).SetValue(config, value);
            Set("UseSeconds", true);
            foreach (string name in new[] { "NormalRespawnTime", "NormalBossRespawnTime", "ExpertRespawnTime", "ExpertBossRespawnTime" }) Set(name, seconds);
            Set("AdjustRespawnTimeWhenBossDespawns", row.GetProperty("adjust").GetBoolean());
            playerMod.Player.Center = new Vector2(Coordinate(row.GetProperty("px")), Coordinate(row.GetProperty("py")));
            playerMod.Player.respawnTimer = timer;
            Terraria.Main.expertMode = row.GetProperty("expert").GetBoolean();
            if (Terraria.Main.npc.Length != npcCount)
            {
                Terraria.Main.npc = new NPC[npcCount];
                for (int i = 0; i < npcCount; i++) Terraria.Main.npc[i] = new NPC();
            }
            foreach (var npc in Terraria.Main.npc) npc.active = false;
            var seen = new bool[npcCount];
            foreach (var npc in row.GetProperty("npcs").EnumerateArray())
            {
                if (npc.GetArrayLength() != 5) throw new ArgumentException("NPC snapshot shape differs");
                int index = npc[0].GetInt32(), typeId = npc[1].GetInt32();
                if (index < 0 || index >= npcCount || seen[index] || typeId < 0 || typeId > 1000000)
                    throw new ArgumentException("NPC snapshot identity differs");
                seen[index] = true;
                var target = Terraria.Main.npc[index];
                target.active = true; target.type = typeId; target.boss = npc[2].GetBoolean();
                target.Center = new Vector2(Coordinate(npc[3]), Coordinate(npc[4]));
            }
            if (phase == "kill") playerMod.Kill(damage, direction, row.GetProperty("pvp").GetBoolean(), new Terraria.DataStructures.PlayerDeathReason());
            else playerMod.UpdateDead();
            return playerMod.Player.respawnTimer;
        }
    }
    private static void Reset()
    {
        mod?.Unload(); mod = null; playerMod = null; session = 0;
        IL_Player.ClearRecorded(); ModContent.ClearSnapshots(); Terraria.Main.npc = Array.Empty<NPC>();
    }
    public static int SelfTest()
    {
        lock (Gate)
        {
            int count = 0;
            void Check(bool condition) { if (!condition) throw new Exception("Live snapshot check " + count); count++; }
            string Input(string phase, int seconds, int timer, bool adjust = true, int token = 1) => JsonSerializer.Serialize(new {
                phase, seconds, timer, adjust, session = token, npcCount = 2, npcs = Array.Empty<int[]>(),
                direction = 1, damage = 100, expert = false, pvp = false, px = 0, py = 0 });
            try
            {
                Check(Initialize() == int.MaxValue);
                Check(Evaluate(Input("kill", 3, 600)) == 180);
                Check(Evaluate(Input("dead", 3, 181)) == 180);
                Check(Evaluate(Input("kill", 61, 600)) == 3660);
                Check(Evaluate(Input("dead", 61, 3660, false)) == 3660);
                Check(Evaluate(Input("kill", 5, 600, token: 2)) == 300);
                bool bad = false;
                try { Evaluate(Input("kill", -1, 600)); } catch (ArgumentOutOfRangeException) { bad = true; }
                Check(bad);
                bad = false;
                try { Evaluate(Input("unknown", 3, 600)); } catch (ArgumentException) { bad = true; }
                Check(bad);
                return count;
            }
            finally { Reset(); }
        }
    }
}
