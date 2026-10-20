using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using Terraria;
using Terraria.ModLoader;
using Terraria.ModLoader.Config;
using Terraria.GameContent.Creative;
using TerrariaMobile.Managed;

static class TimeLifecycleTests
{
    internal static readonly List<string> Events=new();
    internal static bool FailHook, FailLoad;
    static int checks;
    internal static void Check(bool ok,string message) { if(!ok)throw new Exception(message);checks++; }
    static void Reject<T>(Action action) where T:Exception
    { try {action();} catch(T) {checks++;return;} throw new Exception("Expected "+typeof(T)); }
    static MobileContentRegistry Make(bool second=true)
    {
        var r=new MobileContentRegistry();
        if(second)r.Add(new TimeBMod(),new[]{typeof(TimeBSystem)});
        r.Add(new TimeAMod(),new[]{typeof(TimeASystem),typeof(TimeConfig),typeof(TimeBlade)});
        r.Initialize(6196);return r;
    }
    public static void Run()
    {
        using(var a=Make())
        using(var b=Make(false))
        {
            Check(a.SystemCount==2&&b.SystemCount==1&&a.GlobalCount==0,"Separate system/global registries");
            Check(a.Create(6196).damage==37,"Item and time coexist");
            Check(a.EvaluateTimeRate(false,1,1)==(6d,7d,8d),"Order A then B, independent of insertion");
            Check(b.EvaluateTimeRate(false,1,1)==(5d,5d,5d),"Initial config");
            a.Configure<TimeConfig>(c=>{
                Check(ReferenceEquals(c,ModContent.GetInstance<TimeConfig>()),"Config singleton lookup");
                Check(c.Enabled,"Property DefaultValue");c.Multiplier=10;
            });
            Check(a.EvaluateTimeRate(false,1,1)==(11d,12d,13d),"Configured hooks compose");
            Check(b.EvaluateTimeRate(false,1,1)==(5d,5d,5d),"Registry configs isolated");
            Check(b.EvaluateTimeRate(false,2,1)==(1d,1d,1d),"Partial sleep snapshot");
            Check(b.EvaluateTimeRate(true,1,1)==(1d,1d,1d),"Menu snapshot");
            Check(b.EvaluateTimeRate(false,1,1,3)==(15d,15d,15d),"Creative rate snapshot");
            Check(b.EvaluateTimeRate(false,1,1,1,true)==(0d,0d,0d),"Freeze snapshot");
            Main.gameMenu=true;Main.CurrentFrameFlags.ActivePlayersCount=42;Main.CurrentFrameFlags.SleepingPlayersCount=41;
            b.EvaluateTimeRate(false,1,1);
            Check(Ambient(),"Ambient restored on success");
            FailHook=true;
            try {Reject<ApplicationException>(()=>b.EvaluateTimeRate(false,1,1));} finally {FailHook=false;}
            Check(Ambient(),"Ambient restored on exception");
            Check(b.EvaluateTimeRate(false,1,1)==(5d,5d,5d),"Hook recovers");
            Reject<NotSupportedException>(()=>ModContent.GetInstance<TimeConfig>());
            Reject<NotSupportedException>(()=>CreativePowerManager.Instance.GetPower<CreativePowers.FreezeTime>());
            Reject<ArgumentOutOfRangeException>(()=>a.EvaluateTimeRate(false,1,2));
            Reject<ArgumentOutOfRangeException>(()=>a.EvaluateTimeRate(false,1,1,0));
            Reject<KeyNotFoundException>(()=>a.Configure(typeof(UnregisteredTimeConfig),c=>{}));
            Reject<ArgumentNullException>(()=>a.Configure<TimeConfig>(null));
            Events.Clear();a.Dispose();a.Dispose();
            Check(Events.SequenceEqual(new[]{"B.system-unload","A.system-unload","B.mod-unload","A.mod-unload"}),"Reverse unload exactly once");
            Reject<InvalidOperationException>(()=>a.EvaluateTimeRate(false,1,1));
            Reject<InvalidOperationException>(()=>a.Configure<TimeConfig>(c=>{}));
            Check(b.EvaluateTimeRate(false,1,1)==(5d,5d,5d),"Other registry unaffected by disposal");
        }
        Events.Clear();FailLoad=true;
        try {Reject<ApplicationException>(()=>Make(false));} finally {FailLoad=false;}
        Check(Events.Contains("A.system-unload")&&Events.Contains("A.mod-unload"),"Failed system Load cleaned");
        Reject<NotSupportedException>(()=>ModContent.GetInstance<TimeConfig>());
        Main.gameMenu=false;Main.CurrentFrameFlags.ActivePlayersCount=Main.CurrentFrameFlags.SleepingPlayersCount=0;
        Console.WriteLine($"PASS {checks} unified time/config/lifecycle checks; managed snapshots only");
    }
    static bool Ambient()=>Main.gameMenu&&Main.CurrentFrameFlags.ActivePlayersCount==42&&Main.CurrentFrameFlags.SleepingPlayersCount==41;
}
sealed class TimeAMod:Mod
{
    public override string Name=>"ATime";
    public override void Load()=>TimeLifecycleTests.Check(ModContent.GetInstance<TimeConfig>().Multiplier==5,"Config ready at Mod.Load");
    public override void Unload()=>TimeLifecycleTests.Events.Add("A.mod-unload");
}
sealed class TimeBMod:Mod
{ public override string Name=>"BTime";public override void Unload()=>TimeLifecycleTests.Events.Add("B.mod-unload"); }
sealed class TimeConfig:ModConfig
{
    public override ConfigScope Mode=>ConfigScope.ServerSide;
    [DefaultValue(5)] public int Multiplier=1;
    [DefaultValue(true)] public bool Enabled {get;set;}
}
sealed class UnregisteredTimeConfig:ModConfig {public override ConfigScope Mode=>ConfigScope.ClientSide;}
sealed class TimeASystem:ModSystem
{
    private readonly TimeConfig config;
    public TimeASystem()
    {
        config=ModContent.GetInstance<TimeConfig>();
        TimeLifecycleTests.Check(config.Multiplier==5,"Staged config ready at content constructor");
    }
    public override void Load()
    {
        TimeLifecycleTests.Check(ReferenceEquals(this,ModContent.GetInstance<TimeASystem>()),"System singleton at Load");
        TimeLifecycleTests.Check(ReferenceEquals(config,ModContent.GetInstance<TimeConfig>()),"Constructor config committed unchanged");
        if(TimeLifecycleTests.FailLoad)throw new ApplicationException("Intentional system load failure");
    }
    public override void Unload()=>TimeLifecycleTests.Events.Add("A.system-unload");
    public override void ModifyTimeRate(ref double time,ref double tile,ref double events)
    {
        if(TimeLifecycleTests.FailHook)throw new ApplicationException("Intentional hook failure");
        if(Main.gameMenu||Main.CurrentFrameFlags.SleepingPlayersCount!=Main.CurrentFrameFlags.ActivePlayersCount)return;
        int rate=CreativePowerManager.Instance.GetPower<CreativePowers.FreezeTime>().Enabled?0:
            CreativePowerManager.Instance.GetPower<CreativePowers.ModifyTimeRate>().TargetTimeRate*ModContent.GetInstance<TimeConfig>().Multiplier;
        time=tile=events=rate;
    }
}
sealed class TimeBSystem:ModSystem
{
    public override void ModifyTimeRate(ref double time,ref double tile,ref double events){time+=1;tile+=2;events+=3;}
    public override void Unload()=>TimeLifecycleTests.Events.Add("B.system-unload");
}
sealed class TimeBlade:ModItem {public override void SetDefaults(){Item.damage=37;}}
