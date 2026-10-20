using System;
using System.Reflection;
using System.Runtime.InteropServices;
using Terraria.ModLoader;
using Terraria.ModLoader.Config;

namespace TerrariaMobile.Managed;

// The same source manifest and lifecycle as the item host. The original,
// hash-pinned ChangeSleepTime DLL supplies all rate-changing behavior.
public static class ManagedTimeHost
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Rates { public double Time, Tile, Event; }
    private static MobileContentRegistry registry;
    private static Type configType;
    private static FieldInfo multiplier;
    private static readonly object Gate = new();

    private static void Load()
    {
        if (registry != null) return;
        var assembly = Assembly.Load(new AssemblyName("ChangeSleepTime"));
        int systems=0, configs=0;
        foreach (var type in assembly.GetTypes())
        {
            if (!type.IsAbstract && typeof(ModSystem).IsAssignableFrom(type))
            {
                if (type.FullName!="AdjustTimeRate") throw new InvalidOperationException("Unexpected system");
                systems++;
            }
            if (!type.IsAbstract && typeof(ModConfig).IsAssignableFrom(type)) {configType=type;configs++;}
        }
        if (systems!=1 || configs!=1 || configType.FullName!="Config")
            throw new InvalidOperationException("Audited mod types differ");
        multiplier=configType.GetField("SleepTimeMultiplier");
        if (multiplier==null || multiplier.FieldType!=typeof(int)) throw new InvalidOperationException("Config field differs");
        var next=new MobileContentRegistry();
        try
        {
            foreach (var source in new[]{assembly,Assembly.Load(new AssemblyName("PcModItemDemo"))})
            {
                var types=source.GetTypes();Type mod=null;
                foreach(var type in types)
                    if(!type.IsAbstract && typeof(Mod).IsAssignableFrom(type))
                    {
                        if(mod!=null)throw new InvalidOperationException("Expected one mod per assembly");
                        mod=type;
                    }
                if(mod==null)throw new InvalidOperationException("Mod entry missing");
                next.Add((Mod)Activator.CreateInstance(mod),Array.FindAll(types,t=>!t.IsAbstract &&
                    (typeof(ModType).IsAssignableFrom(t)||typeof(ModConfig).IsAssignableFrom(t))));
            }
            next.Initialize(6196);
            if (next.SystemCount!=1 || next.ItemNames.Count!=1 || next.GlobalCount!=0)
                throw new InvalidOperationException("Unexpected content registry");
            next.Configure(configType,c=>{
                if ((int)multiplier.GetValue(c)!=5) throw new InvalidOperationException("Default config differs");
            });
            registry=next;
        }
        catch {next.Dispose();throw;}
    }
    // Both hosts share this one registry. Original mod static fields can cache
    // singleton configs, so a second registry for the same DLL is not created.
    internal static MobileContentRegistry GetRegistry() {lock(Gate){Load();return registry;}}

    public static Rates Evaluate(int flags,int active,int sleeping,int targetRate,int configuredMultiplier)
    {
        lock(Gate)
        {
            if ((flags&~3)!=0 || configuredMultiplier<0 || configuredMultiplier>100)
                throw new ArgumentOutOfRangeException("Invalid time snapshot");
            Load();
            registry.Configure(configType,c=>multiplier.SetValue(c,configuredMultiplier));
            var rates=registry.EvaluateTimeRate((flags&1)!=0,active,sleeping,targetRate,(flags&2)!=0);
            return new Rates {Time=rates.Time,Tile=rates.Tile,Event=rates.Event};
        }
    }
    public static int GetHandlerCount() {lock(Gate){Load();return registry.SystemCount;}}
    public static int SelfTest()
    {
        int[][] inputs={new[]{0,1,0,1,5},new[]{0,1,1,1,5},new[]{0,2,1,1,5},
            new[]{0,1,1,1,10},new[]{1,1,1,1,5},new[]{2,1,1,1,5},new[]{3,1,1,1,5},
            new[]{0,1,1,3,5},new[]{0,1,1,1,0},new[]{0,1,1,1000,100}};
        double[] expected={1,5,1,10,1,0,1,15,0,86400};
        for(int i=0;i<inputs.Length;i++)
        {
            var p=inputs[i];var r=Evaluate(p[0],p[1],p[2],p[3],p[4]);
            double other=i==inputs.Length-1?100000:expected[i];
            if(r.Time!=expected[i] || r.Tile!=other || r.Event!=other)
                throw new InvalidOperationException("Original mod result differs at case "+i);
        }
        return inputs.Length;
    }
    public static int GetLifecycleChecks()
    {
        lock(Gate)
        {
            Load();int count=0;
            void Check(bool ok) {if(!ok)throw new InvalidOperationException("Unified time lifecycle "+count);count++;}
            var get=typeof(ModContent).GetMethod("GetInstance").MakeGenericMethod(configType);
            registry.Configure(configType,c=>Check(ReferenceEquals(c,get.Invoke(null,null))));
            var old=(Terraria.Main.gameMenu,Terraria.Main.CurrentFrameFlags.ActivePlayersCount,Terraria.Main.CurrentFrameFlags.SleepingPlayersCount);
            try
            {
                Terraria.Main.gameMenu=true;Terraria.Main.CurrentFrameFlags.ActivePlayersCount=42;Terraria.Main.CurrentFrameFlags.SleepingPlayersCount=41;
                Check(Evaluate(0,1,1,1,10).Time==10);
                Check(Terraria.Main.gameMenu && Terraria.Main.CurrentFrameFlags.ActivePlayersCount==42 && Terraria.Main.CurrentFrameFlags.SleepingPlayersCount==41);
                Check(registry.SystemCount==1 && registry.ItemNames.Count==1);
                var systemType=configType.Assembly.GetType("AdjustTimeRate",true);
                registry.Configure(configType,c=>Check(ReferenceEquals(c,systemType.GetField("config",BindingFlags.Static|BindingFlags.NonPublic|BindingFlags.Public).GetValue(null))));
                Check(registry.Create(6196,5).damage==37);
                bool rejected=false;
                try {get.Invoke(null,null);} catch(TargetInvocationException ex) when(ex.InnerException is NotSupportedException) {rejected=true;}
                Check(rejected);
            }
            finally
            {
                (Terraria.Main.gameMenu,Terraria.Main.CurrentFrameFlags.ActivePlayersCount,Terraria.Main.CurrentFrameFlags.SleepingPlayersCount)=old;
                registry.Configure(configType,c=>multiplier.SetValue(c,5));
            }
            return count;
        }
    }
    public static int GetContentChecks()
    {
        lock(Gate)
        {
            Load();int count=ManagedSwordDemo.GetFoundationChecks();
            if(count!=8)throw new InvalidOperationException("Foundation checks differ");
            void Check(bool ok){if(!ok)throw new InvalidOperationException("Combined content check "+count);count++;}
            Check(ManagedSwordDemo.GetDamage(6196,5)==37);
            Check(ManagedSwordDemo.GetDamage(3507,5)==5);
            Check(ManagedSwordDemo.GetDamage(6196,7)==37);
            Check(ManagedSwordDemo.GetName(6196)=="PC ModItem Test Blade");
            Check(ManagedSwordDemo.GetHandlerCount()==1);
            Check(ManagedSwordDemo.StressGc()==16777216);
            return count;
        }
    }
    public static int StressGc()
    {
        int total=0;
        for(int i=0;i<2048;i++){var b=new byte[8192];b[i%b.Length]=(byte)i;total+=b.Length;}
        GC.Collect();
        if(SelfTest()!=10 || GetLifecycleChecks()!=7)throw new InvalidOperationException("Post-GC contract differs");
        return total;
    }
}
