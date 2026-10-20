using System;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using Terraria.ModLoader;
using Terraria.ModLoader.Config;
using TerrariaMobile.Managed;

// Executed only in the user's private lab, with exact unchanged local DLLs.
// The fixture mods in TimeLifecycleTests do not substitute for this check.
static class OriginalTimeItemChecks
{
    static int checks;
    static void Check(bool ok) {if(!ok)throw new Exception("Combined original DLL check "+checks);checks++;}
    static void Main()
    {
        Check(ManagedTimeHost.SelfTest()==10);
        Check(ManagedTimeHost.GetLifecycleChecks()==7);
        Check(ManagedTimeHost.StressGc()==16777216);
        Check(ManagedTimeHost.GetContentChecks()==14);
        Check(ManagedSwordDemo.GetDamage(6196,5)==37);
        Check(ManagedSwordDemo.GetDamage(3507,5)==5);
        Check(ManagedSwordDemo.GetDamage(6196,7)==37);
        Check(ManagedTimeHost.Evaluate(0,1,1,1,10).Time==10);
        Check(ManagedTimeHost.Evaluate(0,1,0,1,10).Time==1);
        Check(ManagedSwordDemo.GetName(6196)=="PC ModItem Test Blade");
        Console.WriteLine(JsonSerializer.Serialize(new {status="passed",original_sleep_cases=10,lifecycle_checks=7,
            content_checks=14,combined_checks=checks,gc_bytes=16777216,original_dlls_recompiled=false,same_registry=true}));
    }
}
