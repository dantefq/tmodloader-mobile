using Terraria;
using Terraria.ID;
using Terraria.ModLoader;
using System.Reflection;

[assembly: AssemblyVersion("1.0.0.0")]

namespace PcGlobalItemDemo;

// Compiled against the user's actual PC tModLoader.dll, not our mobile shim.
public sealed class PcGlobalItemDemo : Mod { }

public sealed class CopperSwordGlobal : GlobalItem
{
    public override void SetDefaults(Item item)
    {
        if (item.type != ItemID.CopperShortsword) return;
        item.damage += 19;
        item.SetNameOverride("PC API Test Sword");
    }
}
