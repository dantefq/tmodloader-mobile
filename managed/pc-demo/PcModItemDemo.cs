using Terraria.ModLoader;

namespace PcModItemDemo;

public sealed class PcModItemDemo : Mod { }

// Built against the user's real PC tModLoader assembly, never the mobile shim.
public sealed class TestBlade : ModItem
{
    public override string Texture => "Terraria/Images/Item_3507";
    public override void SetDefaults()
    {
        Item.damage = 37;
        Item.SetNameOverride("PC ModItem Test Blade");
    }
}
