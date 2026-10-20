namespace Terraria;

// Snapshot API only: no shop, currency transfer or native inventory mutation.
public partial class Item
{
    public static int buyPrice(int platinum = 0, int gold = 0, int silver = 0, int copper = 0)
        => unchecked(platinum * 1000000 + gold * 10000 + silver * 100 + copper);

    public static int sellPrice(int platinum = 0, int gold = 0, int silver = 0, int copper = 0)
        => unchecked(buyPrice(platinum, gold, silver, copper) * 5);
}
