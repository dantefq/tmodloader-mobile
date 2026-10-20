using System;
using Terraria;

// Compiled against the user's PC tModLoader, executed against our own shim.
// This checks binary member binding, not the PC game or Android runtime.
static class PcItemEconomyProbe
{
    static void Check(bool ok, string reason)
    {
        if (!ok) throw new Exception(reason);
    }
    public static void Main()
    {
        var item = new Item();
        Entity entity = item;
        entity.width = 18; entity.height = 22;
        Check(item.width == 18 && item.height == 22, "Inherited Entity field binding");
        Check(typeof(Item).GetField("width").DeclaringType == typeof(Entity), "Field owner");
        Check(Item.buyPrice() == 0 && Item.sellPrice() == 0, "Zero/default arguments");
        Check(Item.buyPrice(1, 2, 3, 4) == 1020304, "Currency denominations");
        Check(Item.sellPrice(1, 2, 3, 4) == 5101520, "Sell value multiplier");
        Check(Item.sellPrice(silver: 7) == 3500, "Named optional argument ABI");
        Check(Item.buyPrice(copper: -1) == -1 && Item.sellPrice(copper: -1) == -5, "Signed inputs preserved");
        Check(Item.buyPrice(int.MaxValue) == -1000000, "Int32 multiply wrap");
        Check(Item.sellPrice(copper: int.MaxValue) == 2147483643, "Int32 sell wrap");
        var clone = item.Clone();
        Check(clone.width == 18 && clone.height == 22 && !ReferenceEquals(item, clone), "Inherited fields clone");
        Console.WriteLine("PASS PC-compiled item price/Entity field contract: 10 checks; own shim only");
    }
}
