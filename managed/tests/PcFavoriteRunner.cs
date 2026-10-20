using System;
using Terraria;

public static class PcFavoriteRunner
{
    public static void Main()
    {
        var item = new Item();
        if (!PcFavoriteFixture.Touch(item) || !item.favorite)
            throw new Exception("PC field write was not visible through the alias");
        item.favorite = false;
        if (item.favorited) throw new Exception("Alias write was not visible through the PC field");
        Console.WriteLine("PASS unchanged PC-compiled favorited field contract and alias in both directions");
    }
}
