// Compile ONLY against the user's installed PC tModLoader, then leave unchanged.
public static class PcFavoriteFixture
{
    public static bool Touch(Terraria.Item item)
    {
        item.favorited = true;
        return item.favorited;
    }
}
