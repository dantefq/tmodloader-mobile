namespace TerrariaMobile.Managed;

// Own test assembly. No game code and no claim of tModLoader API compatibility.
public static class ManagedSwordDemo
{
    public static int GetDamage(int itemType, int vanillaDamage)
        => itemType == 3507 ? vanillaDamage + 13 : vanillaDamage;

    public static string GetName(int itemType)
        => itemType == 3507 ? "CSharp Test Sword" : "";

    public static int StressGc()
    {
        int total = 0;
        for (int i = 0; i < 2048; i++)
        {
            byte[] buffer = new byte[8192];
            buffer[i % buffer.Length] = (byte)i;
            total += buffer.Length;
        }
        System.GC.Collect();
        return total;
    }
}
