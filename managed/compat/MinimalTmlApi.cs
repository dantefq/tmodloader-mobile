using System.Reflection;

[assembly: AssemblyVersion("1.4.4.9")]

// Independently written interoperability surface. No Terraria implementation code.
// Only the members used by our bundled GlobalItem test are implemented.
namespace Terraria
{
    public class Item
    {
        public int type;
        public int damage;
        private string nameOverride = "";
        public string Name => nameOverride;
        public void SetNameOverride(string name) => nameOverride = name;
    }
}

namespace Terraria.ModLoader
{
    public abstract class Mod { }
    public abstract class ModType { }
    public abstract class GlobalType<TGlobal> : ModType where TGlobal : GlobalType<TGlobal> { }
    public abstract class GlobalType<TEntity, TGlobal> : GlobalType<TGlobal>
        where TEntity : class where TGlobal : GlobalType<TEntity, TGlobal>
    {
        public virtual void SetDefaults(TEntity entity) { }
    }
    public abstract class GlobalItem : GlobalType<Terraria.Item, GlobalItem> { }
}
