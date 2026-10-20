using System.Reflection;

[assembly: AssemblyVersion("1.4.4.9")]

// Independently written, narrowly scoped API adapter, not Terraria game code.
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
    public abstract class ModType { public virtual string Texture => ""; }
    public abstract class ModType<TEntity> : ModType where TEntity : class
    {
        public TEntity Entity { get; private set; }
        public void Bind(TEntity entity) => Entity = entity;
    }
    public abstract class ModType<TEntity, TModType> : ModType<TEntity>
        where TEntity : class where TModType : ModType<TEntity, TModType> { }
    public abstract class ModItem : ModType<Terraria.Item, ModItem>
    {
        public Terraria.Item Item => Entity;
        public virtual void SetDefaults() { }
    }
}
