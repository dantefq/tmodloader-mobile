using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using Terraria.ModLoader;
using TerrariaMobile.Serialization;

namespace TerrariaMobile.Managed;

public enum MobileLoadRole { Client, Server }
public sealed record MobileModLoadIssue(string Code, string Mod, string Dependency, string Message);
public sealed class MobileModDependencyException : Exception
{
    public IReadOnlyList<MobileModLoadIssue> Issues { get; }
    internal MobileModDependencyException(IReadOnlyList<MobileModLoadIssue> issues) :
        base(string.Join("\n", issues.Select(i => i.Message))) => Issues = issues;
}

// Pure planning over a selected set. Never downloads/enables mods, loads DLLs,
// or calls lifecycle hooks. Multiplayer ID synchronization is outside this plan.
public sealed class MobileModLoadPlan
{
    public const int MaxMods = 1024;
    public bool IsValid => Issues.Count == 0;
    public IReadOnlyList<MobileModManifest> Order { get; }
    public IReadOnlyList<MobileModLoadIssue> Issues { get; }
    private MobileModLoadPlan(List<MobileModManifest> order, List<MobileModLoadIssue> issues)
    {
        Order = order.AsReadOnly(); Issues = issues.AsReadOnly();
    }
    public void RequireValid()
    {
        if (!IsValid) throw new MobileModDependencyException(Issues);
    }
    public static MobileModLoadPlan Build(IEnumerable<MobileModManifest> selected, MobileLoadRole role = MobileLoadRole.Client)
    {
        if (selected == null) throw new ArgumentNullException(nameof(selected));
        if (!Enum.IsDefined(role)) throw new ArgumentException("Invalid load role");
        var mods = new SortedDictionary<string, MobileModManifest>(StringComparer.Ordinal);
        var issues = new List<MobileModLoadIssue>();
        int count = 0;
        foreach (var mod in selected)
        {
            if (++count > MaxMods) throw new ArgumentException("Selected mod set exceeds limit");
            if (mod == null) throw new ArgumentException("Null mod manifest");
            if (!mods.TryAdd(mod.Name, mod))
                issues.Add(new("duplicate-mod", mod.Name, mod.Name, "Duplicate selected mod: " + mod.Name));
        }
        if (issues.Count != 0)
            return new(new(), issues.OrderBy(i => i.Mod, StringComparer.Ordinal).ToList());
        var edges = mods.Keys.ToDictionary(n => n, _ => new SortedSet<string>(StringComparer.Ordinal), StringComparer.Ordinal);
        var incoming = mods.Keys.ToDictionary(n => n, _ => 0, StringComparer.Ordinal);
        void Edge(string from, string to)
        {
            if (mods.ContainsKey(from) && mods.ContainsKey(to) && edges[from].Add(to)) incoming[to]++;
        }
        foreach (var mod in mods.Values)
        {
            if ((role == MobileLoadRole.Client && mod.Side == ModSide.Server) || (role == MobileLoadRole.Server && mod.Side == ModSide.Client))
                issues.Add(new("wrong-side", mod.Name, "", $"{mod.Name}: {mod.Side} mod is selected for {role}"));
            foreach (var dependency in mod.Required.Concat(mod.Weak).OrderBy(d => d.Name, StringComparer.Ordinal))
            {
                if (!mods.TryGetValue(dependency.Name, out var provider))
                {
                    if (mod.Required.Contains(dependency))
                        issues.Add(new("missing-dependency", mod.Name, dependency.Name, $"{mod.Name} requires missing mod {dependency.Name}"));
                    continue;
                }
                if (mod.Required.Contains(dependency) && provider.Side != mod.Side && provider.Side is not ModSide.Both and not ModSide.NoSync)
                    issues.Add(new("dependency-side-incompatible", mod.Name, dependency.Name,
                        $"{mod.Name} ({mod.Side}) cannot strongly depend on {provider.Name} ({provider.Side})"));
                if (dependency.Target == null) continue;
                if (provider.Version < dependency.Target)
                    issues.Add(new("dependency-too-old", mod.Name, dependency.Name,
                        $"{mod.Name} requires {dependency}; selected version is {provider.Version}"));
                else if (provider.Version.Major != dependency.Target.Major)
                    issues.Add(new("dependency-major-mismatch", mod.Name, dependency.Name,
                        $"{mod.Name} requires major {dependency.Target.Major} of {dependency.Name}; selected version is {provider.Version}"));
            }
            foreach (var name in mod.SortAfter) Edge(name, mod.Name);
            foreach (var name in mod.SortBefore) Edge(mod.Name, name);
        }
        var available = new SortedSet<string>(incoming.Where(p => p.Value == 0).Select(p => p.Key), StringComparer.Ordinal);
        var order = new List<MobileModManifest>();
        while (available.Count != 0)
        {
            string name = available.Min; available.Remove(name); order.Add(mods[name]);
            foreach (var next in edges[name]) if (--incoming[next] == 0) available.Add(next);
        }
        if (order.Count != mods.Count)
        {
            var cycle = FindCycle(edges);
            issues.Add(new("ordering-cycle", cycle[0], cycle[^1], "Mod ordering cycle: " + string.Join(" -> ", cycle)));
        }
        issues = issues.OrderBy(i => i.Mod, StringComparer.Ordinal).ThenBy(i => i.Code, StringComparer.Ordinal)
            .ThenBy(i => i.Dependency, StringComparer.Ordinal).ToList();
        return new(issues.Count == 0 ? order : new(), issues);
    }
    private static List<string> FindCycle(Dictionary<string, SortedSet<string>> edges)
    {
        // Iterative DFS keeps long dependency chains off the call stack. Return an
        // actual closed cycle, not every node blocked downstream of that cycle.
        var finished = new HashSet<string>(StringComparer.Ordinal);
        var active = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (string root in edges.Keys.OrderBy(n => n, StringComparer.Ordinal))
        {
            if (finished.Contains(root)) continue;
            var path = new List<string>();
            var stack = new Stack<(string node, IEnumerator<string> next)>();
            void Push(string node)
            {
                active.Add(node, path.Count); path.Add(node); stack.Push((node, edges[node].GetEnumerator()));
            }
            Push(root);
            try
            {
                while (stack.Count != 0)
                {
                    var frame = stack.Peek();
                    if (!frame.next.MoveNext())
                    {
                        frame.next.Dispose(); stack.Pop(); active.Remove(frame.node); path.RemoveAt(path.Count - 1); finished.Add(frame.node);
                        continue;
                    }
                    string next = frame.next.Current;
                    if (active.TryGetValue(next, out int start)) return path.Skip(start).Append(next).ToList();
                    if (!finished.Contains(next)) Push(next);
                }
            }
            finally { foreach (var frame in stack) frame.next.Dispose(); active.Clear(); }
        }
        throw new InvalidOperationException("Expected an ordering cycle");
    }
}
