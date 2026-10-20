using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text.Json;
using Terraria;

// Independent CLR reflection inventory to validate the nonexecuting metadata parser.
// Only our API assembly is loaded, never a third-party mod or game assembly.
static class ApiMetadataReflection
{
    public static void Main()
    {
        const BindingFlags flags = BindingFlags.DeclaredOnly | BindingFlags.Instance | BindingFlags.Static |
            BindingFlags.Public | BindingFlags.NonPublic;
        var types = typeof(Item).Assembly.GetTypes();
        var members = new HashSet<string>(StringComparer.Ordinal);
        string Name(Type type) => type.FullName.Replace('+', '/');
        foreach (var type in types)
        {
            foreach (var method in type.GetMethods(flags)) members.Add(Name(type) + "::" + method.Name);
            foreach (var ctor in type.GetConstructors(flags)) members.Add(Name(type) + "::" + ctor.Name);
            foreach (var field in type.GetFields(flags)) members.Add(Name(type) + "::" + field.Name);
        }
        Console.WriteLine(JsonSerializer.Serialize(new { defined_type_names = types.Select(Name).OrderBy(n => n).ToArray(),
            defined_member_names = members.OrderBy(n => n).ToArray() }));
    }
}
