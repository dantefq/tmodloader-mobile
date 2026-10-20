// Only compiled beside pinned public sources in ReferenceLoader.dll.
// Build-file compilation, Terraria files, logging and localization are untested stubs.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace Terraria.Localization
{
    public static class Language
    {
        public static string GetTextValue(string key, params object[] args) => key;
    }
}
namespace Terraria.ModLoader.IO { internal class UnusedNamespaceMarker { } }
namespace Terraria.ModLoader
{
    internal static class BuildInfo { internal static Version tMLVersion = new(2026, 8, 3, 0); }
    internal static class Logging
    {
        internal static Logger tML = new();
        internal class Logger { internal void Error(string message) => throw new NotSupportedException(); }
    }
}
namespace Terraria.ModLoader.Core
{
    internal static class ModCompile
    {
        internal static void UpdateSubstitutedDescriptionValues(ref string description, string version, string homepage) =>
            throw new NotSupportedException();
    }
    internal class TmodFile { internal Stream GetStream(string name) => throw new NotSupportedException(); }
    internal class LocalMod
    {
        internal string Name;
        internal Version Version;
        internal BuildProperties properties;
    }
    internal class ModSortingException : Exception
    {
        internal ModSortingException(IEnumerable<LocalMod> mods, string message) : base(message) { }
    }
    internal static partial class ReferenceOrganizer { }
    public static class LoaderReferenceHarness
    {
        public static byte[] WriteFixture(int sample)
        {
            var properties = new BuildProperties
            {
                version = new(1, sample % 5, sample % 3), buildVersion = new(2026, 8, 3, 0),
                side = (ModSide)(sample % 4), author = "Автор " + sample, displayName = "Мод " + sample,
                description = "Описание\n" + sample, homepage = "https://example.invalid/" + sample,
                eacPath = sample % 2 == 0 ? "" : "unused", modSource = sample % 3 == 0 ? "source" : "",
                dllReferences = new[] { "Helper" },
                modReferences = new[] { new BuildProperties.ModReference("ZBase", new(1, 2)) },
                weakReferences = new[] { new BuildProperties.ModReference("Optional", null) },
                sortAfter = sample % 2 == 0 ? new[] { "ZBase", "Optional" } : Array.Empty<string>(),
                sortBefore = sample % 2 != 0 ? new[] { "ZBase" } : Array.Empty<string>(),
                noCompile = (sample & 1) != 0, playableOnPreview = (sample & 2) != 0,
                translationMod = (sample & 4) != 0, libraryMod = (sample & 8) != 0,
                hideCode = (sample & 16) != 0, hideResources = (sample & 32) != 0, includeSource = (sample & 64) != 0
            };
            return properties.ToBytes();
        }
        public static Dictionary<string, string> ReadFixture(byte[] bytes)
        {
            var p = BuildProperties.ReadFromStream(new MemoryStream(bytes, false));
            return new()
            {
                ["Version"] = p.version.ToString(), ["BuildVersion"] = p.buildVersion.ToString(), ["Side"] = p.side.ToString(),
                ["Author"] = p.author, ["DisplayName"] = p.displayName, ["Description"] = p.description, ["Homepage"] = p.homepage,
                ["EacPath"] = p.eacPath, ["ModSource"] = p.modSource, ["Required"] = string.Join(",", p.modReferences.Select(r => r.ToString())),
                ["Weak"] = string.Join(",", p.weakReferences.Select(r => r.ToString())), ["SortAfter"] = string.Join(",", p.sortAfter),
                ["SortBefore"] = string.Join(",", p.sortBefore), ["DllReferences"] = string.Join(",", p.dllReferences),
                ["NoCompile"] = p.noCompile.ToString(), ["PlayableOnPreview"] = p.playableOnPreview.ToString(),
                ["TranslationMod"] = p.translationMod.ToString(), ["LibraryMod"] = p.libraryMod.ToString(),
                ["HideCode"] = p.hideCode.ToString(), ["HideResources"] = p.hideResources.ToString(), ["IncludeSource"] = p.includeSource.ToString()
            };
        }
        public static (bool dependencies, bool versions) Validate(string providerVersion, string requirement, bool weak,
            bool providerPresent, int consumerSide, int providerSide)
        {
            var dependency = BuildProperties.ModReference.Parse(requirement);
            var list = new List<LocalMod>
            {
                new() { Name = "Consumer", Version = new(1, 0), properties = new() { side = (ModSide)consumerSide,
                    modReferences = weak ? Array.Empty<BuildProperties.ModReference>() : new[] { dependency },
                    weakReferences = weak ? new[] { dependency } : Array.Empty<BuildProperties.ModReference>() } }
            };
            if (providerPresent) list.Add(new() { Name = "Provider", Version = Version.Parse(providerVersion), properties = new() { side = (ModSide)providerSide } });
            bool dependencies = true, versions = true;
            try { ReferenceOrganizer.EnsureDependenciesExist(list, false); } catch (ModSortingException) { dependencies = false; }
            try { ReferenceOrganizer.EnsureTargetVersionsMet(list); } catch (ModSortingException) { versions = false; }
            return (dependencies, versions);
        }
    }
}
