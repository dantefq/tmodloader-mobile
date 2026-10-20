extern alias ReferenceLoader;
using System;
using System.Collections.Generic;
using System.Linq;
using Terraria.ModLoader;
using TerrariaMobile.Serialization;
using TerrariaMobile.Managed;
using Ref = ReferenceLoader::Terraria.ModLoader.Core.LoaderReferenceHarness;

static class LoaderConformance
{
    static int checks;
    static void Check(bool same, string message)
    {
        if (!same) throw new Exception(message);
        checks++;
    }
    public static void Main()
    {
        for (int sample = 0; sample < 128; sample++)
        {
            var bytes = Ref.WriteFixture(sample); var reference = Ref.ReadFixture(bytes);
            var ours = MobileModManifest.FromInfo("Fixture", Version.Parse(reference["Version"]), bytes);
            var values = new Dictionary<string, string>
            {
                ["Version"] = ours.Version.ToString(), ["BuildVersion"] = ours.BuildVersion.ToString(), ["Side"] = ours.Side.ToString(),
                ["Author"] = ours.Author, ["DisplayName"] = ours.DisplayName, ["Description"] = ours.Description, ["Homepage"] = ours.Homepage,
                ["EacPath"] = ours.EacPath, ["ModSource"] = ours.ModSource, ["Required"] = string.Join(",", ours.Required),
                ["Weak"] = string.Join(",", ours.Weak), ["SortAfter"] = string.Join(",", ours.SortAfter),
                ["SortBefore"] = string.Join(",", ours.SortBefore), ["DllReferences"] = string.Join(",", ours.DllReferences),
                ["NoCompile"] = ours.NoCompile.ToString(), ["PlayableOnPreview"] = ours.PlayableOnPreview.ToString(),
                ["TranslationMod"] = ours.TranslationMod.ToString(), ["LibraryMod"] = ours.LibraryMod.ToString(),
                ["HideCode"] = ours.HideCode.ToString(), ["HideResources"] = ours.HideResources.ToString(), ["IncludeSource"] = ours.IncludeSource.ToString()
            };
            foreach (var field in reference) Check(values[field.Key] == field.Value, "Info conformance: " + field.Key);
        }
        foreach (string version in new[] { "1.0", "1.2", "1.2.0", "1.9", "2.0", "0.9" })
            foreach (bool weak in new[] { false, true })
                foreach (bool present in new[] { false, true })
                    for (int consumerSide = 0; consumerSide < 4; consumerSide++)
                        for (int providerSide = 0; providerSide < 4; providerSide++)
                        {
                            const string target = "Provider@1.2";
                            var consumer = new MobileModManifest("Consumer", new(1, 0),
                                weak ? null : new[] { MobileModReference.Parse(target) }, weak ? new[] { MobileModReference.Parse(target) } : null,
                                side: (ModSide)consumerSide);
                            var selected = new List<MobileModManifest> { consumer };
                            if (present) selected.Add(new("Provider", Version.Parse(version), side: (ModSide)providerSide));
                            var ours = MobileModLoadPlan.Build(selected);
                            var reference = Ref.Validate(version, target, weak, present, consumerSide, providerSide);
                            // Role-selection errors belong to our host policy; compare
                            // only the actual upstream dependency and version validators.
                            Check(reference.dependencies == !ours.Issues.Any(i => i.Code is "missing-dependency" or "dependency-side-incompatible"), "Dependency existence/side conformance");
                            Check(reference.versions == !ours.Issues.Any(i => i.Code is "dependency-too-old" or "dependency-major-mismatch"), "Dependency version conformance");
                        }
        Console.WriteLine($"PASS {checks} upstream Info/dependency comparisons; build-file/DLL execution/network synchronization excluded");
    }
}
