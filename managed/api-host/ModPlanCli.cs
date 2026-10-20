using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using TerrariaMobile.Managed;
using TerrariaMobile.Serialization;

// Read-only metadata CLI. No Assembly.Load, extraction or native/mobile calls.
static class ModPlanCli
{
    public static int Main(string[] args)
    {
        try
        {
            if (args.Length < 2 || args[0] is not "client" and not "server")
                throw new ArgumentException("Usage: ModPlanCli client|server selected.tmod [...]");
            if (args.Length - 1 > MobileModLoadPlan.MaxMods) throw new ArgumentException("Too many selected mods");
            var role = args[0] == "client" ? MobileLoadRole.Client : MobileLoadRole.Server;
            var manifests = new List<MobileModManifest>();
            var artifacts = new List<object>();
            for (int i = 1; i < args.Length; i++)
            {
                var archive = MobileTmodMetadata.FromFile(args[i]);
                var manifest = archive.Manifest;
                manifests.Add(manifest);
                artifacts.Add(new { path = Path.GetFullPath(args[i]), sha256 = archive.Sha256,
                    name = manifest.Name, version = manifest.Version.ToString(),
                    loader_version = archive.TModLoaderVersion.ToString(), build_version = manifest.BuildVersion?.ToString(),
                    side = manifest.Side.ToString(), required = manifest.Required, weak = manifest.Weak,
                    sort_after = manifest.SortAfter, sort_before = manifest.SortBefore, dll_references = manifest.DllReferences,
                    declared_expanded_bytes = archive.DeclaredExpandedBytes, stored_bytes = archive.StoredBytes,
                    resources_decompressed = false, payload_sha1_verified = archive.PayloadSha1Verified, signature_authenticated = archive.SignatureAuthenticated });
            }
            var plan = MobileModLoadPlan.Build(manifests, role);
            Console.WriteLine(JsonSerializer.Serialize(new { format = "terraria-mobile-mod-plan-v1", role = args[0],
                valid = plan.IsValid, order = System.Linq.Enumerable.Select(plan.Order, m => m.Name), issues = plan.Issues,
                artifacts, assembly_executed = false, compatibility_verified = false },
                new JsonSerializerOptions { WriteIndented = true, PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower }));
            return plan.IsValid ? 0 : 2;
        }
        catch (Exception error) when (error is IOException or ArgumentException or NotSupportedException or InvalidDataException)
        {
            Console.Error.WriteLine(error.GetType().Name + ": " + error.Message);
            return 3;
        }
    }
}
