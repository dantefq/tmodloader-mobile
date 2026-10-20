using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text;

namespace Terraria.ModLoader
{
    public enum ModSide { Both, Client, Server, NoSync }
}

namespace TerrariaMobile.Serialization
{
    public sealed class MobileModReference
    {
        public string Name { get; }
        public Version Target { get; }
        public MobileModReference(string name, Version target = null)
        {
            MobileModManifest.ValidateName(name); Name = name; Target = target;
        }
        public static MobileModReference Parse(string value)
        {
            if (value == null) throw new ArgumentNullException(nameof(value));
            var parts = value.Split('@');
            if (parts.Length > 2 || (parts.Length == 2 && !Version.TryParse(parts[1], out _)))
                throw new ArgumentException("Invalid mod reference: " + value);
            return new(parts[0], parts.Length == 2 ? Version.Parse(parts[1]) : null);
        }
        public override string ToString() => Name + (Target == null ? "" : "@" + Target);
    }

    // Actual modern TMOD Info records, not a JSON replacement and not executable code.
    public sealed class MobileModManifest
    {
        public const int MaxInfoBytes = 1024 * 1024, MaxStringBytes = 64 * 1024, MaxListEntries = 256;
        public string Name { get; }
        public Version Version { get; }
        public Version BuildVersion { get; private set; }
        public Terraria.ModLoader.ModSide Side { get; }
        public IReadOnlyList<MobileModReference> Required { get; }
        public IReadOnlyList<MobileModReference> Weak { get; }
        public IReadOnlyList<string> SortAfter { get; }
        public IReadOnlyList<string> SortBefore { get; }
        public IReadOnlyList<string> DllReferences { get; }
        public string Author { get; private set; } = "";
        public string DisplayName { get; private set; } = "";
        public string Description { get; private set; } = "";
        public string Homepage { get; private set; } = "";
        public bool NoCompile { get; private set; }
        public bool LibraryMod { get; private set; }
        public bool TranslationMod { get; private set; }
        public bool PlayableOnPreview { get; private set; } = true;
        public bool HideCode { get; private set; } = true;
        public bool HideResources { get; private set; } = true;
        public bool IncludeSource { get; private set; }
        public string EacPath { get; private set; } = "";
        public string ModSource { get; private set; } = "";
        private static readonly UTF8Encoding Utf8 = new(false, true);

        internal static void ValidateName(string value)
        {
            if (string.IsNullOrEmpty(value) || value.Length > 128 || value.Equals("Terraria", StringComparison.OrdinalIgnoreCase) ||
                value.Any(c => char.IsWhiteSpace(c) || char.IsControl(c) || ".,/\\:@".Contains(c)))
                throw new ArgumentException("Invalid mod identity: " + value);
        }
        private static ReadOnlyCollection<T> Copy<T>(IEnumerable<T> values)
        {
            var result = new List<T>();
            if (values != null)
                foreach (var value in values)
                {
                    if (value == null) throw new ArgumentException("Null manifest entry");
                    if (result.Count == MaxListEntries) throw new ArgumentException("Manifest list exceeds limit");
                    result.Add(value);
                }
            return result.AsReadOnly();
        }
        public MobileModManifest(string name, Version version, IEnumerable<MobileModReference> required = null,
            IEnumerable<MobileModReference> weak = null, IEnumerable<string> sortAfter = null,
            IEnumerable<string> sortBefore = null, IEnumerable<string> dllReferences = null,
            Terraria.ModLoader.ModSide side = Terraria.ModLoader.ModSide.Both)
        {
            ValidateName(name); Name = name; Version = version ?? throw new ArgumentNullException(nameof(version));
            if (!Enum.IsDefined(side)) throw new ArgumentException("Invalid mod side");
            Side = side; Required = Copy(required); Weak = Copy(weak); SortBefore = Copy(sortBefore);
            // Own manifests follow build.txt defaults. Parsed Info passes an explicit
            // (possibly empty) SortAfter: serialized sorting is already normalized.
            SortAfter = Copy(sortAfter ?? Required.Concat(Weak).Select(r => r.Name).Except(SortBefore, StringComparer.Ordinal));
            DllReferences = Copy(dllReferences);
            var dependencies = new HashSet<string>(StringComparer.Ordinal);
            foreach (var dependency in Required.Concat(Weak))
                if (dependency.Name == name || !dependencies.Add(dependency.Name))
                    throw new ArgumentException("Duplicate or self dependency: " + dependency.Name);
            foreach (var list in new[] { SortAfter, SortBefore })
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (var value in list)
                {
                    ValidateName(value);
                    if (value == name || !names.Add(value)) throw new ArgumentException("Duplicate or self sort constraint");
                }
            }
            if (SortAfter.Intersect(SortBefore, StringComparer.Ordinal).Any()) throw new ArgumentException("Conflicting sort constraints");
            var dllNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var dll in DllReferences)
                if (dll.Length == 0 || dll.Length > 256 || dll.Any(c => char.IsControl(c) || "/\\:".Contains(c)) || !dllNames.Add(dll))
                    throw new ArgumentException("Invalid or duplicate DLL reference");
        }
        private static string Text(BinaryReader reader)
        {
            int count = reader.Read7BitEncodedInt();
            if (count < 0 || count > MaxStringBytes || count > reader.BaseStream.Length - reader.BaseStream.Position)
                throw new InvalidDataException("Invalid Info string length");
            return Utf8.GetString(reader.ReadBytes(count));
        }
        private static List<string> List(BinaryReader reader)
        {
            var result = new List<string>();
            for (string value = Text(reader); value.Length != 0; value = Text(reader))
            {
                if (result.Count == MaxListEntries) throw new InvalidDataException("Info list exceeds limit");
                result.Add(value);
            }
            return result;
        }
        public static MobileModManifest FromArchive(MobileTmodArchive archive)
        {
            if (archive == null) throw new ArgumentNullException(nameof(archive));
            if (archive.GetEntryLength("Info") > MaxInfoBytes) throw new InvalidDataException("Info exceeds limit");
            var bytes = archive.GetBytes("Info") ?? throw new InvalidDataException("TMOD Info entry missing");
            return FromInfo(archive.Name, archive.Version, bytes, archive.TModLoaderVersion);
        }
        public static MobileModManifest FromInfo(string name, Version archiveVersion, byte[] bytes, Version loaderVersion = null)
        {
            if (bytes == null) throw new ArgumentNullException(nameof(bytes));
            if (bytes.Length > MaxInfoBytes) throw new InvalidDataException("Info exceeds limit");
            try
            {
                using var input = new MemoryStream(bytes, false);
                using var reader = new BinaryReader(input, Utf8, true);
                var strings = new Dictionary<string, string>(StringComparer.Ordinal);
                var lists = new Dictionary<string, List<string>>(StringComparer.Ordinal);
                var seen = new HashSet<string>(StringComparer.Ordinal);
                var side = Terraria.ModLoader.ModSide.Both;
                for (string tag = Text(reader); tag.Length != 0; tag = Text(reader))
                {
                    if (!seen.Add(tag)) throw new InvalidDataException("Duplicate Info tag: " + tag);
                    switch (tag)
                    {
                        case "dllReferences": case "modReferences": case "weakReferences": case "sortAfter": case "sortBefore":
                            lists.Add(tag, List(reader)); break;
                        case "author": case "version": case "displayName": case "homepage": case "description":
                        case "eacPath": case "buildVersion": case "modSource":
                            strings.Add(tag, Text(reader)); break;
                        case "noCompile": case "!playableOnPreview": case "translationMod": case "libraryMod":
                        case "!hideCode": case "!hideResources": case "includeSource": break;
                        case "side": side = (Terraria.ModLoader.ModSide)reader.ReadByte(); break;
                        default: throw new NotSupportedException("Unknown Info tag: " + tag);
                    }
                }
                if (input.Position != input.Length) throw new InvalidDataException("Trailing Info data");
                Version version = strings.TryGetValue("version", out var value) ? Version.Parse(value) : new(1, 0);
                if (archiveVersion == null || version != archiveVersion) throw new InvalidDataException("Info/archive version mismatch");
                List<string> Values(string tag) => lists.TryGetValue(tag, out var list) ? list : new();
                string Value(string tag) => strings.TryGetValue(tag, out var text) ? text : "";
                return new MobileModManifest(name, version, Values("modReferences").Select(MobileModReference.Parse),
                    Values("weakReferences").Select(MobileModReference.Parse), Values("sortAfter"), Values("sortBefore"),
                    Values("dllReferences"), side)
                {
                    BuildVersion = strings.ContainsKey("buildVersion") ? Version.Parse(Value("buildVersion")) : loaderVersion,
                    Author = Value("author"), DisplayName = Value("displayName"), Description = Value("description"),
                    Homepage = Value("homepage"), EacPath = Value("eacPath"), ModSource = Value("modSource"),
                    NoCompile = seen.Contains("noCompile"), LibraryMod = seen.Contains("libraryMod"),
                    TranslationMod = seen.Contains("translationMod"), PlayableOnPreview = !seen.Contains("!playableOnPreview"),
                    HideCode = !seen.Contains("!hideCode"), HideResources = !seen.Contains("!hideResources"),
                    IncludeSource = seen.Contains("includeSource")
                };
            }
            catch (EndOfStreamException error) { throw new InvalidDataException("Truncated Info", error); }
            catch (DecoderFallbackException error) { throw new InvalidDataException("Invalid Info UTF8", error); }
            catch (FormatException error) { throw new InvalidDataException("Invalid Info string/version", error); }
            catch (ArgumentException error) { throw new InvalidDataException("Invalid Info manifest", error); }
        }
    }
}
