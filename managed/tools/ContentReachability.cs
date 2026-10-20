using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Reflection.Emit;
using System.Reflection.Metadata;
using System.Reflection.Metadata.Ecma335;
using System.Reflection.PortableExecutable;
using System.Text.Json;

// Metadata-only dependency inventory. Never loads a target into the CLR.
internal static class ContentReachability
{
    static readonly Dictionary<ushort, OpCode> Opcodes = typeof(OpCodes).GetFields(BindingFlags.Public | BindingFlags.Static)
        .Where(f => f.FieldType == typeof(OpCode)).Select(f => (OpCode)f.GetValue(null)!)
        .ToDictionary(o => unchecked((ushort)o.Value));

    static int Main(string[] args)
    {
        try
        {
            if (args.Length is < 2 or > 3) throw new ArgumentException("Expected assembly path, exact content type and optional comma-separated root methods");
            using var stream = File.OpenRead(args[0]);
            using var pe = new PEReader(stream);
            var md = pe.GetMetadataReader();
            string TypeName(TypeDefinitionHandle h)
            {
                var t = md.GetTypeDefinition(h);
                return t.GetDeclaringType().IsNil ? Join(md.GetString(t.Namespace), md.GetString(t.Name)) :
                    TypeName(t.GetDeclaringType()) + "+" + md.GetString(t.Name);
            }
            MetadataTypes provider = null!;
            string Name(EntityHandle h) => h.Kind switch
            {
                HandleKind.MethodDefinition => TypeName(md.GetMethodDefinition((MethodDefinitionHandle)h).GetDeclaringType()) + "::" + md.GetString(md.GetMethodDefinition((MethodDefinitionHandle)h).Name),
                HandleKind.FieldDefinition => TypeName(md.GetFieldDefinition((FieldDefinitionHandle)h).GetDeclaringType()) + "::" + md.GetString(md.GetFieldDefinition((FieldDefinitionHandle)h).Name),
                HandleKind.TypeDefinition => TypeName((TypeDefinitionHandle)h),
                HandleKind.TypeReference => Join(md.GetString(md.GetTypeReference((TypeReferenceHandle)h).Namespace), md.GetString(md.GetTypeReference((TypeReferenceHandle)h).Name)),
                HandleKind.MemberReference => Name(md.GetMemberReference((MemberReferenceHandle)h).Parent) + "::" + md.GetString(md.GetMemberReference((MemberReferenceHandle)h).Name),
                HandleKind.MethodSpecification => Name(md.GetMethodSpecification((MethodSpecificationHandle)h).Method),
                HandleKind.TypeSpecification => provider.Specification((TypeSpecificationHandle)h),
                _ => h.Kind + ":0x" + MetadataTokens.GetToken(h).ToString("x8")
            };
            provider = new MetadataTypes(md, h => Name(h));
            var target = md.TypeDefinitions.Where(h => TypeName(h) == args[1]).ToArray();
            if (target.Length != 1) throw new ArgumentException("Content type missing or ambiguous");
            var roots = args.Length == 3 ? new HashSet<string>(args[2].Split(','), StringComparer.Ordinal) : null;
            if (roots != null && (roots.Count == 0 || roots.Contains(""))) throw new ArgumentException("Empty root method");
            var foundRoots = new HashSet<string>(StringComparer.Ordinal);
            var queue = new Queue<MethodDefinitionHandle>();
            var visited = new HashSet<MethodDefinitionHandle>();
            var initialized = new HashSet<TypeDefinitionHandle>();
            var dependencies = new List<object>();
            var blockers = new SortedSet<string>(StringComparer.Ordinal);
            void Init(TypeDefinitionHandle h)
            {
                if (!initialized.Add(h)) return;
                var t = md.GetTypeDefinition(h);
                foreach (var m in t.GetMethods())
                    if (md.GetString(md.GetMethodDefinition(m).Name) == ".cctor") queue.Enqueue(m);
                if (!t.BaseType.IsNil && t.BaseType.Kind == HandleKind.TypeDefinition) Init((TypeDefinitionHandle)t.BaseType);
                else if (!t.BaseType.IsNil) blockers.Add("External base lifecycle: " + Name(t.BaseType));
            }
            Init(target[0]);
            foreach (var t in md.TypeDefinitions)
                if (md.GetString(md.GetTypeDefinition(t).Name) == "<Module>")
                    foreach (var m in md.GetTypeDefinition(t).GetMethods())
                        if (md.GetString(md.GetMethodDefinition(m).Name) == ".cctor")
                        { queue.Enqueue(m); blockers.Add("Module initializer requires audit"); }
            // Include inherited local callbacks/constructors, not only overrides on the selected leaf.
            var current = target[0];
            while (true)
            {
                foreach (var m in md.GetTypeDefinition(current).GetMethods())
                {
                    var name = md.GetString(md.GetMethodDefinition(m).Name);
                    if (roots == null || roots.Contains(name)) { queue.Enqueue(m); foundRoots.Add(name); }
                }
                var b = md.GetTypeDefinition(current).BaseType;
                if (b.Kind != HandleKind.TypeDefinition) break;
                current = (TypeDefinitionHandle)b;
            }
            if (roots != null && !roots.IsSubsetOf(foundRoots)) throw new ArgumentException("Requested root method missing");
            while (queue.Count > 0)
            {
                var h = queue.Dequeue();
                if (!visited.Add(h)) continue;
                var method = md.GetMethodDefinition(h);
                Init(method.GetDeclaringType());
                if (method.RelativeVirtualAddress == 0) { blockers.Add("No IL body: " + Name(h)); continue; }
                var body = pe.GetMethodBody(method.RelativeVirtualAddress);
                var il = body.GetILReader();
                foreach (var region in body.ExceptionRegions)
                    if (!region.CatchType.IsNil) blockers.Add("Exception type: " + Name(region.CatchType));
                while (il.RemainingBytes > 0)
                {
                    int offset = il.Offset;
                    ushort code = il.ReadByte();
                    if (code == 0xfe) code = (ushort)(0xfe00 | il.ReadByte());
                    if (!Opcodes.TryGetValue(code, out var op)) throw new BadImageFormatException("Unknown IL opcode");
                    bool token = op.OperandType is OperandType.InlineField or OperandType.InlineMethod or OperandType.InlineType or OperandType.InlineTok;
                    if (token)
                    {
                        EntityHandle operand = MetadataTokens.EntityHandle(il.ReadInt32());
                        int sourceToken = MetadataTokens.GetToken(operand);
                        string genericSignature = operand.Kind == HandleKind.MethodSpecification ?
                            Convert.ToHexString(md.GetBlobBytes(md.GetMethodSpecification((MethodSpecificationHandle)operand).Signature)) : "";
                        if (operand.Kind == HandleKind.MethodSpecification) operand = md.GetMethodSpecification((MethodSpecificationHandle)operand).Method;
                        string signature = operand.Kind switch
                        {
                            HandleKind.MemberReference => Convert.ToHexString(md.GetBlobBytes(md.GetMemberReference((MemberReferenceHandle)operand).Signature)),
                            HandleKind.MethodDefinition => Convert.ToHexString(md.GetBlobBytes(md.GetMethodDefinition((MethodDefinitionHandle)operand).Signature)),
                            HandleKind.FieldDefinition => Convert.ToHexString(md.GetBlobBytes(md.GetFieldDefinition((FieldDefinitionHandle)operand).Signature)),
                            _ => ""
                        };
                        string displaySignature = operand.Kind switch
                        {
                            HandleKind.MethodDefinition => provider.Method(md.GetMethodDefinition((MethodDefinitionHandle)operand).DecodeSignature(provider, (object)null)),
                            HandleKind.MemberReference => md.GetMemberReference((MemberReferenceHandle)operand).GetKind() == MemberReferenceKind.Method ?
                                provider.Method(md.GetMemberReference((MemberReferenceHandle)operand).DecodeMethodSignature(provider, (object)null)) :
                                md.GetMemberReference((MemberReferenceHandle)operand).DecodeFieldSignature(provider, (object)null),
                            HandleKind.FieldDefinition => md.GetFieldDefinition((FieldDefinitionHandle)operand).DecodeSignature(provider, (object)null),
                            _ => ""
                        };
                        dependencies.Add(new { caller = Name(h), caller_token = MetadataTokens.GetToken(h), offset, opcode = op.Name, target = Name(operand), token = MetadataTokens.GetToken(operand), source_token = sourceToken, signature, generic_signature = genericSignature, display_signature = displaySignature });
                        if (operand.Kind == HandleKind.MethodDefinition)
                        {
                            var callee = (MethodDefinitionHandle)operand;
                            queue.Enqueue(callee); Init(md.GetMethodDefinition(callee).GetDeclaringType());
                        }
                        else if (operand.Kind == HandleKind.FieldDefinition) Init(md.GetFieldDefinition((FieldDefinitionHandle)operand).GetDeclaringType());
                        else if (operand.Kind == HandleKind.TypeDefinition) Init((TypeDefinitionHandle)operand);
                        else blockers.Add("External or unresolved dependency: " + Name(operand));
                        if (op == OpCodes.Callvirt || op == OpCodes.Ldvirtftn) blockers.Add("Virtual dispatch requires runtime target: " + Name(operand));
                    }
                    else
                    {
                        int size = op.OperandType switch
                        {
                            OperandType.InlineNone => 0,
                            OperandType.ShortInlineBrTarget or OperandType.ShortInlineI or OperandType.ShortInlineVar => 1,
                            OperandType.InlineVar => 2,
                            OperandType.InlineI8 or OperandType.InlineR => 8,
                            OperandType.InlineSwitch => checked(il.ReadInt32() * 4),
                            _ => 4
                        };
                        if (size < 0 || size > il.RemainingBytes) throw new BadImageFormatException("Truncated IL operand");
                        il.Offset += size;
                        if (op == OpCodes.Calli) blockers.Add("Indirect call: " + Name(h));
                    }
                }
            }
            Console.WriteLine(JsonSerializer.Serialize(new {
                format = "mobile-content-reachability-v1", content_type = args[1], assembly_executed = false,
                root_methods = roots?.OrderBy(n => n).ToArray(),
                compatibility_verified = false, safe_to_execute = false,
                methods = visited.OrderBy(h => MetadataTokens.GetToken(h)).Select(h => new { token = MetadataTokens.GetToken(h), name = Name(h) }),
                dependencies, blockers,
                limitations = new[] { "Conservative IL dependency closure, not proven runtime reachability.", "External dependencies are not assumed supported.", "Reflection, delegates, generic specialization, virtual dispatch and external lifecycle require further audit.", "Names do not establish signatures or ABI compatibility; no execution authorization is produced." }
            }, new JsonSerializerOptions { WriteIndented = true }));
            return 0;
        }
        catch (Exception e) { Console.Error.WriteLine(e.GetType().Name + ": " + e.Message); return 2; }
    }
    static string Join(string ns, string name) => ns.Length == 0 ? name : ns + "." + name;
}

// Decode metadata type expressions; these names do not assert runtime support.
internal sealed class MetadataTypes : ISignatureTypeProvider<string, object>
{
    readonly MetadataReader reader;
    readonly Func<EntityHandle, string> name;
    int depth;
    public MetadataTypes(MetadataReader reader, Func<EntityHandle, string> name)
    { this.reader = reader; this.name = name; }
    public string Specification(TypeSpecificationHandle handle)
    {
        if (++depth > 64) { depth--; throw new BadImageFormatException("Type specification depth exceeded"); }
        try { return reader.GetTypeSpecification(handle).DecodeSignature(this, (object)null); }
        finally { depth--; }
    }
    public string Method(MethodSignature<string> signature) =>
        signature.ReturnType + " (" + string.Join(", ", signature.ParameterTypes) + ")";
    public string GetArrayType(string elementType, ArrayShape shape) => elementType + "[" + new string(',', shape.Rank - 1) + "]";
    public string GetByReferenceType(string elementType) => elementType + "&";
    public string GetFunctionPointerType(MethodSignature<string> signature) => "fnptr " + Method(signature);
    public string GetGenericInstantiation(string genericType, ImmutableArray<string> typeArguments) => genericType + "<" + string.Join(", ", typeArguments) + ">";
    public string GetGenericMethodParameter(object context, int index) => "!!" + index;
    public string GetGenericTypeParameter(object context, int index) => "!" + index;
    public string GetModifiedType(string modifier, string unmodifiedType, bool isRequired) => unmodifiedType + (isRequired ? " modreq(" : " modopt(") + modifier + ")";
    public string GetPinnedType(string elementType) => elementType + " pinned";
    public string GetPointerType(string elementType) => elementType + "*";
    public string GetPrimitiveType(PrimitiveTypeCode typeCode) => "System." + typeCode;
    public string GetSZArrayType(string elementType) => elementType + "[]";
    public string GetTypeFromDefinition(MetadataReader md, TypeDefinitionHandle handle, byte rawTypeKind) => name(handle);
    public string GetTypeFromReference(MetadataReader md, TypeReferenceHandle handle, byte rawTypeKind) => name(handle);
    public string GetTypeFromSpecification(MetadataReader md, object context, TypeSpecificationHandle handle, byte rawTypeKind) => Specification(handle);
}
