# Content dependency audit

[Русский](CONTENT_REACHABILITY.ru.md)

`audit_content_reachability.py` validates a local `.tmod` payload and inventories IL dependencies of one exact content type without loading its assembly into the CLR. It builds the project's own metadata reader with the pinned .NET SDK. Compiler outputs, the selected DLL and reports must stay outside this checkout.

```powershell
python tools/audit_content_reachability.py '<mod.tmod>' --assembly SOTS.dll --type SOTS.Items.AbandonedVillage.AVPot --lab '<private-lab>'
python tools/test_content_reachability.py
```

The reader follows local method references, inherited local callbacks, constructors and referenced owners' static initializers. Add `--methods .ctor SetDefaults` to choose method roots; transitive calls and initializers remain included. Module initializers are included and flagged. Each dependency retains its caller token, IL offset, opcode, target token and available signature blob; generic method references also retain their original token and instantiation blob. Overloads remain distinct by token. Type expressions and method/field signatures are decoded into readable names, including generic owners.

External references, missing bodies, virtual dispatch and indirect calls are explicit unresolved entries. `callvirt` is conservatively flagged even when C# used it only for a null check. Decoded generic names do not resolve their methods or static initialization semantics. Reflection, delegates, external lifecycle and signature/local-variable type closure require further analysis. This is a conservative inventory, not a complete semantic call graph or execution permission. Reports always set `safe_to_execute`, `assembly_executed` and `compatibility_verified` to false.

Host regression compiles an independent fixture and verifies inherited/helper/initializer traversal, distinct overloads, unrelated-method exclusion, dispatch uncertainty and rejection of missing types/malformed images. This does not verify a mod in Android.

The first audit used SOTS 0.25.1.9, TMOD SHA-256 `4642380a29751664afa9122f01a8cf4491232ef9cd7bdb40e15c6d8e4e7c3790`, DLL SHA-256 `e96d7591ec56f5236454931ae0a3045be6072d2a7649f70679131bf0f0ee338f`. AVPot requires tile APIs; AncientSteelBar, OldKey and ExcavatorMask reach graphics/resource helpers. These four audits establish dependencies only; no SOTS code was executed. Original code/assets and raw reports remain private; no redistribution permission is assumed.

Subsequent separately gated original-code execution is described in the [host slice](SOTS_HOST_SLICE.md).
