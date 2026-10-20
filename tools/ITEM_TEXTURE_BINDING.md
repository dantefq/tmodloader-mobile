# Laboratory item texture binding

[Русский](ITEM_TEXTURE_BINDING.ru.md) · [Native texture diagnostics](DEVICE_TEXTURE_PROBE.md)

The checked path now connects a live **host** C# registry to the native game's item-icon renderer. This is a bounded laboratory adapter for one researched build, not full SOTS loading or a production mod importer.

`MobileContentRegistry.PrepareItemTextureBinding(id)` creates an immutable binding to the item identity, resource provider, registry generation and packet. Its PNG is checked with the managed bounded row reader before its digest enters the plan. `ValidateOwner`, `CopyPacket` and `PlanJson` reject an unloaded owner, another registry or a changed resource identity. The small native backend accepts dimensions up to 256×256 and PNG data up to 64 KiB.

`BeginTextureTransfer(binding)` creates a correlated transfer and blocks registry disposal while that transfer remains pending. A second transfer for the same item is rejected. The trusted backend calls `CompleteNativeTeardown(transferId)` only after native references/observers/resources have been released. Wrong or replayed acknowledgements cannot complete another transfer. Changing a configurable texture key does not prevent acknowledging already completed teardown. These APIs assume serialized host operations; they do not authenticate an untrusted backend or infer GPU state from an acknowledgement.

The laboratory sequence is:

1. Keep an own C# registry alive and export its checked packet and `tmal-item-texture-transfer-v1` plan.
2. Validate packet and plan identities before graphics calls; create Unity/XNA/Asset objects on the game thread in the offline menu.
3. Prepare extended copies of the pinned 129 item tables through managed `Array.Copy`. Check all original references before publication and assign the image only to the new laboratory slot.
4. Draw an isolated item with type 6196 through `ItemSlot.DrawItemIcon`. Observe queue growth and the exact uploaded XNA texture in the current SpriteBatcher array; inspect the private screenshot separately.
5. Remove observers, restore table references and observe deferred Unity destruction. Retain resources if reference rollback remains unresolved.
6. Acknowledge the matching transfer, then dispose the host registry. The old binding is invalid after unload.

The native item is a stock-template renderer fixture. It never enters an inventory or save, does not establish SOTS gameplay defaults, and does not register ContentSamples dictionaries or a general SetDefaults hook. The host's own resource archive contains only a private copy of the hash-pinned HelicopterParts texture; it is **not** the SOTS mod archive. No original mod DLL executes in this path, on host or Android. Original assets, packets, screenshots and logs stay outside published source.

Two consecutive transfer-guard cycles passed on the device. During both, the host registry stayed active until native table restoration and destruction completed; pending-transfer unload was rejected. In the next registry generation, the previous packet was rejected before graphics despite identical item ID, asset, archive and PNG identity. Six rejection controls passed in the first cycle and seven in the next. The isolated icon was visually reviewed; this is not an inventory/gameplay test or an exact screen-pixel comparison. The game process stayed running, four player/world files matched the pre-test backup and the captured crash buffer was empty.

Host checks cover 57 registry image/resource/lifecycle cases. Source-only JavaScript checks cover 24 packet, 12 slot-lease and 13 table-transaction cases. The full existing managed host suite also passed; optional external upstream conformance inputs were not supplied.

With an authorized target already in its menu, a private backup and the existing loopback Frida setup:

```powershell
python tools/probe_registry_texture_binding.py --tmod '<pinned-SOTS.tmod>' --lab '<new-private-lab>' --host-only
python tools/probe_registry_texture_binding.py --tmod '<pinned-SOTS.tmod>' --lab '<new-private-lab>' --serial '<serial>'
python tools/probe_registry_texture_binding.py --tmod '<pinned-SOTS.tmod>' --lab '<another-new-private-lab>' --serial '<serial>' --previous-binding '<previous-private-lab>/fixture/texture-binding-plan.json'
```

Each run requires a new lab directory. Host-only mode does not execute Android. The native mode does not launch/restart the game, open a world or modify inventory/saves. An interrupted native probe requests game-thread cleanup and records teardown status privately; an unresolved teardown is a failed run requiring recovery before another probe.

General companion integration, dynamic ID allocation, multiple-mod/shared texture ownership, full inventory/tooltips/gameplay, persistence, original SOTS lifecycle on Android and sustained resource tests remain pending.

The host fixture now uses `MobileTextureBridge`; its pinned-original native cycle passed. The subsequent [Android bridge lab](ANDROID_TEXTURE_BRIDGE.md) passed both a separate Android app and a separate texture companion inside the game process, using an own 2×2 image with real cleanup ACK. Common item/time integration remains pending.

The client unloads its script only after a terminal native cleanup state. Pending cleanup retains the controller in the target when possible, so original table references and GC roots survive client detach. Nine mocked host cases cover terminal, retryable, paused and uncertain-transport paths. The ordinary synthetic upload/cleanup also passed on the device after this change; controller retention during a paused or failed device cleanup has not been exercised. A retained controller is recovery state, not successful teardown; resolve it before another probe.
