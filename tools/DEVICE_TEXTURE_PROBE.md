# Native texture diagnostics

[Русский](DEVICE_TEXTURE_PROBE.ru.md)

These tools require an explicitly selected authorized native ARM64 Android target, the pinned researched library, and an already configured loopback Frida server/ADB forward. They do not install a server or restart the game. The optional item-icon mode publishes and restores copied laboratory tables; see [item texture binding](ITEM_TEXTURE_BINDING.md). Keep the game on its menu and retain a private save backup before tests. All outputs must be outside this checkout.

`collect_texture_capabilities.py` verifies the direct library file hash, then reads class/method metadata. It invokes no game/Unity methods and makes no content changes.

```powershell
python tools/collect_texture_capabilities.py --serial '<serial>' --lab '<private-lab>' --expected-library-sha256 '<verified-library-sha256>'
python tools/probe_device_texture_upload.py --serial '<serial>' --lab '<private-lab>/synthetic'
python tools/probe_device_texture_upload.py --serial '<serial>' --lab '<private-lab>/coordinates' --calibrate-uv
python tools/probe_device_texture_upload.py --serial '<serial>' --lab '<private-lab>/original' --original-packet '<private-host-probe>/original-item.png.tmit' --verify-xna-wrapper --verify-native-asset --verify-private-slot
python tools/probe_device_texture_upload.py --serial '<serial>' --lab '<private-lab>/menu-preview' --original-packet '<private-host-probe>/original-item.png.tmit' --verify-xna-wrapper --verify-native-asset --verify-private-slot --verify-menu-overlay
```

The upload probe **invokes graphics methods**. It checks exact signatures/native offsets and schedules work through a temporary Main.Draw observer after checking the main thread. Its scope is one temporary Unity texture, at most 256×256 and 64 KiB PNG input, with at most eight RGBA sample checks. The original mode accepts only the hash-pinned HelicopterParts raw image and host probe packet, not arbitrary mod assets. Optional XNA wrapping checks Width/Height and the Unity object reference. Ordinary graphics resource counters may advance; no counters are rewound.

`--verify-native-asset` additionally creates a standalone `Asset<Texture2D>`, checks loaded state and its value, then verifies disposal. `--verify-private-slot` requires that option and installs the Asset in a separate one-element array of the actual mobile element type. Managed `Array.SetValue/GetValue` handle references; the array is never assigned to a game field. Its loaded Asset/Unity object is checked over two subsequent Draw calls, then the lease restores the original null entry. This establishes a short frame-boundary check, not a forced-GC or sustained-lifetime test.

`--verify-menu-overlay` requires the private-slot phase. For about three seconds it adds an enlarged diagnostic image to an already active main menu SpriteBatch using the checked Rectangle/Color Draw overload. Struct sizes and fields are read from runtime metadata; no guessed native argument layout is used. The observer is removed and resources survive two further Draw calls before release. A screenshot is captured only while Terraria is foreground, and a capture failure still waits for normal teardown. Submission/capture is not automatically a visual pass; inspect the private image separately. This preview does not register an item or test its inventory renderer.

Original mode also runs the native-side TMIT receiver before graphics setup. The expected generation is the independently pinned host diagnostic generation; mismatched asset/archive/generation and a damaged payload are rejected. The receiver requires the known PNG digest from a host-validated plan and checks bounded framing, strict UTF-8, GUID layout, SHA256, PNG dimensions/profile and CRCs. It does **not** inflate zlib rows; those are checked by the managed host and independent PNG reader. This is a small-texture diagnostic subset, not an untrusted general PNG decoder or live registry generation binding.

On completion the probe requests deferred Unity destruction, observes the object becoming invalid in a later frame, frees its GC handles and removes its observer. An incomplete cleanup is a failed test: retain the private report and resolve it before further probes. Without `--verify-item-icon`, game content tables are untouched. Item-icon mode temporarily publishes copied tables and restores their original references. No mode writes inventory, worlds or saves. Pixel reading confirms engine texture contents; optional menu preview submission and visual review are separate evidence.

Observed on the pinned build: synthetic texture load/readback/destruction, 4×4 UV calibration, original HelicopterParts dimensions and eight RGBA samples, mobile XNA wrapper dimensions/reference, and observed cleanup all passed. An earlier center-average assumption failed; the separate coordinate calibration established the tested pixel-space/PNG-row mapping. The failed result is retained privately. Four player/world save files matched their pre-test hashes; the game process stayed running and its captured crash buffer had no entries. This does not establish full SOTS code/lifecycle support on Android.

The standalone Asset, private-array install/two-frame retention/rollback and four packet rejection controls also passed on the device. Source checks cover 24 receiver cases and 12 lease cases, including partial writes, stale generations, table replacement, foreign ownership and retryable rollback failure:

```powershell
node tools/test_texture_packet.js
node tools/test_texture_slot_lease.js
```

The original HelicopterParts menu preview was also visually reviewed against its private source PNG: silhouette, colors and transparent background were consistent. The preview disappeared after teardown. This was an enlarged preview, not an exact screen-pixel or inventory-item comparison. The basic synthetic path passed after the overlay implementation; final process/save/crash checks also passed.

The reusable lease requires an adapter that serializes writers on the game thread and holds all GC roots until successful release. An unresolved live lease must retain its resources for recovery. The separate [item-icon scope](ITEM_TEXTURE_BINDING.md) subsequently verified copied-table publication and host registry unload ordering. General companion integration, actual inventory/gameplay and long-running resource behavior remain pending.

`device_texture_teardown.py` preserves a pending cleanup controller across client detach when possible. Nine mocked host cases passed; the normal synthetic device path passed after this change. Paused/failed device cleanup retention remains untested. Retained cleanup must be resolved before another probe.

`--own-bridge-export` accepts only the fixed own 2×2 `TextureBridgeLab/Icon` envelope. The [Android controller](ANDROID_TEXTURE_BRIDGE.md) keeps its registry alive until native teardown; reading an export file alone does not establish a live owner or authorize arbitrary mod resources.
