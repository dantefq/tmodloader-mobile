# Android texture bridge laboratory

[Русский](ANDROID_TEXTURE_BRIDGE.ru.md) · [Item-icon scope](ITEM_TEXTURE_BINDING.md)

`MobileTextureBridge` exports one pending item texture from an existing registry. Its envelope contains the transfer plan and a Base64 TMIT packet, with a 94,208-character ceiling. The backend still accepts only the bounded 256-side/64-KiB PNG subset. Export failure before returning to the caller releases the unpublished transfer; an oversized item identity cannot leave unload blocked. All registry users must serialize operations through the same supplied gate.

`BeginItem` returns an export, `ReadExport` revalidates its owner, and `CompleteNativeTeardown` requires the matching canonical transfer ID. `Unload` preserves the registry's pending-transfer barrier. The ID provides correlation, not sender authentication or evidence of GPU completion. The JavaScript export reader requires separately supplied registry/item identities, rejects noncanonical Base64 and delegates packet validation to the bounded TMIT reader. Managed code checks decompressed PNG rows before export.

Three different Android checks have run:

- **Isolated app:** own C# registry and own 2×2 RGBA image, managed-to-JavaScript packet transfer, failed unload/ACK controls, GC and subsequent unload. GPU teardown acknowledgements are simulated because this mode creates no game graphics.
- **Separate-process game scope:** the registry stays alive in the own Android app while an external controller sends its checked export to Terraria's native laboratory icon adapter. After GC, the same export remains valid. The adapter checks four RGBA samples, including transparency, rejects six invalid inputs, publishes/restores 129 copied tables and observes resource destruction. Only then does the controller acknowledge the matching transfer back in Android and unload its registry. These acknowledgements follow real native cleanup.
- **In-process test companion:** a separate signed instrumentation package loads the exact Android-tested own assemblies and Mono runtime into the game process, using its own lab folder. The same 29 managed checks, GC and native icon/rollback/destruction/ACK sequence passed there. Installed game APK identity stayed unchanged; post-detach process, four save hashes and crash-buffer checks passed. The test scene was the main menu, with no inventory item inserted.

Both game paths passed with the final bounded bridge. The separate-process path preserves the existing game process. Starting instrumentation for the in-process path deliberately restarts the game after checking a current save baseline; its new process survived the probe and controller detach. These laboratories do not establish inventory/gameplay, arbitrary mod import or original mod DLL execution. Game screenshots remain private; the tiny own fixture has no separate visual-equivalence claim.

The source suite has 29 bridge export/lifecycle cases and 18 JavaScript envelope cases. The 29 managed cases also execute during Android initialization. They include oversized-export rejection with no pending transfer left behind. The full managed host suite passed; optional upstream conformance inputs were not supplied. The existing pinned-original host/native icon path also passed after adopting the common bridge.

Build and run in new private directories, with the existing pinned Mono package and an already configured loopback Frida server:

```powershell
python tools/build_texture_bridge_probe.py --sdk '<SDK>' --jdk '<JDK>' --lab '<new-private-build>' --key '<private-key>' --cert '<certificate>'
python tools/probe_android_texture_bridge.py --serial '<serial>' --build '<private-build>' --lab '<new-private-evidence>'
python tools/probe_android_texture_bridge.py --serial '<serial>' --build '<private-build>' --lab '<another-new-private-evidence>' --native-game --save-backup '<private-Players-Worlds.tar>'
node tools/test_texture_export.js
```

The builder does not install anything or overwrite older reports. The runner installs/starts only the own probe app. Native-game mode additionally requires an existing game process and a current private save baseline; it returns that process to the foreground, with main-thread/offline-menu guards in the native adapter. All build outputs, runtime binaries and detailed evidence remain outside published source.

Uncertain native cleanup cannot authorize an ACK. The controller records recovery state and retains the Android controller when possible. Paused/failed cleanup retention is covered by host mocks, not a deliberate device failure experiment. Resolve pending recovery before starting another probe.

The separate companion requires the researched development-signed target and matching certificate. Build it only from the exact passed own Android probe:

```powershell
python tools/build_texture_companion.py --sdk '<SDK>' --jdk '<JDK>' --lab '<new-private-companion-build>' --key '<private-key>' --cert '<certificate>' --source '<pinned-target.apk>' --probe-build '<passed-private-probe-build>' --probe-validation '<passed-two-process-evidence>/validation.json'
python tools/start_texture_companion.py --serial '<serial>' --build '<companion-build>' --probe-build '<probe-build>' --lab '<new-private-preparation>' --save-backup '<private-Players-Worlds.tar>' --saved-and-exited
python tools/probe_texture_companion.py --prepared '<preparation>/prepared.json' --lab '<new-private-in-process-evidence>'
```

Preparation now loads libraries and verifies copied assemblies before launching Unity. The experimental probe initializes Mono, records signal ownership, launches the activity and checks native offline-menu guards. It requires a full post-detach health interval before reporting success. This new bootstrap has not yet run on Android. The test variant does not alter the existing item/time companion, its settings or sidecars. It has no Gadget or general importer and still needs the authorized external ADB/Frida controller. Restart the game normally for ordinary play after testing.

Still pending: integration with the common item/time companion and user controls, dynamic IDs, multiple content owners, inventory/defaults/tooltips/gameplay, persistence, original SOTS lifecycle and sustained resource testing.

## Latest lifecycle finding — 2026-10-20

The fixed pinned-original texture profile passed host, isolated Android and separate-process native checks. It completed in-process rendering, table restoration, resource destruction and correlated acknowledgement, but that process subsequently crashed after controller detach with a Mono thread/signal assertion. Read-only diagnostics found IL2CPP owned its suspend/restart signal handlers before late Mono initialization. The new companion initializes Mono before launching Unity and records signal ownership; this candidate has only built and passed syntax checks so far. Its Android lifecycle and post-detach checks have NOT run. Earlier short-lived health results do not establish stability.
