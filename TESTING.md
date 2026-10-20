# Testing

[Русский](TESTING.ru.md) · [README](README.md)

Completed categories: host API/serialization/metadata/dependency and rejection checks; isolated Android execution of own demos and original small-mod DLLs with post-GC callbacks; actual item tooltip/attacks; restricted sidecar save/restart and separate item-build off/on; real sleep/time/config/off/on/restart; laboratory protection checks.

The combined item/time build has item/sleep and item restoration evidence. Combined off/on and restart-session sleep are pending. ShorterRespawn has isolated and native short-respawn evidence; subsequent disabled/long/live-adjustment behavior was observed, but final saved matrix collection and restart are pending. SOTS has static audit evidence and bounded original defaults probes for HelicopterParts, Snakeskin and Curgeon on host snapshots, plus CPU decoding of their original textures; full lifecycle and Android remain unverified. See [host slice](tools/SOTS_HOST_SLICE.md). The investigated translated-emulator route failed before managed execution.

A build is not a runtime test; a probe is not game integration; static audit is not compatibility. Tests against our API do not emulate the complete game. Local collectors bind artifacts and copied managed files to hashes. Logs and visually reviewed screenshots support different claims. A queued command is not an executed test.

Source-only checks, from the repository root:

```powershell
node tools/test_mono_runtime.js
node tools/test_respawn_clamp.js
node tools/test_texture_packet.js
node tools/test_texture_slot_lease.js
node tools/test_content_table_lease.js
node tools/test_texture_export.js
python tools/test_combined_script.py
python tools/test_device_texture_teardown.py
```

These check orchestration/guards, not real game behavior. Other scripts may require local .NET/game references, metadata dependencies or private checkpoint fixtures. Missing private evidence must not be counted as passing.

The separate [native texture diagnostic](tools/DEVICE_TEXTURE_PROBE.md) passed temporary Unity/XNA/Asset creation from a checked original packet, eight RGBA checks, private-array retention across two Draw calls, rollback and deferred destruction. Four mismatched/damaged packet controls were rejected before graphics setup. An optional brief SpriteBatch menu preview of the original texture was captured and visually reviewed; it disappeared after teardown. No game texture table or inventory entry was installed; registered-item inventory rendering and full SOTS DLL execution remain unverified.

For new game checkpoints: back up saves/sidecars, validate the exact build in isolation, inspect the real scene, exercise on/off/config, save normally, restart into a new process, verify restoration and final save, then collect artifact-bound evidence. Detailed logs, screenshots and device data stay private; the [public summary](reports/public-validation-summary.json) is generalized.

Still needed: arbitrary mods, combined off/on, respawn restart, general persistence/recovery, content/assets/projectiles/NPCs/world generation, multiplayer and sustained performance/platform coverage.

The subsequent [item texture binding](tools/ITEM_TEXTURE_BINDING.md) passed two live-host/native laboratory transfer cycles: temporary publication/restoration of 129 copied tables, isolated type-6196 ItemSlot rendering with exact queued texture checks, unload blocking until teardown acknowledgement, and rejection of the previous generation with unchanged resource identities. Inventory contents, gameplay, full SOTS execution and sustained resource behavior were not tested. The final host image/resource/lifecycle suite has 57 own cases; the table transaction adds 13 own JavaScript cases.

Cleanup-controller retention has nine mocked host cases and a normal synthetic device regression. Paused/failed cleanup retention has not been tested on the device.

The [Android texture bridge](tools/ANDROID_TEXTURE_BRIDGE.md) adds 29 managed export/lifecycle and 18 JavaScript envelope cases. All 29 managed checks ran on host and Android. The final Android-to-game lab kept its registry live across GC, native rendering, four RGBA checks, restoration of 129 copied tables and deferred destruction; six invalid inputs were rejected. Real matching ACK preceded registry unload, and process/save/crash checks passed. This is an own 2×2 fixture in two processes, not the companion or inventory/gameplay. The isolated no-graphics mode passed with simulated ACKs before the final export-size guard; final native-game mode exercised that guard on Android.

The subsequent separate texture companion passed the same own-fixture path inside the game process, including all 29 managed checks, GC and native cleanup before ACK. The game APK was unchanged. After controller detach, the new instrumented process remained alive, all four baseline saves matched and its captured crash buffer was empty. The main menu before/after probing was viewed privately; the tiny dark fixture has no visual-equivalence claim. General item/time integration, inventory/gameplay and sustained lifecycle remain pending.

## Latest lifecycle finding — 2026-10-20

The fixed pinned-original texture profile passed host, isolated Android and separate-process native checks. It completed in-process rendering, table restoration, resource destruction and correlated acknowledgement, but that process subsequently crashed after controller detach with a Mono thread/signal assertion. Read-only diagnostics found IL2CPP owned its suspend/restart signal handlers before late Mono initialization. The new companion initializes Mono before launching Unity and records signal ownership; this candidate has only built and passed syntax checks so far. Its Android lifecycle and post-detach checks have NOT run. Earlier short-lived health results do not establish stability.
