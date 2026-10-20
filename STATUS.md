# Status — 2026-10-20

[Русский](STATUS.ru.md) · [README](README.md)

| Area | Verified scope | Remaining work |
|---|---|---|
| JSON / own PC item demos | In-game name/damage changes, custom item, tooltip and attacks | Arbitrary content registration |
| Item persistence | Sidecar save/restart; separate item-build off/on cycle | One known item only; atomic recovery, banks/chests/world data |
| ChangeSleepTime | Original DLL, actual sleep, configuration, off/on and restart | Event-rate and broader lifecycle |
| Combined item/time | Shared runtime, real attacks/sleep, item restoration after restart | Combined off/on; repeat sleep after restart |
| Lab protection | Controlled invulnerability/no-knockback and switching checks | Designated offline classic test profiles only |
| ShorterRespawn | Original callbacks, Android GC/transport checks, native short respawn; off/long/live adjustment observed | Final saved matrix and restart; common API integration |
| SOTS | IL dependency inventories; unchanged constructor/SetDefaults for three item types on two snapshots each matched shipped sources; three raw textures decoded through TMOD reader | Full mod lifecycle/static defaults, original DLL execution on Android, gameplay and saves unverified |
| Content images | Bounded images/packets; live host registry to a new-ID native ItemSlot icon; copied-table publication/rollback; transfer/unload barrier and next-generation rejection verified in two lab cycles | General companion/importer integration, full inventory/gameplay/persistence, shared resource ownership and sustained GPU lifecycle |
| Android texture bridge | Own C# registry and native icon in the same game process through a separate test companion; GC, four RGBA samples, rollback/destruction and real ACK verified | General item/time companion integration and user controls; fixed own 2×2 fixture only |
| Calamity / Infernum | Static dependency/signature research | Not supported; full feasibility unresolved |
| Standalone launch | Several approaches investigated | USB/ADB still required |

Host tests cover selected archive, metadata, signature, dependency, registry, serialization and combat contracts. Counters and matching names are not compatibility percentages. Historical results apply to their tested build/scenario, not automatically to later variants.

Detailed evidence stays private. Next: finish respawn regression and extend the bounded SOTS host slice to lifecycle/resources and Android integration. See [roadmap](ROADMAP.md).

The host content-dependency reader and its regression checks are described in [Content dependency audit](tools/CONTENT_REACHABILITY.md). It reports unresolved paths and never marks content safe to execute.

The bounded [item texture binding](tools/ITEM_TEXTURE_BINDING.md) now connects a live host generation and unload barrier to a temporary native item icon. Its laboratory resource provider is an own fixture, not a loaded SOTS mod.

The subsequent [Android bridge](tools/ANDROID_TEXTURE_BRIDGE.md) passed both external two-process orchestration and a separate companion with the own registry inside the game process. It has 29 managed bridge checks and 18 JavaScript export checks; full inventory/gameplay and SOTS execution remain unverified.

## Latest lifecycle finding — 2026-10-20

The fixed pinned-original texture profile passed host, isolated Android and separate-process native checks. It completed in-process rendering, table restoration, resource destruction and correlated acknowledgement, but that process subsequently crashed after controller detach with a Mono thread/signal assertion. Read-only diagnostics found IL2CPP owned its suspend/restart signal handlers before late Mono initialization. The new companion initializes Mono before launching Unity and records signal ownership; this candidate has only built and passed syntax checks so far. Its Android lifecycle and post-detach checks have NOT run. Earlier short-lived health results do not establish stability.
