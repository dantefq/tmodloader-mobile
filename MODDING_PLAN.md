# Architecture

[Русский](MODDING_PLAN.ru.md) · [README](README.md)

Android Terraria uses Unity/IL2CPP; PC tModLoader mods are managed assemblies. The prototype hosts selected code in Mono and translates narrowly supported interactions to the mobile runtime.

| Component | Responsibility |
|---|---|
| Java companion/instrumentation | Fixed-bundle validation, managed runtime preparation, compatible-certificate USB/ADB launch |
| Frida/native bridge | Validated IL2CPP metadata, build-specific method/field bindings and guards |
| Shared Mono bootstrap | Domain/image coordination, thread attachment, balanced GC transitions and rooted values |
| Independent compatibility API | Selected configuration, metadata, registries, item/time and persistence contracts |
| Feature adapters | Real game state bindings; respawn uses a separate bounded snapshot host and scoped clamp lease |
| Sidecar | Stable mod item key/player-file fingerprint and vanilla placeholder; mismatch rejection without atomic recovery |

Builders validate pinned inputs and preceding isolated checkpoints, then produce private outputs. Variants have different verified scopes; installing one does not merge all features.

Managed snapshots are values, not native game objects. Broad content needs lifecycle ordering, original assets, native bindings, dependencies and world/save semantics. Arbitrary desktop On/IL hooks cannot be assumed to work on IL2CPP.

Game assemblies, decompiled game source, third-party mod binaries, private evidence and keys are not distributed. See [limitations](README.md#limitations) and [roadmap](ROADMAP.md).
