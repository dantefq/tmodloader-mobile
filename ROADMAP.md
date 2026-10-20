# Roadmap

[Русский](ROADMAP.ru.md) · [README](README.md)

The final research target is **Calamity + Infernum Mode on Android**. Feasibility and dates are not established. SOTS is the next selected content mod.

1. Finish ShorterRespawn: saved on/off/long/live-adjustment matrix, new-process restart and safe final state.
2. Harden combined item/time: off/save/reload/on in the same build and actual sleep after restart.
3. First SOTS slice: audit lifecycle/reachable calls, unchanged DLL in an isolated Android probe, then one real item with original texture, behavior, save/restart and disabling.
4. Generalize lifecycle/config/registries/dependencies and deterministic IDs across multiple mods; reject unsupported paths explicitly.
5. Make saves recoverable: coherent player/sidecar export/restore, migration, missing-mod retention and broader inventory support.
6. Bind real projectiles/NPCs, assets/rendering, recipes, tiles/world data and generation; verify each in game before expanding SOTS scope.
7. Resolve Calamity/Infernum API, dependency, hooks, rendering and worldgen blockers; verify real combat, saves and performance together.
8. Deliver a supported standalone installation/launch/update/recovery route; expand platform coverage. Multiplayer is a separate later effort.

Other small mods and Thorium remain possible future targets. One successful slice must not be called full mod support. Reassess after concrete lifecycle/content/save/performance milestones; test counts do not measure completion.
