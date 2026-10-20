# tModLoader Mobile — Experimental

English · [Русский](README.ru.md)

**Unofficial research project. Not affiliated with or endorsed by Re-Logic or the tModLoader team.**

An experimental project for running selected PC Terraria mod code inside Android Terraria through an independently written compatibility layer and native bridges.

**Checkpoint: 2026-10-20. This is prototype source code, not a general-purpose mobile tModLoader or a ready-to-install release.**

## Demonstrated features

- JSON item changes and our own PC-compiled GlobalItem/ModItem demos inside the mobile game.
- A custom test item with a runtime ID, tooltip and real attacks; sidecar saving and automatic restoration after a new game process.
- The original unchanged ChangeSleepTime DLL on Android, actual sleep, configurable acceleration, off/on and save/restart checks.
- A combined item/time build: shared Mono, real item attacks and sleep, then saved custom-item restoration after restart. Combined off/on regression remains pending.
- Laboratory invulnerability and knockback prevention, including controlled hits and toggle checks.
- Original ShorterRespawn callbacks in isolation and a dedicated native adapter driving actual respawns. Short, disabled and long-timer transitions were observed; final saved matrix/restart verification is unfinished.

Tests cover deliberately restricted scenarios. They do not establish compatibility with arbitrary PC mods.

The [Android texture bridge](tools/ANDROID_TEXTURE_BRIDGE.md) has rendered fixed own and pinned-original textures through a managed registry and temporary native icon. Table restoration, destruction and acknowledgement passed. A later in-process run crashed after controller detach; the Mono-before-Unity bootstrap has built but has not yet run on Android. In-process stability is an open issue.

## Limitations

- **Arbitrary `.tmod` imports, full tModLoader compatibility, multiplayer, Calamity, Infernum Mode and Thorium are not supported.**
- **Secrets Of The Shadows** is the next content target. Unchanged defaults for `HelicopterParts`, `Snakeskin` and `Curgeon` ran on host snapshots and matched bundled sources; their original textures decoded on CPU. One original texture also passed a live-host-registry to native item-icon laboratory path with generation/teardown checks. Full mod lifecycle and gameplay support remain unverified.
- Native ARM64 and one researched Android game build are targeted. Other builds, signatures and architectures need separate work. The investigated translation-based emulator route failed before managed execution.
- Each new game process currently needs a computer and authorized USB/ADB bootstrap. Standalone launch is unfinished. Some diagnostics and laboratory controls require root; not every demonstrated route requires root.
- Companion instrumentation needs a compatible signing certificate. An arbitrary official installation is not automatically supported. No game APK or signing keys are provided.
- The respawn adapter uses a separate snapshot API/build; it is not integrated into the common item/time build. Feature variants have different tested scopes.
- Persistence covers one known test item in a designated inventory/profile/world. Player and sidecar writes are not atomic; mismatch rejection exists, general recovery/migration does not. Banks, chests and world data remain unfinished.
- Real projectiles/NPCs, tiles/world generation, assets/rendering, recipes, UI and arbitrary On/IL hooks need substantial work. Broad compatibility, sustained performance and long-session stability are unproven.

No reliable release date or meaningful compatibility percentage is available.

## Development and launch

The repository contains our Java, C#, JavaScript and Python source. Game files, third-party mod binaries, saves, private device reports, keys and build outputs are excluded from publication.

Tooling uses Python, Node.js, .NET SDK, JDK, Android SDK, a pinned Mono runtime and Frida Gadget. Individual scripts provide `--help`. Some require local dependencies and private validation reports from earlier steps; a fresh clone is not a self-contained build environment.

For an already built compatible companion, save and exit the world first:

```powershell
python tools/start_mobile.py --serial <ADB_SERIAL> --managed-demo --saved-and-exited
```

This does not install dependencies or convert arbitrary `.tmod` files. Select the correct companion variant beforehand. Builders do not install output automatically. Back up game saves and loader sidecars before testing; do not clear app data as an update step.

Disable supported features through **Mobile Mods**, then save/exit and reload when required. Launch the original game normally for ordinary play; retain sidecars/backups until custom content is safely recovered.

## Documentation

| English | Русский | Contents |
|---|---|---|
| [Status](STATUS.md) | [Состояние](STATUS.ru.md) | Verified scope and unfinished work |
| [Testing](TESTING.md) | [Проверки](TESTING.ru.md) | Test summary and evidence boundaries |
| [Roadmap](ROADMAP.md) | [План](ROADMAP.ru.md) | Milestones and acceptance criteria |
| [Architecture](MODDING_PLAN.md) | [Архитектура](MODDING_PLAN.ru.md) | Runtime and technical constraints |
| [Research](RESEARCH.md) | [Исследования](RESEARCH.ru.md) | Findings and open questions |
| [Item texture binding](tools/ITEM_TEXTURE_BINDING.md) | [Привязка текстуры предмета](tools/ITEM_TEXTURE_BINDING.ru.md) | Laboratory registry/native icon and unload scope |
| [Android texture bridge](tools/ANDROID_TEXTURE_BRIDGE.md) | [Android-адаптер текстур](tools/ANDROID_TEXTURE_BRIDGE.ru.md) | Own Android registry, native icon and correlated teardown |
| [Changelog](MODLOG.md) | [История](MODLOG.ru.md) | Concise development checkpoints |

[Public validation summary](reports/public-validation-summary.json) contains generalized outcomes. Detailed local evidence is intentionally private; the summary is not an independently reproducible evidence bundle.

## Credits and rights

Developed with OpenAI Codex and AI assistance. Terraria belongs to its rights holders. tModLoader and third-party mods belong to their contributors and are not distributed here. Frida and Mono/.NET retain upstream licenses/notices: [Frida](https://github.com/frida/frida), [dotnet/runtime](https://github.com/dotnet/runtime), [tModLoader](https://github.com/tModLoader/tModLoader).

No project-wide open-source license has been declared. Public availability alone does not grant redistribution rights. This independent project is not an official Terraria or tModLoader product.

## Research downloads

[Reverse-engineering research](research/README.md) describes separately packaged decompilation, pseudocode and declaration outlines. These are reconstructed analysis artifacts, not the original source project or a buildable replacement. Game binaries, assets, saves and raw device logs are excluded.

## Current checkpoint

The fixed-profile tests passed 17 host profile checks and 15 independent rejection checks, plus 29 bridge and four profile checks on Android. The pinned texture passed the separate-process renderer/rollback path. In-process rendering and cleanup completed, followed by a native thread/signal assertion after detach. The early-bootstrap candidate is unverified. Short checks do not prove long-session stability.

Code and documentation were developed with assistance from OpenAI Codex. This source checkpoint is not an installable release.
