# Research findings

[Русский](RESEARCH.ru.md) · [README](README.md)

- Selected PC-compiled callbacks can run through an independent Android API; own demos and unchanged small-mod DLLs provide distinct evidence.
- Actual game behavior needs native integration. Signature matching, isolated callbacks and class counts are insufficient.
- Shared Mono initialization and thread/GC transitions matter when adapters coexist. Post-GC checks are narrow transport evidence, not indefinite stability.
- Placeholder/sidecar persistence works for a restricted item scenario. General inventory/world persistence and coherent recovery remain unfinished.
- ChangeSleepTime has actual time/sleep evidence. ShorterRespawn has callback/native respawn evidence; its final saved/restarted regression remains pending.
- SOTS has package/API/resource audits and one bounded original item-defaults host probe. A small method count does not make an item easy: helpers, constructors, assets and lifecycle paths also matter. The selected defaults probe omits static defaults and full mod lifecycle explicitly; CPU texture decoding does not prove rendering.
- Calamity/Infernum dependency/signature research identifies blockers; a valid graph does not prove detours, shaders, subworlds or boss AI.
- The investigated translated emulator failed before managed execution; this is not a verdict about every emulator.
- Standalone launch is unresolved. A small control reaching a lifecycle stage does not prove the full game/runtime launches without USB.

Open questions: general content registration, FNA/ReLogic, object lifetimes, hooks, UI/rendering, world generation, save recovery and sustained CPU/memory/frame-time costs. No reliable compatibility percentage or release date follows from current evidence.

## Latest lifecycle finding — 2026-10-20

The fixed pinned-original texture profile passed host, isolated Android and separate-process native checks. It completed in-process rendering, table restoration, resource destruction and correlated acknowledgement, but that process subsequently crashed after controller detach with a Mono thread/signal assertion. Read-only diagnostics found IL2CPP owned its suspend/restart signal handlers before late Mono initialization. The new companion initializes Mono before launching Unity and records signal ownership; this candidate has only built and passed syntax checks so far. Its Android lifecycle and post-detach checks have NOT run. Earlier short-lived health results do not establish stability.
