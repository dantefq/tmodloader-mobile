# Original SOTS defaults: host slice

[Русский](SOTS_HOST_SLICE.ru.md)

The pinned SOTS release and hashes are in [AGENTS.md](../AGENTS.md). Original code/assets and detailed reports stay in a private lab; no redistribution permission is assumed.

```powershell
python tools/probe_sots_item_defaults.py '<SOTS.tmod>' --lab '<private-lab>'
python tools/probe_sots_item_defaults.py '<SOTS.tmod>' --lab '<private-lab>' --type SOTS.Items.Pyramid.Snakeskin
python tools/probe_sots_item_defaults.py '<SOTS.tmod>' --lab '<private-lab>' --type SOTS.Items.Fishing.Curgeon
python tools/test_pc_item_economy.py --lab '<private-lab>'
python tools/test_sots_probe_scope.py
```

The first command **executes original mod code** in a separate host CLR process. Before execution it validates archive/DLL/source hashes and inventories only the selected constructor/SetDefaults roots (HelicopterParts, Snakeskin or Curgeon). The exact method closure, dependency counts and signatures must match the reviewed profile. Extra initializers, indirect dispatch, changed signatures or generic specializations fail. This restriction is specific to this pinned item; it is not a general sandbox for arbitrary DLLs.

The original selected constructor and SetDefaults execute against independently written snapshot APIs. Two instances are compared with an oracle parsed from the shipped source; the rarity symbol is resolved from the local PC API's constant table. The original DLL is not rewritten or recompiled. Mod.Load, SetStaticDefaults, registration, recipes, effects, save/reload and Android are not invoked or verified.

The item API now owns width/height on Entity, and implements Int32 buyPrice/sellPrice arithmetic with wrapping. An own probe compiled against local PC tModLoader verifies member binding and selected values against our shim. This is a binary contract check, not execution of the PC game.

The original item texture is read through MobileTmodArchive and decoded by MobileRawImage. The raw format is version/width/height as little-endian Int32 followed by RGBA bytes, as described by upstream [ImageIO](https://github.com/tModLoader/tModLoader/blob/1.4.4/patches/tModLoader/Terraria/ModLoader/IO/ImageIO.cs). Pixels remain unchanged, including transparent channels. Bounds, exact payload length and caller resource budget are enforced; stricter malformed-input rejection is intentional. CPU decoding creates no texture/GPU resource. [RawImgReader](https://github.com/tModLoader/tModLoader/blob/1.4.4/patches/tModLoader/Terraria/ModLoader/Assets/Readers/RawImgReader.cs) shows the separate graphics creation step that remains to be bound.

Local evidence: all three item types matched both instances (six snapshots total), their original texture dimensions matched item dimensions, and all three decoded pixel SHA-256 values matched archive payloads. Lossless PNG transports passed independent Pillow decoding for the three originals and three transparency/row-order fixtures. Android execution, rendering and full SOTS support remain unverified.

Separate [native texture diagnostics](DEVICE_TEXTURE_PROBE.md) subsequently verified temporary Unity loading/readback and mobile XNA wrapping of HelicopterParts on a native ARM64 target. Packet delivery, standalone Asset creation and private-array rollback also passed; a brief menu preview was visually reviewed, then removed. This does not execute SOTS's DLL or establish a registered inventory item.

`MobileContentRegistry.ReadItemImage` now resolves registered items' qualified rawimg paths through their loaded resource provider and a per-registry LRU cache. Vanilla atlas aliases require a native binding and are rejected explicitly. Cache keys include archive SHA-256 and canonical entry path; unload releases cache ownership. The configurable budget bounds cached pixel bytes, not total process memory, transient decoding/PNG allocations or images retained by callers. Synthetic tests cover 17 registry/resource/lifecycle cases (including cross-mod providers and unload failure) and 27 raw-image/cache/bounds cases. These registry lifecycle checks use own fixtures, not the full SOTS lifecycle.

A later [own-registry texture fixture](ITEM_TEXTURE_BINDING.md) keeps the C# owner alive through native ItemSlot icon rendering and table/resource teardown. It copies the pinned texture into an explicitly separate private laboratory archive, and executes no original SOTS code. This does not satisfy the real SOTS manifest, dependency graph or full lifecycle.
