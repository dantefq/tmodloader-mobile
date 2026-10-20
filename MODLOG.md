# Development log

Public experimental loader checkpoints.

## 2026-10-20 — owner-bound item-icon scope

- Added immutable C# item texture bindings and transfer IDs. The host registry blocks unload until a matching native teardown acknowledgement; stale/replayed acknowledgements and changed owners/resources are rejected. The image/resource/lifecycle suite now passes 57 own cases.
- Added a copied-table transaction with 13 own failure/recovery cases. The native lab prepares and restores 129 table references, assigns only its extra texture slot and draws an isolated new-ID item through ItemSlot.DrawItemIcon. Exact queued texture identity and queue growth were checked; screenshots were privately reviewed.
- Passed two consecutive live-host/native transfer-guard cycles. The next generation rejected the prior packet despite identical item/resource/archive/PNG identities. Host unload remained blocked until verified native restoration/destruction. Original SOTS code did not execute in this path; the texture provider is an explicitly own private fixture.
- Retained earlier failed verification attempts privately; the final verifier reads the current SpriteBatcher array/count used by the active sorted path. Final game process, four save hashes and crash-buffer checks passed. Inventory/gameplay, general companion integration and full SOTS remain pending.
- Fixed client cleanup to preserve a nonterminal native controller across detach when possible. Nine mocked host checks and an ordinary synthetic device regression passed; paused/failed device cleanup retention is untested.

## 2026-10-20 — Android texture export bridge

- Added a reusable single-flight managed export bridge and strict JavaScript Base64/envelope reader. Oversized exports release their unpublished transfer instead of leaving unload blocked. Passed 29 managed and 18 JavaScript cases, plus the full managed host suite.
- Built an isolated own Android app with only own mod/resource data and the pinned Mono runtime. Managed-to-JavaScript transfer, GC, invalid ACK/unload and packet/pixel checks passed. No-graphics teardown ACKs are explicitly simulated.
- The final bounded bridge then passed an Android-registry-to-native-game lab: the live Android owner survived GC and rendering, four RGBA samples including transparency matched, six invalid inputs were rejected, 129 copied tables were restored and resources destroyed before real ACK/unload. The existing process, four save hashes and crash buffer passed final checks.
- The pinned-original host/native icon path also passed through the reusable bridge. Android-to-game tests use an own 2×2 image; inventory/gameplay and original SOTS execution remain pending.

## 2026-10-20 — in-process texture companion laboratory

- Packaged the exact Android-tested own assemblies/runtime into a separate instrumentation companion, with a matching researched-target certificate and an isolated lab folder. Existing item/time companions and settings were preserved; no Gadget or game/mod implementation bundled.
- Passed all 29 managed checks, GC, native icon/queue identity, four RGBA samples, six invalid-input controls, 129-table rollback and destruction before matching ACK/unload inside one game process. The APK identity was unchanged.
- After controller detach the new instrumented process remained alive, four baseline save hashes matched and the captured crash buffer was empty. Main-menu scenes before/after probing were viewed privately; the tiny dark fixture has no visual-equivalence claim. General item/time integration, inventory/gameplay and sustained resource testing remain pending.

## Latest lifecycle finding — 2026-10-20

The fixed pinned-original texture profile passed host, isolated Android and separate-process native checks. It completed in-process rendering, table restoration, resource destruction and correlated acknowledgement, but that process subsequently crashed after controller detach with a Mono thread/signal assertion. Read-only diagnostics found IL2CPP owned its suspend/restart signal handlers before late Mono initialization. The new companion initializes Mono before launching Unity and records signal ownership; this candidate has only built and passed syntax checks so far. Its Android lifecycle and post-detach checks have NOT run. Earlier short-lived health results do not establish stability.
