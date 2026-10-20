# Texture transport v1

[Русский](TEXTURE_TRANSPORT.ru.md)

`MobileContentRegistry.PrepareItemTexture(id)` resolves a registered item's rawimg resource, uses the CPU cache and produces `MobileTexturePacket`. Every registry instance has a fresh `ContentGeneration`. A receiver supplies the expected canonical asset key, generation and archive SHA-256; values from an earlier registry generation are rejected.

The packet contains: `TMIT` magic, version byte 1, Int32 key byte count and UTF-8 key, 16 .NET GUID bytes, 32 archive SHA-256 bytes, Int32 width/height/PNG byte count, 32 PNG SHA-256 bytes, then PNG bytes. Integer fields are little-endian; GUID bytes follow `Guid.ToByteArray()` (Python `UUID(bytes_le=...)`). Keys are at most 512 UTF-8 bytes. No paths, native pointers or GPU handles are transported.

The reader checks identities, lengths, dimensions and separate compressed/pixel budgets before decoding. It checks the payload digest and the sender's PNG profile: RGBA8, no interlace, IHDR/one IDAT/IEND, chunk CRCs and zero-filter rows. Zlib output is consumed one bounded row at a time; truncated or excess pixel output is rejected. This profile intentionally does not accept arbitrary third-party PNG layouts. Before encoding, the sender rejects images whose conservative output-size estimate exceeds its ceiling; this is not a total process-memory limit.

Checksums and matching labels detect corruption and mismatched load-plan values; they do not authenticate an untrusted sender or prove the PNG originated from a particular archive. Packet validation does not authorize native execution. A production backend must still enforce its active generation, main thread, object/GC lifetime, Unity decode result and dimensions, installation and rollback. The separate [native diagnostic](DEVICE_TEXTURE_PROBE.md) has verified temporary Unity loading and mobile XNA wrapping; a menu preview was visually reviewed, while game-content installation and registered-item inventory rendering remain unverified.

The bounded JavaScript receiver additionally requires a known PNG digest from the host-validated plan. It checks TMIT framing/identities and PNG SHA256/header/chunk profile/CRCs, without inflating rows. Original host packets have passed this receiver, standalone Asset creation and a private typed-array lease across two Draw calls on Android. The reusable lease retains ownership on unresolved rollback; the bounded item-icon scope now exercises table publication and host unload ordering. General companion integration remains pending. Source checks cover 24 receiver and 12 lease cases.

Host tests cover 24 packet cases and 57 registry image/lifecycle cases, including stale generations, mismatched identities, invalid UTF-8, truncation, CRC corruption and excess decompressed pixels. The original three SOTS textures are also transported and checked by C# plus an independent Python wire reader. Those probe generations and item IDs are synthetic; no game content IDs are registered.

Run the host suite with `python tools/test_managed_api.py --dotnet '<SDK root>' --lab '<private-lab>'`. Original item probes are described in [SOTS host slice](SOTS_HOST_SLICE.md). Original textures and generated packets stay in the private lab.

`PrepareItemTextureBinding` and `BeginTextureTransfer` add a serialized host ownership/unload contract. The transfer plan includes an acknowledgement ID alongside item/resource/generation identities; it is separate from TMIT pixel data. See [item texture binding](ITEM_TEXTURE_BINDING.md) for the checked native table scope, two-cycle result and remaining integration work.

The [Android texture bridge](ANDROID_TEXTURE_BRIDGE.md) adds bounded envelopes and strict Base64. The own Android registry passed separate-process and in-process texture-companion laboratories with real cleanup ACK; common item/time integration and inventory remain pending.
