"""One explicit source manifest for the common shim and both demo hosts.

Historical Minimal* adapters must not be included in these assemblies.
"""
API_SOURCES = (
    'managed/compat/MobileItemApi.cs',
    'managed/compat/MobileItemEconomy.cs',
    'managed/compat/MobileRawImage.cs',
    'managed/compat/MobileRawImageCache.cs',
    'managed/compat/MobileTexturePacket.cs',
    'managed/compat/MobileTimeApi.cs',
    'managed/compat/MobileTagCodec.cs',
    'managed/compat/StatModifier.cs',
    'managed/compat/CombatStats.cs',
    'managed/compat/DamageClasses.cs',
    'managed/compat/PlayerCombat.cs',
    'managed/compat/NpcHit.cs',
    'managed/compat/MobileTmodArchive.cs',
    'managed/compat/ModManifest.cs',
)
HOST_SUPPORT_SOURCES = (
    'managed/api-host/MobileContentRegistry.cs',
    'managed/api-host/MobileItemTextureBinding.cs',
    'managed/api-host/MobileTextureTransfer.cs',
    'managed/api-host/MobileTextureBridge.cs',
    'managed/api-host/MobileModLoadPlan.cs',
    'managed/api-host/MobileSidecarStore.cs',
)
