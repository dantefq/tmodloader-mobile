'use strict';

// Export-only IL2CPP bridge. No DRM, anti-cheat, or signature-check patches.
const REGISTRY = '/data/user/0/com.and.games505.TerrariaPaid/files/tmloader/mods.json';
let rules = new Map();
let lastRegistry = null;
let hook = null;
let applications = 0;
let failures = 0;
let attempts = 0;
let managedReady = false;
let managedEnabled = false;
let managedFailed = false;
let managedApplications = 0;
let managedMode = 'own-csharp';
const MANAGED_ROOT = '/data/user/0/com.and.games505.TerrariaPaid/files/tmloader/managed';

function readManaged() {
    try {
        const raw=File.readAllText(MANAGED_ROOT+'/../managed-enabled.json');
        if (raw.length>1024) throw Error('Managed flag too large');
        const config=JSON.parse(raw);
        if (typeof config.enabled!=='boolean') throw Error('Invalid managed flag');
        if (config.enabled && !managedReady && !managedFailed) {
            TMALManaged.initialize(MANAGED_ROOT);
            const contract=TMALManaged.contract(MANAGED_ROOT);
            managedMode=contract.mode;
            for (const [id,input,expected] of contract.checks)
                if (TMALManaged.damage(id,input)!==expected) throw Error('C# self-check failed');
            if (TMALManaged.name(contract.name_test_id||3507)!==contract.name || TMALManaged.handlers()!==contract.handler_count) throw Error('C# handler/name self-check failed');
            if (TMALManaged.stress()!==16777216) throw Error('Managed GC self-check failed');
            if(contract.api_revision!==undefined) {
                if(contract.api_revision!=='managed-foundation-v1'||contract.foundation_check_count!==8||TMALManaged.foundationChecks()!==8)
                    throw Error('Unified API foundation self-check failed');
                log('UNIFIED_API_READY managed-foundation-v1; 8 archive/registry/serialization/combat snapshot checks passed');
            }
            managedReady=true;
            log('MANAGED_READY own C# DLL, Mono 8.0.31, numeric/string/foreign-thread GC checks passed');
            if (contract.mode==='global-item') log('TML_API_READY own PC-compiled .tmod; GlobalItem.SetDefaults handlers='+contract.handler_count);
        }
        const next=config.enabled && managedReady && !managedFailed;
        if (next!==managedEnabled) log('Managed demo enabled='+next);
        managedEnabled=next;
    } catch(error) {
        managedEnabled=false;
        if (Process.findModuleByName('libmonosgen-2.0.so')!==null && !managedFailed) {
            managedFailed=true;log('MANAGED_FAILED '+error.stack);
        }
    }
}

let androidLog = null;
function log(message) {
    console.log('[TMAL] ' + message);
    try {
        if (androidLog === null)
            androidLog = new NativeFunction(Process.getModuleByName('liblog.so').getExportByName('__android_log_write'),
                'int', ['int', 'pointer', 'pointer']);
        androidLog(4, Memory.allocUtf8String('TMAL'), Memory.allocUtf8String(message));
    } catch (_) { /* Console remains available when Android log is not ready. */ }
}

function readRules() {
    try {
        const raw = File.readAllText(REGISTRY);
        if (raw === lastRegistry) return;
        const list = JSON.parse(raw);
        if (!Array.isArray(list) || list.length > 16 || raw.length > 65536) throw Error('Invalid registry');
        const next = new Map();
        for (const mod of list) {
            if (mod.format !== 'terraria-mobile-json-v1' || typeof mod.enabled !== 'boolean' ||
                typeof mod.id !== 'string' || !/^[a-z0-9-]{1,48}$/.test(mod.id) ||
                !Array.isArray(mod.items) || mod.items.length < 1 || mod.items.length > 32)
                throw Error('Invalid mobile mod');
            for (const item of mod.items) {
                if (!Number.isInteger(item.type) || item.type < 1 || item.type > 6144 ||
                    !Number.isInteger(item.damage) || item.damage < 1 || item.damage > 100 ||
                    typeof item.name !== 'string' || item.name.length < 1 || item.name.length > 48)
                    throw Error('Invalid item override');
                if (mod.enabled) next.set(item.type, { ...item, mod: mod.id });
            }
        }
        rules = next;
        lastRegistry = raw;
        log('Registry loaded: ' + rules.size + ' item override(s); later enabled mod wins conflicts');
    } catch (error) {
        rules = new Map(); // Fail closed, never keep stale enabled rules after bad input.
        lastRegistry = null;
        if (failures++ < 3) log('Registry disabled: ' + error.message);
    }
}

function install() {
    if (globalThis.TMALContentDelayUntil && Date.now()<globalThis.TMALContentDelayUntil) return false;
    if (Process.arch !== 'arm64') throw Error('Expected Android ARM64');
    const lib = Process.findModuleByName('libil2cpp.so');
    if (lib === null) return false;
    function api(name, result, args) {
        return new NativeFunction(lib.getExportByName('il2cpp_' + name), result, args);
    }
    const domainGet = api('domain_get', 'pointer', []);
    const domain = domainGet();
    if (domain.isNull()) return false;
    if (api('get_corlib','pointer',[])().isNull()) return false;
    const attach = api('thread_attach', 'pointer', ['pointer']);
    const detach = api('thread_detach', 'void', ['pointer']);
    const thread = attach(domain);
    if (thread.isNull()) throw Error('Could not attach IL2CPP thread');
    try {
        const assemblies = api('domain_get_assemblies', 'pointer', ['pointer', 'pointer']);
        const imageGet = api('assembly_get_image', 'pointer', ['pointer']);
        const imageName = api('image_get_name', 'pointer', ['pointer']);
        const klassGet = api('class_from_name', 'pointer', ['pointer', 'pointer', 'pointer']);
        const methodGet = api('class_get_method_from_name', 'pointer', ['pointer', 'pointer', 'int']);
        const fieldGet = api('class_get_field_from_name', 'pointer', ['pointer', 'pointer']);
        const fieldOffset = api('field_get_offset', 'size_t', ['pointer']);
        const fieldType = api('field_get_type', 'pointer', ['pointer']);
        const typeCode = api('type_get_type', 'int', ['pointer']);
        const fieldFlags = api('field_get_flags', 'int', ['pointer']);
        const staticGet = api('field_static_get_value', 'void', ['pointer', 'pointer']);
        const invoke = api('runtime_invoke', 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
        const stringNew = api('string_new', 'pointer', ['pointer']);
        const gcNew = api('gchandle_new', 'uint', ['pointer', 'uchar']);
        const gcFree = api('gchandle_free', 'void', ['uint']);
        const count = Memory.alloc(Process.pointerSize);
        count.writeU64(0);
        const array = assemblies(domain, count);
        const n = count.readU64().toNumber();
        if (array.isNull() || n === 0) return false;
        if (n > 2048) throw Error('Unexpected assembly count');
        let image = ptr(0);
        for (let i = 0; i < n; i++) {
            const candidate = imageGet(array.add(i * Process.pointerSize).readPointer());
            if (imageName(candidate).readUtf8String() === 'Assembly-CSharp.dll') { image = candidate; break; }
        }
        if (image.isNull()) return false;
        const cstr = value => Memory.allocUtf8String(value);
        const itemClass = klassGet(image, cstr('Terraria'), cstr('Item'));
        const mainClass = klassGet(image, cstr('Terraria'), cstr('Main'));
        if (itemClass.isNull() || mainClass.isNull()) throw Error('Terraria classes missing');
        function intField(klass, name, isStatic) {
            const field = fieldGet(klass, cstr(name));
            if (field.isNull() || typeCode(fieldType(field)) !== 8 ||
                Boolean(fieldFlags(field) & 0x10) !== isStatic) throw Error('Unexpected field: ' + name);
            return field;
        }
        const typeOffset = Number(fieldOffset(intField(itemClass, 'type', false)));
        const damageOffset = Number(fieldOffset(intField(itemClass, 'damage', false)));
        if (typeOffset < 16 || damageOffset < 16 || typeOffset > 8192 || damageOffset > 8192)
            throw Error('Invalid Item field offsets');
        const netMode = intField(mainClass, 'netMode', true);
        const setDefaults = methodGet(itemClass, cstr('SetDefaults'), 2);
        const setName = methodGet(itemClass, cstr('SetNameOverride'), 1);
        if (setDefaults.isNull() || setName.isNull()) throw Error('Required Item method missing');
        const entry = setDefaults.readPointer(); // MethodInfo.methodPointer, ARM64.
        const executable = Process.findRangeByAddress(entry);
        if (entry.isNull() || executable === null || !executable.protection.includes('x'))
            throw Error('Method entry is not executable');
        hook = Interceptor.attach(entry, {
            onEnter(args) { this.item = args[0]; },
            onLeave() {
                if ((rules.size === 0 && !managedEnabled) || this.item.isNull()) return;
                let handle = null;
                try {
                    const mode = Memory.alloc(4);
                    staticGet(netMode, mode);
                    if (mode.readS32() !== 0) return;
                    const type=this.item.add(typeOffset).readS32();
                    let rule = rules.get(type);
                    if (managedEnabled && managedMode!=='mod-item' && type===3507) {
                        const vanilla=this.item.add(damageOffset).readS32();
                        const damage=TMALManaged.damage(type,vanilla);
                        const name=TMALManaged.name(type);
                        if (!Number.isInteger(damage)||damage<1||damage>100||name.length<1||name.length>48) throw Error('Invalid C# item result');
                        rule={type,damage,name,mod:'own-csharp-demo'};
                        if (++managedApplications<=5) log('Managed SetDefaults result: vanilla='+vanilla+', damage='+damage+', name='+name);
                    }
                    if (rule === undefined) return;
                    const text = stringNew(cstr(rule.name));
                    handle = gcNew(text, 0);
                    const args = Memory.alloc(Process.pointerSize);
                    args.writePointer(text);
                    const exception = Memory.alloc(Process.pointerSize);
                    exception.writePointer(ptr(0));
                    invoke(setName, this.item, args, exception);
                    if (!exception.readPointer().isNull()) throw Error('SetNameOverride threw managed exception');
                    this.item.add(damageOffset).writeS32(rule.damage);
                    applications++;
                    if (applications <= 5) log('Applied ' + rule.mod + ': type=' + rule.type + ', damage=' + rule.damage);
                } catch (error) {
                    if (failures++ < 3) log('Override failed: ' + (error.stack || error.message));
                    if (failures >= 3) { rules.clear(); managedEnabled=false; managedFailed=true; log('Overrides disabled after repeated errors'); }
                } finally { if (handle !== null) gcFree(handle); }
            }
        });
        log('HOOK_READY Terraria.Item.SetDefaults(Type, variant); type@' + typeOffset + ', damage@' + damageOffset);
        return true;
    } finally { detach(thread); }
}

log('Mobile loader starting; arbitrary PC .tmod import unsupported');
readRules();
readManaged();
const registryTimer = setInterval(()=>{readRules();readManaged();}, 2000);
const startupTimer = setInterval(() => {
    try {
        if (install()) { clearInterval(startupTimer); return; }
        if (++attempts >= 120) { clearInterval(startupTimer); log('HOOK_FAILED: IL2CPP not ready after 120 seconds'); }
    } catch (error) {
        clearInterval(startupTimer);
        log('HOOK_FAILED: ' + error.message);
    }
}, 1000);

rpc.exports = {
    status() { return { hookReady: hook !== null, itemRules: rules.size, applications, failures, managedReady, managedEnabled, managedApplications }; },
    dispose() {
        clearInterval(startupTimer); clearInterval(registryTimer);
        rules.clear(); if (hook !== null) { hook.detach(); hook = null; }
    }
};
