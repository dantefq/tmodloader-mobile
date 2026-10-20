"""Compile and execute the managed API on the host; never invokes ADB or Terraria.

Requires .NET SDK 8.0.425. Builds outside the checkout, without NuGet packages.
The demos are compiled against our shim here, not the unavailable PC game DLL.
"""
import argparse
import json
from pathlib import Path
import subprocess
import shutil
from managed_api_sources import API_SOURCES, HOST_SUPPORT_SOURCES

ROOT = Path(__file__).resolve().parents[1]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dotnet', type=Path, required=True, help='SDK installation directory')
    p.add_argument('--lab', type=Path, required=True)
    p.add_argument('--upstream-stats', type=Path, help='Verified reference folder produced by fetch_stats_reference.py')
    p.add_argument('--upstream-combat', type=Path, help='Verified public combat sources from fetch_combat_reference.py')
    p.add_argument('--upstream-loader', type=Path, help='Verified public Info/dependency sources from fetch_loader_reference.py')
    args = p.parse_args()
    lab = args.lab.resolve() / 'managed-api-tests'
    if lab.is_relative_to(ROOT):
        raise ValueError('Keep binaries outside the source checkout')
    lab.mkdir(parents=True, exist_ok=True)
    dotnet = args.dotnet / ('dotnet.exe' if (args.dotnet/'dotnet.exe').exists() else 'dotnet')
    csc = args.dotnet / 'sdk/8.0.425/Roslyn/bincore/csc.dll'
    refs = sorted((args.dotnet/'packs/Microsoft.NETCore.App.Ref/8.0.31/ref/net8.0').glob('*.dll'))
    if not csc.is_file() or not refs:
        raise ValueError('Pinned .NET 8.0.425 / reference assemblies 8.0.31 required')

    def run(command):
        subprocess.run(list(map(str, command)), check=True, timeout=120)

    def compile(folder, name, sources, extra=(), exe=False, aliases=None):
        output = folder / name
        response = folder / (name + '.rsp')
        lines = ['-nologo', '-nostdlib+', '-deterministic+', '-debug:portable', '-langversion:12',
                 '-target:' + ('exe' if exe else 'library'), f'-out:"{output}"']
        lines += [f'-r:"{ref}"' for ref in [*refs, *extra]]
        lines += [f'-r:{alias}="{path}"' for alias, path in (aliases or {}).items()]
        lines += [f'"{ROOT/source}"' for source in sources]
        response.write_text('\n'.join(lines), encoding='utf-8')
        run([dotnet, csc, '@' + str(response)])
        return output

    shim = compile(lab, 'tModLoader.dll', API_SOURCES)
    metadata_runner = compile(lab, 'ApiMetadataReflection.dll', ['managed/tests/ApiMetadataReflection.cs'], [shim], True)
    metadata_runner.with_suffix('.runtimeconfig.json').write_text(json.dumps({'runtimeOptions': {
        'tfm': 'net8.0', 'framework': {'name': 'Microsoft.NETCore.App', 'version': '8.0.31'}}}), encoding='utf-8')
    reflected = json.loads(subprocess.check_output([str(dotnet), str(metadata_runner)], text=True, timeout=120))
    from inspect_mod_api import metadata
    parsed = metadata(shim.read_bytes(), include_definitions=True)
    for key in ('defined_type_names', 'defined_member_names'):
        expected = set(reflected[key])
        actual = set(parsed[key]) - ({'<Module>'} if key == 'defined_type_names' else set())
        if actual != expected:
            raise ValueError('Metadata/reflection mismatch: ' + key + '; missing=' + repr(sorted(expected - actual))
                             + '; extra=' + repr(sorted(actual - expected)))
    print('PASS complete API type/member metadata inventory against own CLR reflection; nested names included')
    tests = compile(lab, 'TerrariaMobile.ManagedDemo.dll',
                    [*HOST_SUPPORT_SOURCES,
                     'managed/tests/RegistryTests.cs', 'managed/tests/TextureBridgeChecks.cs', 'managed/tests/PersistenceTests.cs',
                     'managed/tests/StatModifierTests.cs', 'managed/tests/ArchiveTests.cs', 'managed/tests/RegistryImageTests.cs', 'managed/tests/TexturePacketTests.cs', 'managed/tests/DamageClassTests.cs', 'managed/tests/NpcHitTests.cs', 'managed/tests/ModLoadTests.cs', 'managed/tests/TimeLifecycleTests.cs'], [shim], True)
    config = {'runtimeOptions': {'tfm': 'net8.0', 'framework': {'name': 'Microsoft.NETCore.App', 'version': '8.0.31'}}}
    tests.with_suffix('.runtimeconfig.json').write_text(json.dumps(config), encoding='utf-8')
    run([dotnet, tests])
    image_tests = compile(lab, 'RawImageTests.dll', ['managed/tests/RawImageTests.cs'], [shim], True)
    image_tests.with_suffix('.runtimeconfig.json').write_text(json.dumps(config), encoding='utf-8')
    run([dotnet, image_tests])
    from test_mod_plan_cli import run_checks
    run_checks(args.dotnet, args.lab)
    if args.upstream_stats:
        from fetch_stats_reference import verify
        verify(args.upstream_stats)
        sources = [str((args.upstream_stats / name).resolve()) for name in
                   ('StatModifier.cs', 'StatInheritanceData.cs', 'MultipliableFloat.cs', 'AddableFloat.cs')]
        reference = compile(lab, 'ReferenceStats.dll', sources)
        conformance = compile(lab, 'StatsConformance.dll', ['managed/tests/StatsConformance.cs'], [shim], True,
                              {'ReferenceStats': reference})
        conformance.with_suffix('.runtimeconfig.json').write_text(json.dumps(config), encoding='utf-8')
        run([dotnet, conformance])
    else:
        print('Upstream arithmetic conformance not run: supply --upstream-stats after fetching verified references')
    if args.upstream_combat:
        from fetch_combat_reference import verify, prepare_player
        verify(args.upstream_combat)
        combat = lab / 'combat'; combat.mkdir(exist_ok=True)
        player_source = combat / 'ReferencePlayerStats.cs'
        prepare_player(args.upstream_combat, player_source)
        reference_sources = [str((args.upstream_combat / name).resolve()) for name in
                             ('StatModifier.cs', 'StatInheritanceData.cs', 'MultipliableFloat.cs', 'AddableFloat.cs',
                              'DamageClass.cs', 'DamageClassLoader.cs', 'VanillaDamageClasses.cs', 'NPC.TML.Hit.cs')]
        reference = compile(combat, 'ReferenceCombat.dll',
                            [*reference_sources, str(player_source), 'managed/tests/CombatReferenceScaffolding.cs'])
        conformance = compile(combat, 'TerrariaMobile.ManagedDemo.dll',
                              [*HOST_SUPPORT_SOURCES, 'managed/tests/CombatConformance.cs', 'managed/tests/NpcHitConformance.cs'], [shim], True,
                              {'ReferenceCombat': reference})
        shutil.copyfile(shim, combat / shim.name)
        conformance.with_suffix('.runtimeconfig.json').write_text(json.dumps(config), encoding='utf-8')
        run([dotnet, conformance])
    else:
        print('Upstream combat conformance not run: supply --upstream-combat after fetching verified references')
    if args.upstream_loader:
        from fetch_loader_reference import verify, prepare_validators
        verify(args.upstream_loader)
        loader = lab / 'loader'; loader.mkdir(exist_ok=True)
        validators = loader / 'ReferenceDependencyValidators.cs'
        prepare_validators(args.upstream_loader, validators)
        reference = compile(loader, 'ReferenceLoader.dll',
                            [str((args.upstream_loader / name).resolve()) for name in ('BuildProperties.cs', 'ModSide.cs')]
                            + [str(validators), 'managed/tests/LoaderReferenceScaffolding.cs'])
        conformance = compile(loader, 'TerrariaMobile.ManagedDemo.dll',
                              [*HOST_SUPPORT_SOURCES, 'managed/tests/LoaderConformance.cs'], [shim], True,
                              {'ReferenceLoader': reference})
        shutil.copyfile(shim, loader / shim.name)
        conformance.with_suffix('.runtimeconfig.json').write_text(json.dumps(config), encoding='utf-8')
        run([dotnet, conformance])
    else:
        print('Upstream Info/dependency conformance not run: supply --upstream-loader after fetching verified references')
    # Also compile both existing hosts and their exact bundled demo sources against the unified API.
    for mode, demo, host in [('global', 'PcGlobalItemDemo', 'ManagedGlobalItemHost'),
                             ('moditem', 'PcModItemDemo', 'ManagedModItemHost')]:
        folder = lab / mode; folder.mkdir(exist_ok=True)
        compile(folder, demo + '.dll', ['managed/pc-demo/' + demo + '.cs'], [shim])
        host_assembly = compile(folder, 'TerrariaMobile.ManagedDemo.dll',
                ['managed/unified-host/' + host + '.cs', *HOST_SUPPORT_SOURCES], [shim])
        shutil.copyfile(shim, folder / shim.name)
        cases = [(3507, 5, 24), (1, 5, 5), (3507, 7, 26)] if mode == 'global' else [(6196, 5, 37), (3507, 5, 5), (6196, 7, 37)]
        name_id, expected_name = (3507, 'PC API Test Sword') if mode == 'global' else (6196, 'PC ModItem Test Blade')
        source = folder / 'DemoChecks.cs'
        statements = [f'if (ManagedSwordDemo.GetDamage({t}, {d}) != {expected}) throw new Exception("Damage regression");'
                      for t, d, expected in cases]
        statements += [f'if (ManagedSwordDemo.GetName({name_id}) != "{expected_name}") throw new Exception("Name regression");',
                       'if (ManagedSwordDemo.GetHandlerCount() != 1) throw new Exception("Handler regression");',
                       'if (ManagedSwordDemo.StressGc() != 16777216) throw new Exception("GC regression");',
                       f'Console.WriteLine("PASS {mode}: 6 existing demo contract checks on host CLR");']
        source.write_text('using System; using TerrariaMobile.Managed; class DemoChecks { static void Main() { '
                          + '\n'.join(statements) + ' } }', encoding='utf-8')
        runner = compile(folder, 'DemoChecks.dll', [str(source)], [host_assembly], True)
        runner.with_suffix('.runtimeconfig.json').write_text(json.dumps(config), encoding='utf-8')
        run([dotnet, runner])
    print('Both demo/host variants compiled against unified item API')


if __name__ == '__main__':
    main()
