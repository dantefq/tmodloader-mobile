"""Preserve a bounded offline menu/input attempt; never package emulator userdata."""
import argparse, hashlib, json, pathlib, shutil, xml.etree.ElementTree as ET


def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()


def main():
    ap=argparse.ArgumentParser();ap.add_argument('--lab',type=pathlib.Path,required=True);ap.add_argument('--delivery',type=pathlib.Path,required=True);a=ap.parse_args()
    root=a.lab/'runtime-gameplay-20261014';dest=a.delivery/root.name;repo=pathlib.Path(__file__).resolve().parents[1]
    if dest.resolve().is_relative_to(repo):raise ValueError('Private destination required')
    if (root/'installed-apk-sha256.txt').read_text().strip()!='1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e':raise ValueError('APK mismatch')
    if (root/'prelaunch-routes.txt').read_bytes().strip():raise ValueError('Prelaunch network routes existed')
    commands=[json.loads(line) for line in (root/'commands.jsonl').read_text().splitlines()]
    if not commands or commands[-1]['args']!=['emu','kill']:raise ValueError('Emulator shutdown not recorded')
    if any('tap' in r['args'] or 'swipe' in r['args'] for r in commands):raise ValueError('Unexpected coordinate action')
    captures=[]
    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        metadata=json.loads((folder/'capture.json').read_text())
        for name,digest in metadata['files'].items():
            if pathlib.Path(name).name!=name or sha(folder/name)!=digest:raise ValueError('Capture changed')
        xml=(folder/'ui.xml').read_text();end=xml.index('</hierarchy>')+len('</hierarchy>');tree=ET.fromstring(xml[:end])
        clickable=[node for node in tree.iter('node') if node.get('clickable')=='true' and (node.get('text') or node.get('content-desc'))]
        captures.append({'label':folder.name,'named_clickable_nodes':len(clickable),'capture_sha256':sha(folder/'capture.json'),'crash_buffer_bytes':(folder/'crash.txt').stat().st_size})
    result={'profile':'offline-TerrariaRE-menu-keyboard-gamepad-input-attempt-v1','installed_apk_sha256':(root/'installed-apk-sha256.txt').read_text().strip(),
            'prelaunch_network_routes_empty':True,'captures':captures,'coordinate_actions_issued':False,'character_creation_verified':False,'world_creation_verified':False,'save_load_verified':False,
            'menu_rendered_visual_review':True,'observed_menu_version':'v1.4.5.8.1 Build 1720','synthetic_input_menu_advance_observed':False,'emulator_shutdown_command_succeeded':commands[-1]['returncode']==0,
            'blocking_boundary':'Android QA skill requires UI-tree-derived tap coordinates; Unity menu exposes no named clickable buttons. User exception for screenshot-based input remains pending.',
            'helper_current_after_run_sha256':sha(repo/'tools/terraria_gameplay_lab.py'),'package_tool_sha256':sha(pathlib.Path(__file__))}
    (root/'summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    text=['# Повторный запуск и попытка перехода к игровым сценариям','',
          'Неизменённый APK повторно запущен в отдельном TerrariaRE AVD. SHA установленного base.apk проверен; перед запуском включён авиарежим, Wi-Fi/data отключены, маршрутов не было. Главное меню отрисовано, виден v1.4.5.8.1 Build 1720.','',
          'Синтетические DPAD/Enter, Tab/DPAD Center и gamepad Button A не дали наблюдаемого перехода к следующему экрану. Это не доказывает отсутствие поддержки настоящей аппаратной клавиатуры/контроллера.','',
          'В Android UI-дереве нет именованных clickable-кнопок меню: видна поверхность Unity. Тапы и свайпы не выполнялись. Правило используемого [Android QA SKILL.md](C:/Private/.codex/plugins/cache/openai-curated-remote/test-android-apps/0.1.2/skills/android-emulator-qa/SKILL.md): «Always compute tap coordinates from the UI tree, not screenshots». Исключение для управления по снимкам запрошено у пользователя и не получено.','',
          '**Создание персонажа/мира, игра, сохранение и загрузка этим проходом не проверены.** После итогового сбора приложение и собственный эмулятор остановлены; личный AVD не использовался.','',
          '[Главное меню](menu-03/screen.png) · [Последний снимок](final-menu/screen.png) · [Итоги и ограничения](summary.json) · [Журнал команд](commands.jsonl).','',
          'AVD userdata и образы Android в выдачу не копируются. Манифест подтверждает сохранённые файлы, а не семантику игры.']
    (root/'REPORT.ru.md').write_text('\n'.join(text)+'\n',encoding='utf8')
    dest.mkdir(exist_ok=True)
    for p in root.iterdir():
        if p.is_dir():shutil.copytree(p,dest/p.name,dirs_exist_ok=True)
        elif p.name in ('launch.json','installed-apk-sha256.txt','prelaunch-routes.txt','app-start.txt','commands.jsonl','summary.json','REPORT.ru.md'):shutil.copy2(p,dest/p.name)
    tools=dest/'tools';tools.mkdir(exist_ok=True)
    for name in ('terraria_gameplay_lab.py','package_terraria_runtime_attempt.py'):shutil.copy2(repo/'tools'/name,tools/name)
    rows=[{'path':p.relative_to(dest).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(dest.rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (dest/'addendum-manifest.json').write_text(json.dumps({'files':rows,'file_count':len(rows),'profile':result['profile']},indent=2)+'\n',encoding='utf8')
    for row in rows:
        if sha(dest/row['path'])!=row['sha256']:raise ValueError('Delivery file changed')
    print(json.dumps({'report':str(dest/'REPORT.ru.md'),'captures':len(captures),'files':len(rows),'gameplay_verified':False},ensure_ascii=False))


if __name__=='__main__':main()
