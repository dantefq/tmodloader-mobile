"""Preserve reviewed disposable-AVD world/save/load evidence outside Git."""
import hashlib,json,pathlib,shutil,subprocess

LAB=pathlib.Path('C:/Temp/terraria-re-20261012/runtime-world-20261014')
DEST=pathlib.Path('C:/Private/Documents/ChatGPT/Terraria-Reverse-20261012/runtime-world-20261014')
REPO=pathlib.Path(__file__).resolve().parents[1]
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
    original=pathlib.Path('C:/Private/Downloads/Terraria-v1-4-5-8-6-patched.apk')
    adb=pathlib.Path.home()/'AppData/Local/Android/Sdk/platform-tools/adb.exe'
    devices=subprocess.run([str(adb),'devices'],capture_output=True,check=True).stdout
    assert b'emulator-5580' not in devices, 'Owned emulator still visible'
    (LAB/'shutdown-devices.txt').write_bytes(devices)
    saved=json.loads((LAB/'saved-files.json').read_text())['files']
    reloaded=json.loads((LAB/'reloaded-files.json').read_text())['files']
    assert saved==reloaded and len(saved)==5
    review={'character_creation_verified':True,'small_classic_world_creation_verified':True,'world_entry_verified':True,'save_exit_cold_restart_reentry_verified':True,'saved_file_hashes_unchanged_through_reload':True,'source_apk_sha256':sha(original),'emulator_absent_after_shutdown':True,
            'report_ru':'Созданы REPlayer20261014 (Classic) и REWorld20261014 (Small, Classic, Random evil). Генерация завершена, выполнен вход в игровой мир. После штатного Save & Exit появились обновлённые .plr/.wld, карта и резервные копии. Процесс приложения принудительно остановлен и запущен заново (COLD). Персонаж и мир выбраны повторно, игровой экран и сохранённая карта отрисованы. Хеши пяти файлов после сохранения и после загрузки совпали.',
            'limitations_ru':'Проверен один короткий одиночный сценарий. Полнота механик, бой, крафт, сеть и семантическая эквивалентность C-псевдокода не проверены. Обнаружено повторное предложение настройки управления при входе. Начальные before-files/generated-files снимки искали только подпапку files и потому не доказывают отсутствие сохранений во всём каталоге: фактические Players/Worlds находятся рядом с files. Пустые списки выбора наблюдались визуально. Короткий свайп выполнен; точная дистанция перемещения и сохранение изменения тайла не проверены.'}
    (LAB/'review.json').write_text(json.dumps(review,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    launch=json.loads((LAB/'launch.json').read_text(encoding='utf-8-sig'))
    commands=[json.loads(s) for s in (LAB/'commands.jsonl').read_text().splitlines()]
    assert launch['personal_avd_used'] is False and launch['screenshot_taps_user_authorized'] is True
    assert commands[-1]['args']==['emu','kill'] and commands[-1]['returncode']==0
    assert not (LAB/'prelaunch-routes.txt').read_bytes().strip()
    assert (LAB/'installed-apk-sha256.txt').read_text().strip()=='1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e'
    captures=[]
    for folder in sorted(p for p in LAB.iterdir() if p.is_dir()):
        doc=json.loads((folder/'capture.json').read_text())
        for name,digest in doc['files'].items():
            assert pathlib.Path(name).name==name and sha(folder/name)==digest
        captures.append({'label':folder.name,'sha256':sha(folder/'capture.json'),'crash_buffer_bytes':(folder/'crash.txt').stat().st_size})
    result={'profile':'disposable-offline-world-save-load-visual-QA-v1','visual_review':review,'captures':captures,'personal_avd_used':False,'screenshot_input_user_authorized':True,'shutdown_command_succeeded':True,'source_apk_unchanged':review['source_apk_sha256']=='1f8e2ba7ddabaee961a1b2552d44bc0c281c9b5122480642b018779bcbf2fe8e','limits':'Observed bounded flow only; no full gameplay coverage or native pseudocode equivalence proof.'}
    (LAB/'summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
    (LAB/'REPORT.ru.md').write_text('\n'.join(['# Создание мира и проверка сохранения Terraria','',review['report_ru'],'','Управление по снимкам явно разрешено пользователем. Использован только отдельный TerrariaRE AVD. Установленный APK сверён по SHA-256, сеть отключена. Исходный APK не изменён.','',review['limitations_ru'],'','[Итоги и ограничения](summary.json) · [Журнал команд](commands.jsonl) · [Файлы после сохранения](saved-files.json) · [Файлы после повторной загрузки](reloaded-files.json).','', '[Мир после повторной загрузки](reloaded-playable/screen.png) · [Сохранённый персонаж](restart-player/screen.png) · [Сохранённый мир](restart-world/screen.png).','', 'Снимки, UI-деревья и логи сохранены по этапам. Собственный эмулятор остановлен. Образы Android и userdata AVD в выдачу не копируются.'])+'\n',encoding='utf8')
    DEST.mkdir(exist_ok=True)
    for p in LAB.iterdir():
        if p.is_dir():shutil.copytree(p,DEST/p.name,dirs_exist_ok=True)
        elif p.suffix in ('.json','.jsonl','.txt','.md'):shutil.copy2(p,DEST/p.name)
    (DEST/'tools').mkdir(exist_ok=True)
    for name in ('terraria_gameplay_lab.py','package_terraria_world_qa.py'):shutil.copy2(REPO/'tools'/name,DEST/'tools'/name)
    rows=[{'path':p.relative_to(DEST).as_posix(),'bytes':p.stat().st_size,'sha256':sha(p)} for p in sorted(DEST.rglob('*')) if p.is_file() and p.name!='addendum-manifest.json']
    (DEST/'addendum-manifest.json').write_text(json.dumps({'files':rows,'file_count':len(rows)},indent=2)+'\n')
    for r in rows:assert sha(DEST/r['path'])==r['sha256']
    print(json.dumps({'report':str(DEST/'REPORT.ru.md'),'files':len(rows),'captures':len(captures)},ensure_ascii=False))
if __name__=='__main__':main()
