"""Prepare a fresh disposable AVD configuration; never copy personal userdata."""
import argparse, json
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--lab',type=Path,default=Path('C:/Temp/terraria-re-20261012'));a=p.parse_args()
sdk=Path.home()/'AppData/Local/Android/Sdk'
image=sdk/'system-images/android-34/google_apis_playstore/x86_64'
assert (image/'system.img').is_file() and (image/'userdata.img').is_file()
home=a.lab/'runtime-avd';home.mkdir(exist_ok=True)
device=home/'TerrariaRE.avd'
if device.exists():raise SystemExit('Fresh destination required; existing runtime AVD preserved')
device.mkdir()
config={'AvdId':'TerrariaRE','avd.ini.displayname':'Terraria reverse engineering disposable lab',
 'avd.ini.encoding':'UTF-8','PlayStore.enabled':'true','abi.type':'x86_64','hw.cpu.arch':'x86_64',
 'hw.cpu.ncore':'2','hw.ramSize':'2048','hw.lcd.width':'720','hw.lcd.height':'1280','hw.lcd.density':'320',
 'hw.gpu.enabled':'yes','hw.gpu.mode':'swiftshader_indirect','hw.keyboard':'yes','hw.audioInput':'no',
 'hw.camera.back':'none','hw.camera.front':'none','hw.sdCard':'no','disk.dataPartition.size':'4G',
 'fastboot.forceColdBoot':'yes','fastboot.forceFastBoot':'no','showDeviceFrame':'no',
 'image.sysdir.1':str(image)+'\\','tag.id':'google_apis_playstore','tag.display':'Google Play'}
(device/'config.ini').write_text(''.join(f'{k}={v}\n' for k,v in config.items()),encoding='utf-8')
(home/'TerrariaRE.ini').write_text(f'avd.ini.encoding=UTF-8\npath={device.resolve()}\ntarget=android-34\n',encoding='utf-8')
record={'avd_home':str(home.resolve()),'device':str(device.resolve()),'sdk':str(sdk),
 'system_image':str(image),'personal_userdata_copied':False,'apk_installed':False,'target_executed':False,
 'reference':'https://developer.android.com/studio/run/emulator-commandline',
 'plan':'Boot headless without snapshots; enable airplane mode before installing supplied APK; capture ABI and package identity first.'}
(a.lab/'runtime-avd-preparation.json').write_text(json.dumps(record,indent=2)+'\n')
print(json.dumps(record,indent=2))
