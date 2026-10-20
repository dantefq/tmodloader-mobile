"""Bounded, root-requested IPC hold between completed analysis processes."""
import datetime,hashlib,json,os,pathlib,re,time
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
def wait_if_requested(stage):
    request=LAB/'analysis-checkpoint-hold-20261016.json'
    if not request.exists():return
    r=json.loads(request.read_text(encoding='utf-8-sig'))
    if r.get('stage')!=stage or r.get('expected_parent_pid')!=os.getppid():return
    token=r['token'];assert re.fullmatch('[a-f0-9]{32}',token)
    if time.time()>r['expires_unix']:return
    release=LAB/('analysis-checkpoint-release-'+token+'.json')
    if release.exists():return
    event=LAB/('analysis-checkpoint-event-'+token+'.json')
    state={'token':token,'stage':stage,'process_id':os.getpid(),'parent_pid':os.getppid(),'status':'checkpoint_hold_ready','ready_UTC':datetime.datetime.now(datetime.timezone.utc).isoformat(),'max_wait_seconds':180,'gate_source_sha256':hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()}
    event.write_text(json.dumps(state,indent=2)+'\n')
    deadline=min(time.time()+180,r['expires_unix'])
    while time.time()<deadline:
        if release.exists():
            signal=json.loads(release.read_text(encoding='utf-8-sig'))
            assert signal['token']==token and signal['release'] is True
            state['status']='checkpoint_hold_released';break
        time.sleep(1)
    else:state['status']='checkpoint_hold_expired'
    event.write_text(json.dumps(state,indent=2)+'\n')
