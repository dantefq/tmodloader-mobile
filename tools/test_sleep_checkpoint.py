"""Reject incomplete or inconsistent real-clock checkpoint evidence."""
import copy
import json
import unittest
from verify_sleep_checkpoint import validate


def fixture():
    ready=['TIME_HOST_READY originalChangeSleepTime=true cases=10',
           'TIME_HOOK_READY originalDLL=true normalOfflineTestWorldOnly=true clockAndTilesOnly=true']
    phases=((True,10,0,1),(True,10,1,10),(True,5,1,5),(False,10,1,5),(True,10,1,10),(True,10,0,1))
    def measurements(phase_list):
        result=[]
        for enabled,multiplier,sleeping,rate in phase_list:
            result.append('TIME_BRIDGE '+json.dumps(dict(enabled=enabled,multiplier=multiplier,active=1,sleeping=sleeping,after=[rate,rate],classicOnly=True,eventRateApplied=False)))
            result.extend(['TIME_ADVANCE '+json.dumps(dict(enabled=enabled,multiplier=multiplier,active=1,sleeping=sleeping,dayRate=rate,frames=180,delta=180*rate,expected=180*rate,wallMs=2990))]*2)
        return result
    initial=ready+['SLEEP_SCENE_BUILT {}']+measurements(phases)
    protection=['LAB_PROTECTION_READY offlineClassicTestProfilesOnly=true',
                'LAB_PROTECTION_CONFIG enabled=true',
                'SLEEP_SCENE_ACTION {"action":"use-bed","vanillaSleepAPI":true}']
    states=['LAB_PROTECTION_STATE '+json.dumps(dict(profile='TMAL_Sleep',god=True,noKnockback=True,life=100,dead=False))]*2
    second=ready+protection+measurements(phases[:2])+states+['LAB_PROTECTION_CONFIG enabled=false','LAB_PROTECTION_RELEASED','LAB_PROTECTION_CONFIG enabled=true']
    third=ready+protection+measurements(phases[:2])+states
    return [[dict(time=f'10-10 22:{minute:02}:{i:02}.000',pid=pid,message=m) for i,m in enumerate(messages)]
            for minute,pid,messages in ((10,100,initial),(20,200,second),(30,300,third))]


class SleepCheckpointTests(unittest.TestCase):
    def test_complete(self):
        self.assertEqual(validate(*fixture())['same_companion_sessions'][1]['pid'],300)

    def test_measured_clock_must_match(self):
        data=fixture()
        row=next(r for r in data[0] if r['message'].startswith('TIME_ADVANCE '))
        m=json.loads(row['message'].split(' ',1)[1]);m['delta']+=1
        row['message']='TIME_ADVANCE '+json.dumps(m)
        with self.assertRaisesRegex(ValueError,'Actual clock'):validate(*data)

    def test_off_is_required(self):
        data=fixture();data[0]=[r for r in data[0] if '"enabled": false' not in r['message']]
        with self.assertRaises(ValueError):validate(*data)

    def test_mixed_config_window_excluded_without_counting_it(self):
        data=fixture()
        bad=copy.deepcopy(next(r for r in data[0] if r['message'].startswith('TIME_ADVANCE ')))
        m=json.loads(bad['message'].split(' ',1)[1]);m['delta']-=1
        bad['message']='TIME_ADVANCE '+json.dumps(m)
        config=dict(time='10-10 22:10:03.500',pid=100,message='TIME_CONFIG enabled=false multiplier=10')
        data[0][4:4]=[config,bad]
        report=validate(*data)
        self.assertEqual(len(report['excluded_historical_mixed_config_windows']),1)
        self.assertTrue(all(s['delta']==s['expected'] for p in report['initial_phases'] for s in p['samples']))

    def test_same_config_does_not_excuse_wrong_clock(self):
        data=fixture()
        bad=next(r for r in data[0] if r['message'].startswith('TIME_ADVANCE '))
        m=json.loads(bad['message'].split(' ',1)[1]);m['delta']-=1
        bad['message']='TIME_ADVANCE '+json.dumps(m)
        data[0].insert(4,dict(time='10-10 22:10:03.500',pid=100,message='TIME_CONFIG enabled=true multiplier=10'))
        with self.assertRaisesRegex(ValueError,'Actual clock'):
            validate(*data)

    def test_new_pid_required(self):
        data=fixture()
        for r in data[2]:r['pid']=200
        with self.assertRaisesRegex(ValueError,'full restart'):validate(*data)

    def test_sleep_counter_required(self):
        data=fixture()
        for r in data[2]:r['message']=r['message'].replace('"sleeping": 1','"sleeping": 0')
        with self.assertRaises(ValueError):validate(*data)

    def test_knockback_protection_required(self):
        data=copy.deepcopy(fixture())
        for r in data[1]:r['message']=r['message'].replace('"noKnockback": true','"noKnockback": false')
        with self.assertRaisesRegex(ValueError,'Protection state'):validate(*data)


if __name__=='__main__':unittest.main()
