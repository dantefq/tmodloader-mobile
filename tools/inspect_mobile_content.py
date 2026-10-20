"""Read mobile IL2CPP metadata declarations; keep detailed output in a private lab."""
import argparse
import json
from pathlib import Path
import struct
import zipfile
from apk_format import METADATA_PATH, sha256

ROOT=Path(__file__).resolve().parents[1]
TARGETS={('Terraria','Item'),('Terraria','Main'),('Terraria','Lang'),('Terraria','Player'),
         ('Terraria.ID','ItemID'),('Terraria.GameContent','TextureAssets'),
         ('Terraria.IO','PlayerFileData'),('Terraria.IO','WorldFile'),('Terraria.IO','FileData'),
         ('Terraria.GameContent','ContentSamples'),('Terraria.ID','ContentSamples'),('Terraria.Localization','LocalizedText')}

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('apk',type=Path)
    p.add_argument('--output',type=Path,required=True)
    p.add_argument('--include-time',action='store_true',help='Include time/sleep declarations for the small-mod lab')
    p.add_argument('--include-sleep-scene',action='store_true',help='Include vanilla test-room/bed APIs for the backed-up sleep lab')
    args=p.parse_args()
    if args.output.resolve().is_relative_to(ROOT): raise ValueError('Keep metadata details outside source repository')
    with zipfile.ZipFile(args.apk) as archive: data=archive.read(METADATA_PATH)
    if struct.unpack_from('<II',data)!=(0xFAB11BAF,31): raise ValueError('Expected verified metadata31')
    def table(offset):
        start,size=struct.unpack_from('<II',data,offset)
        if start+size>len(data): raise ValueError('Table outside metadata')
        return start,size
    strings,string_size=table(24)
    def name(index):
        if index>=string_size: raise ValueError('String outside table')
        start=strings+index
        return data[start:data.index(b'\0',start,strings+string_size)].decode('utf-8')
    types,type_size=table(160);fields,field_size=table(96);methods,method_size=table(48);parameters,parameter_size=table(88)
    defaults,default_size=table(64);values,value_size=table(72)
    default_map={idx:(typ,value) for idx,typ,value in struct.iter_unpack('<iii',data[defaults:defaults+default_size])}
    result={}
    type_records=[struct.unpack_from('<16I8H2I',data,offset) for offset in range(types,types+type_size,88)]
    for offset in range(types,types+type_size,88):
        record=struct.unpack_from('<16I8H2I',data,offset)
        identity=(name(record[1]),name(record[0]))
        time_target=args.include_time and identity[1] in ('CurrentFrameFlags','CreativePowerManager','CreativePowers','ModifyTimeRate','FreezeTime','ASharedTogglePower','PlayerSleepingHelper')
        scene_target=args.include_sleep_scene and identity in {('Terraria','WorldGen'),('Terraria.ID','TileID'),('Terraria.ID','WallID'),('Terraria','Tile'),('Terraria','NPC'),('Microsoft.Xna.Framework','Vector2')}
        if identity not in TARGETS and identity[1]!='Sets' and not time_target and not scene_target: continue
        field_rows=[];method_rows=[]
        for i in range(record[8],record[8]+record[18]):
            f=struct.unpack_from('<III',data,fields+12*i);row={'name':name(f[0]),'type_index':f[1]}
            if i in default_map:
                _,value=default_map[i]
                if value>=0 and value<value_size-3: row['constant_first4_hex']=data[values+value:values+value+4].hex()
            field_rows.append(row)
        for i in range(record[9],record[9]+record[16]):
            m=struct.unpack_from('<7I4H',data,methods+36*i)
            params=[struct.unpack_from('<III',data,parameters+12*j) for j in range(m[4],m[4]+m[10])]
            method_rows.append({'name':name(m[0]),'parameters':[name(param[0]) for param in params],
                                'parameter_type_indices':[param[2] for param in params],
                                'return_type_index':m[2], 'flags':m[7],
                                'is_static':bool(m[7]&0x10)})
        # Nested Sets declarations use the parent type index to distinguish owners.
        parent=record[3]
        owner=None
        if parent!=0xffffffff and parent<len(type_records): owner=name(type_records[parent][0])
        key='.'.join(identity)+((' (in '+owner+')') if owner else '')
        if identity[1]=='Sets' and owner!='ItemID': continue
        result[key]={'fields':field_rows,'methods':method_rows}
    args.output.parent.mkdir(parents=True,exist_ok=True)
    args.output.write_text(json.dumps({'apk_sha256':sha256(args.apk),'classes':result},indent=2)+'\n',encoding='utf-8')
    for key,row in result.items():
        if 'ItemID' in key:
            selected=[f for f in row['fields'] if f['name']=='Count']
        else: selected=[f['name'] for f in row['fields'] if any(part in f['name'].lower() for part in ('item','texture','inventory','damage','type'))]
        print(key,json.dumps({'fields':selected[:100],'method_count':len(row['methods'])}))

if __name__=='__main__':main()
