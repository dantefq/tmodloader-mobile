"""Repack reviewed arpy 1.1.1 pure Python bytes without running setup.py."""
import base64,csv,hashlib,io,json,pathlib,tarfile,zipfile
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ARCHIVE_SHA='3ec36309d2234648ef8dcd2118fe7d81c30195087e0353473546583f3434e776'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    archive=LAB/'angr-reviewed-sources-20261016/arpy-1.1.1.tar.gz';assert sha(archive.read_bytes())==ARCHIVE_SHA
    with tarfile.open(archive) as source:
        assert all(m.isfile() or m.isdir() for m in source.getmembers())
        payload={n:source.extractfile('arpy-1.1.1/'+n).read() for n in ('arpy.py','PKG-INFO')}
    dist='arpy-1.1.1.dist-info/'
    contents={'arpy.py':payload['arpy.py'],dist+'METADATA':payload['PKG-INFO'],dist+'WHEEL':b'Wheel-Version: 1.0\nGenerator: reviewed-pure-python-repack\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
    record=io.StringIO();writer=csv.writer(record,lineterminator='\n')
    for name,data in contents.items():writer.writerow([name,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('='),len(data)])
    writer.writerow([dist+'RECORD','','']);contents[dist+'RECORD']=record.getvalue().encode()
    wheel=LAB/'angr-wheelhouse-20261016/arpy-1.1.1-py3-none-any.whl';assert not wheel.exists()
    with zipfile.ZipFile(wheel,'x',compression=zipfile.ZIP_DEFLATED) as target:
        for name,data in contents.items():
            info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED;target.writestr(info,data)
    provenance={'archive_sha256':ARCHIVE_SHA,'local_wheel_sha256':sha(wheel.read_bytes()),'module_bytes_preserved':True,'embedded_license_preserved':True,'setup_executed':False,'local_repack_not_upstream_wheel':True,'own_tool_sha256':sha(pathlib.Path(__file__).read_bytes())}
    (wheel.parent/'arpy-local-repack.json').write_text(json.dumps(provenance,indent=2)+'\n');print(json.dumps(provenance))
if __name__=='__main__':main()
