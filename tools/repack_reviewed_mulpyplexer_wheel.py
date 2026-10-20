"""Repack an exact reviewed pure-Python module; never execute its setup.py."""
import base64,csv,hashlib,io,json,pathlib,tarfile,zipfile
LAB=pathlib.Path('C:/Temp/terraria-re-20261012')
ARCHIVE_SHA='144e9e9bf66d3988f60542c9d3d4c94857438f7908f60e53f4c1cb1622fbbd30'
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    archive=LAB/'angr-reviewed-sources-20261016/mulpyplexer-0.09.tar.gz'
    assert sha(archive.read_bytes())==ARCHIVE_SHA
    prefix='mulpyplexer-0.09/'
    with tarfile.open(archive) as source:
        files={m.name:m for m in source.getmembers() if m.isfile()}
        assert set(files)=={prefix+n for n in ('LICENSE','PKG-INFO','mulpyplexer.py','setup.py')}
        assert all(m.isfile() or m.isdir() for m in source.getmembers())
        payload={n:source.extractfile(files[prefix+n]).read() for n in ('LICENSE','PKG-INFO','mulpyplexer.py')}
    dist='mulpyplexer-0.9.dist-info/'
    contents={'mulpyplexer.py':payload['mulpyplexer.py'],dist+'METADATA':payload['PKG-INFO'],dist+'LICENSE':payload['LICENSE'],dist+'WHEEL':b'Wheel-Version: 1.0\nGenerator: reviewed-pure-python-repack\nRoot-Is-Purelib: true\nTag: py3-none-any\n'}
    record=io.StringIO();writer=csv.writer(record,lineterminator='\n')
    for name,data in contents.items():writer.writerow([name,'sha256='+base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode().rstrip('='),len(data)])
    writer.writerow([dist+'RECORD','','']);contents[dist+'RECORD']=record.getvalue().encode()
    wheel=LAB/'angr-wheelhouse-20261016/mulpyplexer-0.9-py3-none-any.whl'
    assert not wheel.exists()
    with zipfile.ZipFile(wheel,'x',compression=zipfile.ZIP_DEFLATED) as target:
        for name,data in contents.items():
            info=zipfile.ZipInfo(name,date_time=(1980,1,1,0,0,0));info.compress_type=zipfile.ZIP_DEFLATED
            target.writestr(info,data)
    provenance={'archive_sha256':ARCHIVE_SHA,'local_wheel_sha256':sha(wheel.read_bytes()),'upstream_archive_version':'0.09','PEP440_normalized_version':'0.9','module_bytes_preserved':True,'setup_executed':False,'local_repack_not_upstream_wheel':True,'upstream_url':'https://files.pythonhosted.org/packages/d7/6f/f036d4fb9f5a511262345bb18215c70fa69a250aca2e5ffe1a9c7e4cb85c/mulpyplexer-0.09.tar.gz','own_tool_sha256':sha(pathlib.Path(__file__).read_bytes())}
    (wheel.parent/'mulpyplexer-local-repack.json').write_text(json.dumps(provenance,indent=2)+'\n')
    print(json.dumps(provenance))
if __name__=='__main__':main()
