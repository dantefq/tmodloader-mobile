"""Check the Git index or a source ZIP for private evidence and sensitive artifacts."""
import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ALLOWED_REPORT = 'reports/public-validation-summary.json'
FORBIDDEN_SUFFIXES = {'.apk', '.dll', '.so', '.dex', '.class', '.tmod', '.plr', '.wld',
                      '.pk8', '.pem', '.jks', '.keystore', '.p12', '.env'}
PATTERNS = [
    re.compile(r"\b[A-Z][0-9]{2}[A-Z0-9]{8}\b"),
    re.compile(r'(?i)[A-Z]:[\\/]+Users[\\/]+(?!Public(?:[\\/]|$))[^\\/\s"\']+[\\/]'),
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}|AKIA[A-Z0-9]{16})\b'),
]


def validate(name, data):
    path = PurePosixPath(name)
    if path.is_absolute() or '..' in path.parts or path.suffix.lower() in FORBIDDEN_SUFFIXES:
        raise ValueError('Forbidden publication artifact: ' + name)
    if path.parts[0] in ('notes', '.tools', 'private-build') or (path.parts[0] == 'reports' and name != ALLOWED_REPORT):
        raise ValueError('Private evidence in publication: ' + name)
    text = data.decode('utf-8', errors='strict')
    if any(pattern.search(text) for pattern in PATTERNS):
        raise ValueError('Sensitive content in publication: ' + name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path)
    args = parser.parse_args()
    if args.archive:
        with zipfile.ZipFile(args.archive) as archive:
            files = [(name, archive.read(name)) for name in archive.namelist() if not name.endswith('/')]
    else:
        command = ['git', '-c', 'safe.directory=' + ROOT.as_posix(), '-C', str(ROOT)]
        names = subprocess.check_output(command + ['ls-files', '-z']).decode().split('\0')
        files = [(name, subprocess.check_output(command + ['show', ':' + name])) for name in names if name]
    for name, data in files:
        validate(name, data)
    print('PASS publication privacy/artifact checks: ' + str(len(files)) + ' source files')


if __name__ == '__main__':
    main()
