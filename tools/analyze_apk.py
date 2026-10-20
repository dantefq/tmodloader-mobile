import argparse
import json
from pathlib import Path
from apk_format import probe

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('apk', type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = probe(args.apk)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(text + '\n', encoding='utf-8')
    print(json.dumps({key:value for key,value in report.items() if key != 'il2cpp_exports'}, ensure_ascii=False, indent=2))
