"""Compose the opt-in combined bridge without altering standalone script order."""
from pathlib import Path


def combined_script(root: Path) -> bytes:
    def read(name):
        return (root / 'runtime' / name).read_bytes()
    early = b'\n'.join(read(name) for name in (
        'mono-runtime.js', 'managed-time-host.js', 'managed-host.js',
        'sleep-scene.js', 'time-loader.js'))
    # All item modules share loader.js lexical state. Wait for time's delayed
    # crypto/GC checks before executing them; domain creation remains early.
    items = b'\n'.join(read(name) for name in (
        'loader.js', 'save-trace.js', 'content-sidecar.js', 'moditem-content.js'))
    return (early + b'\n(() => {\nconst combinedTimer=setInterval(()=>{\n'
            b'if(globalThis.TMALCombinedTimeReady!==true)return;\n'
            b'clearInterval(combinedTimer);\n'
            b'globalThis.TMALContentDelayUntil=Date.now()+15000;\n'
            b'(() => {\n' + items + b'\n})();\n},100);\n})();\n'
            + read('lab-protection.js'))
