"""Inert trace-only source-snapshot generator. No build, launch, download or analysis.

Requires a separately reviewed baseline preparation manifest and its exact original
snapshot. This generator never changes that baseline or the frozen installation.
"""
import argparse
import datetime
import difflib
import hashlib
import json
from pathlib import Path
import re
import shutil

PINS={
    'action.cc':'c14bee9f21a2a3cf43bef77f4940429edf1f1ac629d9b4544733b9232535035f',
    'action.hh':'30a4b0223f32b5a04a084bce8d1632098926065708c91638022637140a0e5624',
    'ghidra_process.cc':'d7b1ed2b70cec9209cadcdb4029641da0e00774c0a5c62be7dd940423413148e',
}

# Header-only inline external-linkage state is shared across the two translation
# units. There are no extra .cc files and no changes to the 79-source build list.
HEADER=r'''// Trace-only diagnostic helper, C++11. No analysis-state access or output on protocol streams.
#ifndef TERRARIA_NATIVE_ACTION_TRACE_HH
#define TERRARIA_NATIVE_ACTION_TRACE_HH
#include <atomic>
#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <mutex>
#include <fcntl.h>
#include <io.h>
#include <process.h>
#include <sys/stat.h>

namespace terraria_trace {
struct PreserveErrno {
  int value;
  PreserveErrno() noexcept : value(errno) {}
  ~PreserveErrno() noexcept { errno=value; }
};
inline unsigned long long tick() noexcept {
  return static_cast<unsigned long long>(std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now().time_since_epoch()).count());
}
inline void clean(char *out,const char *in,std::size_t n) noexcept {
  std::size_t i=0;
  if (in) for(;i+1<n && in[i];++i) {
    const unsigned char c=static_cast<unsigned char>(in[i]);
    out[i]=(c>=33 && c<=126)?static_cast<char>(c):'?';
  }
  out[i]=0;
}
struct ThreadState {
  unsigned long long current;
  unsigned int depth;
  ThreadState() noexcept : current(0),depth(0) {}
};
inline ThreadState &threadState() noexcept { static thread_local ThreadState value; return value; }
struct State {
  std::FILE *file;
  std::atomic<bool> enabled;
  std::mutex lock;
  unsigned long long sequence,events,bytes;
  static const unsigned long long maxBytes=64ULL*1024ULL*1024ULL;
  static const unsigned long long maxEvents=500000ULL;
  State() noexcept : file(0),enabled(false),sequence(0),events(0),bytes(0) {
    // Explicit ASCII drive-absolute path only. No fallback, stdout or stderr.
    const char *base=std::getenv("TERRARIA_DECOMP_TRACE_FILE");
    if (!base || !base[0]) return;
    const bool drive=((base[0]>='A'&&base[0]<='Z')||(base[0]>='a'&&base[0]<='z'));
    if (!drive || base[1]!=':' || (base[2]!='/' && base[2]!='\\')) return;
    std::size_t length=0;
    for(;base[length];++length) if(length>=1800 || static_cast<unsigned char>(base[length])<32 || static_cast<unsigned char>(base[length])>126) return;
    char path[2048];
    const int count=std::snprintf(path,sizeof(path),"%s.pid%d.log",base,_getpid());
    if(count<=0 || static_cast<std::size_t>(count)>=sizeof(path)) return;
    // Exclusive create: a stale PID/path never silently overwrites evidence.
    const int fd=_open(path,_O_WRONLY|_O_CREAT|_O_EXCL|_O_BINARY,_S_IREAD|_S_IWRITE);
    if(fd<0) return;
    file=_fdopen(fd,"wb");
    if(!file) { _close(fd); return; }
    const int wrote=std::fprintf(file,"TRACEv1\tpid=%d\tclock=steady_ns\tmax_events=%llu\tmax_bytes=%llu\n",_getpid(),maxEvents,maxBytes);
    if(wrote<0 || std::fflush(file)!=0) return;
    bytes=static_cast<unsigned long long>(wrote);enabled.store(true);
  }
  ~State() noexcept { if(file) std::fclose(file); }
  bool write(const char *event,unsigned long long seq,unsigned long long parent,unsigned int depth,
             const char *kind,const char *name,const char *group,const char *function,
             unsigned long long address,unsigned long long now,unsigned long long elapsed,bool exceptional) noexcept {
    try {
      std::lock_guard<std::mutex> guard(lock);
      if(!enabled.load() || !file) return false;
      // Leave room for one final diagnostic line, including the largest bounded fields.
      if(events>=maxEvents || bytes+2048>=maxBytes) {
        std::fprintf(file,"LIMIT\ttime_ns=%llu\tevents=%llu\tbytes=%llu\n",now,events,bytes);
        std::fflush(file);enabled.store(false);return false;
      }
      const int wrote=std::fprintf(file,"%s\tseq=%llu\tparent=%llu\tdepth=%u\ttime_ns=%llu\telapsed_ns=%llu\tkind=%s\tname=%s\tgroup=%s\tfunction=%s\tentry=0x%llx\texception_active=%u\n",
          event,seq,parent,depth,now,elapsed,kind,name,group,function,address,exceptional?1U:0U);
      if(wrote<0 || std::fflush(file)!=0) { enabled.store(false);return false; }
      bytes+=static_cast<unsigned long long>(wrote);++events;return true;
    } catch(...) { enabled.store(false);return false; }
  }
  unsigned long long next() noexcept {
    try { std::lock_guard<std::mutex> guard(lock);return ++sequence; }
    catch(...) { enabled.store(false);return 0; }
  }
};
inline State &state() noexcept { static State value;return value; }
class Scope {
  bool active;
  unsigned long long seq,parent,begin,address;
  unsigned int depth;
  char kind[32],name[128],group[96],function[192];
public:
  Scope(const char *k,const char *n,const char *g,const char *f,unsigned long long a) noexcept
    :active(false),seq(0),parent(0),begin(0),address(a),depth(0) {
    PreserveErrno preserveErrno;
    State &s=state();
    if(!s.enabled.load()) return;
    ThreadState &t=threadState();seq=s.next();if(!seq) return;
    clean(kind,k,sizeof(kind));clean(name,n,sizeof(name));clean(group,g,sizeof(group));clean(function,f,sizeof(function));
    parent=t.current;depth=t.depth;begin=tick();
    if(!s.write("BEGIN",seq,parent,depth,kind,name,group,function,address,begin,0,std::uncaught_exception())) return;
    t.current=seq;t.depth=depth+1;active=true;
  }
  ~Scope() noexcept {
    if(!active) return;
    PreserveErrno preserveErrno;
    const unsigned long long end=tick();
    state().write("END",seq,parent,depth,kind,name,group,function,address,end,end-begin,std::uncaught_exception());
    ThreadState &t=threadState();t.current=parent;t.depth=depth;
  }
  Scope(const Scope &)=delete;
  Scope &operator=(const Scope &)=delete;
};
} // namespace terraria_trace
#endif
'''

def sha(p):
    with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def require(ok,message):
    if not ok:raise ValueError(message)
def regular(p):
    require(p.is_file() and not p.is_symlink() and not(getattr(p.lstat(),'st_file_attributes',0)&0x400),f'Nonregular/reparse input: {p}')
def replace_once(text,old,new,label,rows):
    require(text.count(old)==1,f'Anchor not unique: {label}')
    rows.append(dict(label=label,original_anchor=old,replacement=new,anchor_sha256=hashlib.sha256(old.encode()).hexdigest()))
    return text.replace(old,new,1)

def patched(name,text,anchors):
    if name=='action.cc':
        text=replace_once(text,'#include "funcdata.hh"','#include "funcdata.hh"\n#include "terraria_action_trace.hh"','action trace include',anchors)
        old='      res = apply(data);\t// Start or continue action'
        new='''      {
        terraria_trace::Scope trace("action",getName().c_str(),getGroup().c_str(),data.getName().c_str(),data.getAddress().getOffset());
        res = apply(data);\t// Start or continue action
      }'''
        return replace_once(text,old,new,'action apply guard',anchors)
    if name=='ghidra_process.cc':
        text=replace_once(text,'#include "blockaction.hh"','#include "blockaction.hh"\n#include "terraria_action_trace.hh"','command trace include',anchors)
        for call,label in [('ghidra->allacts.getCurrent()->reset( *fd );','reset'),('ghidra->allacts.getCurrent()->perform( *fd );','perform')]:
            old='    '+call
            new='    {\n      terraria_trace::Scope trace("command","'+label+'","protocol",fd->getName().c_str(),fd->getAddress().getOffset());\n      '+call+'\n    }'
            text=replace_once(text,old,new,'command '+label,anchors)
        old='      fd->encode(encoder,0,ghidra->getSendSyntaxTree());'
        new='''      {
        terraria_trace::Scope trace("command","encode","protocol",fd->getName().c_str(),fd->getAddress().getOffset());
        fd->encode(encoder,0,ghidra->getSendSyntaxTree());
      }'''
        text=replace_once(text,old,new,'command encode',anchors)
        old='''      if (ghidra->getSendCCode()&&
\t  (ghidra->allacts.getCurrentName() == "decompile"))
        ghidra->print->docFunction(fd);'''
        new='''      if (ghidra->getSendCCode()&&
\t  (ghidra->allacts.getCurrentName() == "decompile")) {
        terraria_trace::Scope trace("command","docFunction","protocol",fd->getName().c_str(),fd->getAddress().getOffset());
        ghidra->print->docFunction(fd);
      }'''
        return replace_once(text,old,new,'command docFunction',anchors)
    return text

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--lab',type=Path,default=Path('C:/Temp/terraria-re-20261012'))
    p.add_argument('--baseline',type=Path,required=True)
    p.add_argument('--name',default='portable-decompiler-trace-source-20261017')
    a=p.parse_args();lab=a.lab.resolve();base=a.baseline.resolve()
    require(lab.is_dir() and base.is_relative_to(lab) and base!=lab,'Baseline must be isolated inside lab')
    require(re.fullmatch(r'portable-decompiler-trace-source-[a-zA-Z0-9-]+',a.name) is not None,'Fresh destination name invalid')
    out=lab/a.name;require(not out.exists() and out.resolve().is_relative_to(lab),'Fresh safe destination required')
    manifest_path=base/'preparation-manifest.json';regular(manifest_path)
    baseline=json.loads(manifest_path.read_text(encoding='utf-8-sig'))
    require(baseline['schema']=='portable-ghidra-baseline-preparation-v1' and baseline['source_snapshot_unmodified'] is True,'Unmodified baseline preparation required')
    src=base/'source';require(src.is_dir() and not src.is_symlink() and not(getattr(src.lstat(),'st_file_attributes',0)&0x400) and src.resolve().is_relative_to(base),'Snapshot missing/reparse/outside baseline')
    rows=baseline['snapshot_files'];require(len({r['path'] for r in rows})==len(rows),'Duplicate input manifest paths')
    actual={p.name for p in src.iterdir() if p.is_file()}
    require(actual=={r['path'] for r in rows},'Snapshot inventory differs')
    for row in rows:
        name=row['path'];require(Path(name).name==name and re.fullmatch(r'[A-Za-z0-9_.-]+\.(cc|hh|h)',name) is not None,'Unsafe snapshot filename')
        f=src/name;regular(f);require(f.stat().st_size==row['bytes'] and sha(f)==row['sha256'],'Snapshot hash differs: '+name)
    for name,digest in PINS.items():require(sha(src/name)==digest,'Pinned native source differs: '+name)
    sources=baseline['sources'];require(len(sources)==79 and len(set(sources))==79 and set(sources)<=actual,'Exact baseline 79 sources required')
    changes={};anchors=[];diff=[]
    for name in ('action.cc','ghidra_process.cc'):
        before=(src/name).read_text(encoding='utf8');after=patched(name,before,anchors);require(before!=after,'Missing trace change')
        changes[name]=after;diff.extend(difflib.unified_diff(before.splitlines(True),after.splitlines(True),fromfile='baseline/'+name,tofile='trace/'+name))
    require(len(anchors)==7,'Expected exactly seven anchored edits')
    # No mutations before all original source hashes and anchors are verified.
    out.mkdir();dest=out/'source';dest.mkdir()
    for row in rows:shutil.copyfile(src/row['path'],dest/row['path'])
    for name,text in changes.items():(dest/name).write_text(text,encoding='utf8',newline='\n')
    (dest/'terraria_action_trace.hh').write_text(HEADER,encoding='utf8',newline='\n')
    patch=out/'trace-only.patch';patch.write_text(''.join(diff)+''.join(difflib.unified_diff([],HEADER.splitlines(True),fromfile='/dev/null',tofile='trace/terraria_action_trace.hh')),encoding='utf8',newline='\n')
    final=[]
    originals={r['path']:r['sha256'] for r in rows}
    for f in sorted(dest.iterdir()):
        regular(f);name=f.name
        if name not in changes and name!='terraria_action_trace.hh':require(sha(f)==sha(src/name)==originals[name],'Unexpected nontrace change')
        final.append(dict(path=name,bytes=f.stat().st_size,sha256=sha(f)))
    record=dict(schema='portable-ghidra-trace-source-v1',created_UTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),generator_sha256=sha(Path(__file__)),baseline=str(base),baseline_preparation_manifest_sha256=sha(manifest_path),pinned_original_sources=PINS,original_snapshot_files=rows,trace_snapshot_files=final,sources=sources,added_translation_units=[],modified_source_files=['action.cc','ghidra_process.cc'],added_header='terraria_action_trace.hh',anchors=anchors,patch_sha256=sha(patch),trace_environment_variable='TERRARIA_DECOMP_TRACE_FILE',trace_output='explicit ASCII drive-absolute base path plus .pid<PID>.log, exclusive create',maximum_trace_events=500000,maximum_trace_bytes=64*1024*1024,log_capacity_reached_means_incomplete_evidence=True,CPUI_DEBUG_enabled=False,analysis_algorithms_changed=False,analysis_budgets_changed=False,build_or_engine_modified=False,baseline_native_compile_required_before_execution=True,compiler_validation_performed=False,runtime_validation_performed=False,C_coverage_addition=0)
    (out/'trace-source-manifest.json').write_text(json.dumps(record,indent=2)+'\n',encoding='utf8')
    print(json.dumps(dict(trace_source_snapshot=str(out),modified_sources=record['modified_source_files'],build_executed=False)))

if __name__=='__main__':main()
