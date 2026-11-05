#!/usr/bin/env python3
"""Regenerate the CPU C declaration inventory inside the exclusive build guard.

Run from the repository root. Writes only .tools/cpu-generation diagnostics;
review the JSON against native/cpu_generation_footprint.inc before repinning.
The GCC-only intrinsic spelling is aliased for Clang AST analysis only. The
production backend is still compiled with its original GCC flags.
"""
import subprocess,json,collections
from pathlib import Path
base=Path('research/pq-ringct'); dest=Path('.tools/cpu-generation')
dest.mkdir(parents=True, exist_ok=True)
groups={}
for leaf in ['spend','gaussian_avx','fastrandombytes','matrict']:
 path=base/('native/matrict.c' if leaf=='matrict' else f'vendor/matrict-plus/n10/{leaf}.c')
 command=['clang','-std=gnu11','-D_mm_cvtsi64x_si128=_mm_cvtsi64_si128','-mavx2','-maes','-mfma','-I'+str(base/'vendor/matrict-plus/n10'),'-I'+str(base/'native/include'),'-I'+str(base/'native'),'-Xclang','-ast-dump=json','-fsyntax-only',str(path)]
 with (dest/f'{leaf}-ast.json').open('w') as f: subprocess.run(command,stdout=f,check=True)
 ast=json.loads((dest/f'{leaf}-ast.json').read_text()); result={}; last_file=''
 for node in ast['inner']:
  loc=node.get('loc',{});last_file=loc.get('file',last_file)
  if node.get('kind')!='FunctionDecl' or not any(c['kind']=='CompoundStmt' for c in node.get('inner',[])):continue
  name=node.get('name','')
  if leaf=='matrict':
   if not (name.startswith('cpu_generation_') or name.startswith('lattica_cpu_generation_')):continue
  elif Path(last_file).name!=path.name:continue
  locals=[]
  def visit(n):
   if n.get('kind') in ('VarDecl','ParmVarDecl') and n.get('storageClass')!='static':
    locals.append({'name':n.get('name',''),'type':n['type']['qualType']})
   for x in n.get('inner',[]):visit(x)
  visit(node);result[name]=locals
 groups[leaf]=result
counts=collections.Counter(v['type'] for funcs in groups.values() for vs in funcs.values() for v in vs)
(dest/'cpu-census-r1.json').write_text(json.dumps({'functions':groups,'type_counts':dict(sorted(counts.items()))},indent=2)+'\n')
print(json.dumps({'functions':{k:list(v) for k,v in groups.items()},'type_counts':dict(sorted(counts.items()))},indent=2))
