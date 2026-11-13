#!/usr/bin/env python3
import os,subprocess,shutil,tempfile,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1];out=Path(tempfile.gettempdir())/'mimiboot-night';out.mkdir(exist_ok=True)
cc=os.environ.get('HOST_CC') or shutil.which('clang') or shutil.which('gcc') or 'C:/Program Files/LLVM/bin/clang.exe'
with (ROOT/'tests/gen_signed.h').open('w') as f:subprocess.run([sys.executable,'tests/gen_signed.py'],cwd=ROOT,check=True,stdout=f)
src=['core/'+n+'.c' for n in ['mb_hash','mb_ed25519','mb_image','mb_bcl','mb_config','mb_policy','mb_recv','mb_console','mb_control','mb_grub','mb_formats']]+['client/mb_client.c','tests/sim_port.c','tests/test_crypto.c','tests/test_mimiboot.c']
exe=out/('mimiboot_tests.exe' if os.name=='nt' else 'mimiboot_tests')
subprocess.run([cc,'-std=c11','-O1','-g','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-D_CRT_SECURE_NO_WARNINGS','-I.','-Iinclude',*src,'-o',str(exe)],cwd=ROOT,check=True)
subprocess.run([str(exe)],cwd=ROOT,check=True)
