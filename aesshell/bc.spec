# -*- mode: python -*-
a = Analysis(['bc.py'],
             pathex=[''],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
		  a.binaries + [('msvcp90.dll', 'msvcp90.dll', 'BINARY'),
						('msvcr90.dll', 'msvcr90.dll', 'BINARY')]
		  if sys.platform == 'win32' else a.binaries,
          a.zipfiles,
          a.datas,
          name='bc.exe',
          debug=False,
          strip=None,
          upx=True,
          console=True )
