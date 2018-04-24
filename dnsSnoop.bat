@ECHO off
SET /P domain=Please enter a domain:
IF "%domain%"=="" GOTO Error
nslookup -type=soa -debug %domain% >> results.txt
ECHO Snooping DNS cache...
ECHO Results printed!
GOTO End
:Error:
ECHO You didn't enter anything!
:End:
PAUSE

