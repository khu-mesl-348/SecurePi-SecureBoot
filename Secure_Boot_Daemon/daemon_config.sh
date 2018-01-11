#!bin/bash

perl -p -i -e '$.==19 and print "/root/SecurePi_Secure-Boot/Secure_Boot_Daemon/Secure_Boot_Daemon"' /etc/rc.local 
