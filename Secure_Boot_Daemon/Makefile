Secure_Boot_Daemon: Secure_Boot_Daemon.o
	gcc -o Secure_Boot_Daemon Secure_Boot_Daemon.o -ltspi -lcrypto -lssl
Secure_Boot_Daemon.o: Secure_Boot_Daemon.c
	gcc -c Secure_Boot_Daemon.c

clean:
	rm -f Secure_Boot_Daemon Secure_Boot_Daemon.o
