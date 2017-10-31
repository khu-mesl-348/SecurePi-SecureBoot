Secure_Boot: Secure_Boot.o
	gcc -o Secure_Boot Secure_Boot.o -ltspi -lcrypto -lssl
Secure_Boot.o: Secure_Boot.c
	gcc -c Secure_Boot.c

clean:
	rm -f Secure_Boot Secure_Boot.o
