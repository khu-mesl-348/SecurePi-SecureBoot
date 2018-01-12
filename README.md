# SecurePi_Secure-Boot

1. root계정 로그인
2. 디렉토리 생성 및 이동
	- mkdir /root/securepi (이미 존재한다면 생략)
	- cd /root/securepi
3. Secure Boot 파일 다운
	- git clone https://github.com/khu-mesl-348/SecurePi_Secure-Boot.git
4. uboot 설정
	- cd /root/securepi/SecurePi_Secure-Boot/uboot
	- sh ./uboot_config.sh
5 검증 서명 생성
	- cd/root/ securepi/SecurePi_Secure-Boot/Create_Sign
	- make
	- ./Create_Sign
6. Secure Boot Daemon 설정
	- cd/root/ securepi/SecurePi_Secure-Boot/Secure_Boot_Daemon
	- make
	- sh ./daemon_config.sh
7. 재부팅
