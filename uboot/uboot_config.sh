#!bin/bash

cp u-boot.bin /boot/
cp image.fit /boot/
cp uboot.env /boot/

echo "kernel=u-boot.bin" >> /boot/config.txt
