#!/bin/bash
gcc -o tunnel_malidi_server tunnelc.c -L/opt/beltunnel/build/local/lib/ -I/opt/beltunnel/build/local/include/ -lssl -lcrypto -lbee2evp -lpthread -Wl,-rpath=/opt/beltunnel/build/local/lib/
mkdir -p package/usr/bin
mkdir -p package/opt/beltunnel/build/local/lib
mkdir -p package/opt/beltunnel/build/local/include

cp tunnel_malidi_server package/usr/bin/
cp -r /opt/beltunnel/build/local/lib/* package/opt/beltunnel/build/local/lib/
cp -r /opt/beltunnel/build/local/include/* package/opt/beltunnel/build/local/include/

# Создание файла control
echo "Package: tunnel_malidi" > package/DEBIAN/control
echo "Version: 1.0" >> package/DEBIAN/control
echo "Architecture: amd64" >> package/DEBIAN/control
echo "Maintainer: Your Name <your.email@example.com>" >> package/DEBIAN/control
echo "Description: Description of your program" >> package/DEBIAN/control
echo " A longer description can go here if needed." >> package/DEBIAN/control

dpkg-deb --build package
