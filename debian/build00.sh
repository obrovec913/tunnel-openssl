#!/bin/bash
PRODUCT_NAME=${PRODUCT_NAME:-mmbeltunnel}
PRODUCT_VERSION=${PRODUCT_VERSION:-1.0}
PRODUCT_DEBARCH=$(dpkg --print-architecture)

cd ${START_DIR}

gcc -o ${PRODUCT_NAME} tunnel.c -L/opt/${PRODUCT_NAME}/build/local/lib/ -I/opt/${PRODUCT_NAME}/build/local/include/ -lssl -lcrypto -lbee2evp -lpthread -Wl,-rpath=/opt/${PRODUCT_NAME}/build/local/lib/
mkdir -p package/usr/bin
mkdir -p package/DEBIAN
mkdir -p package/opt/${PRODUCT_NAME}/build/local/lib
mkdir -p package/opt/${PRODUCT_NAME}/build/local/include

cp ${PRODUCT_NAME} package/usr/bin/
cp -r /opt/${PRODUCT_NAME}/build/local/lib/* package/opt/${PRODUCT_NAME}/build/local/lib/
cp -r /opt/${PRODUCT_NAME}/build/local/include/* package/opt/${PRODUCT_NAME}/build/local/include/

# Создание файла control
cat << DEB_CONTROL > package/DEBIAN/control
Package: ${PRODUCT_NAME}
Version: ${PRODUCT_VERSION}
Architecture: ${PRODUCT_DEBARCH}
Maintainer: Your Name <your.email@malidi.by>
Description: Description of your program
 A longer description can go here if needed.
DEB_CONTROL

pwd
dpkg-deb --build package ${PRODUCT_NAME}_${PRODUCT_VERSION}_${PRODUCT_DEBARCH}.deb
