#!/bin/bash
bee2evpinstall=/opt/beltunnel/bee2evp
tunnelMalidi=/opt/beltunnel/tunel
bee2evp=/opt/beltunnel/
build_root=$bee2evp/build
bee2=$bee2evp/bee2
openssl=$bee2evp/openssl
build_bee2evp=$build_root/build_bee2evp
build_bee2=$build_root/build_bee2
build_openssl=$build_root/build_openssl
local=$build_root/local
openssl_branch=OpenSSL_1_1_1i
openssl_patch=OpenSSL_1_1_1i.patch



install_prereq(){
  sudo apt-get update
    sudo apt-get install git gcc cmake python3
  git clone https://github.com/bcrypto/bee2evp.git $bee2evpinstall
  git clone https://github.com/agievich/bee2.git $bee2evpinstall/bee2
  mkdir $tunnelMalidi
  cp -r ./* $tunnelMalidi
}

clean(){
  rm -rf $build_root
  rm -rf $openssl
}

update_repos(){
  git submodule update --init
  git clone -b $openssl_branch --depth 1 https://github.com/openssl/openssl $openssl
  cd $openssl
  git apply $bee2evpinstall/btls/patch/$openssl_patch
  cp $bee2evpinstall/btls/btls.c ./ssl/
  cp $bee2evpinstall/btls/btls.h ./ssl/
}

build_bee2(){
  mkdir -p $build_bee2 && mkdir -p $local && cd $build_bee2
  cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_PIC=ON -DCMAKE_INSTALL_PREFIX=$local $bee2evpinstall/bee2/
  make -j$(nproc) && ctest && make install
  ls -la $local/lib/libbee2_static.a
}

build_openssl(){
  mkdir -p $build_openssl && mkdir -p $local && cd $build_openssl
  $openssl/config shared -d --prefix=$local --openssldir=$local
  make -j$(nproc) all 
  make install > build.log 2>&1 || (cat build.log && exit 1)
  ls -la $local/lib/libcrypto.a
  ls -la $local/lib/libssl.a
  ls -la $local/lib/libcrypto.so
  ls -la $local/lib/libssl.so
}

build_bee2evp(){
  mkdir -p $build_bee2evp && cd $build_bee2evp
  cmake -DCMAKE_BUILD_TYPE=Release \
    -DBEE2_LIBRARY_DIRS=$local/lib -DBEE2_INCLUDE_DIRS=$local/include \
    -DOPENSSL_LIBRARY_DIRS=$local/lib -DOPENSSL_INCLUDE_DIRS=$local/include \
    -DLIB_INSTALL_DIR=$local/lib -DCMAKE_INSTALL_PREFIX=$local $bee2evpinstall
  make -j$(nproc) && make install
  ls -la $local/lib/libbee2evp.so
}

attach_bee2evp(){
  cp $tunnelMalidi/openssl.cnf $local/openssl.cnf
  sed -i "s|#path/to/bee2evp|$local/lib/libbee2evp.so|g" $local/openssl.cnf  
}

test_bee2evp(){
  export LD_LIBRARY_PATH="$local/lib:${LD_LIBRARY_PATH:-}"
  cd $local/bin
  ./openssl version
  ./openssl engine -c -t bee2evp
}

tunnel_build(){
  sudo update-alternatives --install /usr/bin/openssl openssl /opt/beltunnel/build/local/bin/openssl 100
  sudo ln -sf /opt/beltunnel/build/local/bin/openssl /usr/bin/openssl
  export OPENSSL_CONF=/opt/beltunnel/build/local/openssl.cnf
  cd $tunnelMalidi
  gcc -o tunnel_malidi tunnel.c -L/opt/beltunnel/build/local/lib/ -I/opt/beltunnel/build/local/include/ -lssl -lcrypto -lbee2evp -lpthread -Wl,-rpath=/opt/beltunnel/build/local/lib/
  chmod +x ./build00.sh
  ./build00.sh

}


install_prereq

clean
update_repos
build_bee2
build_openssl
build_bee2evp
attach_bee2evp
test_bee2evp
tunnel_build