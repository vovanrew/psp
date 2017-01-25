#!/bin/bash
sudo mkdir /usr/local/psp
sudo cp -r include src libsqlite.a tinyxml.a /usr/local/psp
cd /usr/local/psp
sudo git clone https://github.com/mfontanini/libtins.git
sudo apt-get install libpcap-dev libssl-dev cmake
cd libtins
sudo mkdir build_libtis
cd build_libtis
sudo cmake ../ -DLIBTINS_ENABLE_CXX11=1
make
sudo make install
cd ..
cd ..
sudo g++ src/psp.cpp src/conf.cpp libsqlite.a tinyxml.a -o psp -ltins -std=c++11 -ldl -lpthread -I include
sudo sudo ln -s "/usr/local/psp/./psp" "/usr/bin/psp" 
exit 0
