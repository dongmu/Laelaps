#!/bin/bash


cp /etc/apt/sources.list /etc/apt/sources.list~
sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
apt-get update
apt-get install python3 python3-pip vim wget python3-dev libffi-dev build-essential psmisc -y
update-alternatives --install /usr/bin/python python /usr/bin/python3 10
update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 10





apt-get build-dep -y qemu
mkdir ./build
cd ./build
../qemu-3.0.0/configure --python=python3 --target-list="arm-softmmu" --disable-vnc --disable-curses --disable-sdl --disable-hax --disable-rdma --enable-debug
make -j4
cd ..


#only needed to compile targets
wget https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-rm/9-2020q2/gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2
tar xf gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2


echo 'export PATH="/root/gcc-arm-none-eabi-9-2020-q2-update/bin:/root/build/arm-softmmu:$PATH"' >> ~/.bashrc
source .profile



wget https://files.pythonhosted.org/packages/35/19/07442cc5789f6c40eae7ea2bd34a04402fa94f9e3d94cba0ab8354d231cf/angr-8.19.2.4.tar.gz
tar xf angr-8.19.2.4.tar.gz
cd angr-8.19.2.4
patch -p1 < ../p.patch
pip install -e ./
cd ..



cd avatar2
pip install -e ./

cd ../concolic
pip install -e ./
cd ..



















