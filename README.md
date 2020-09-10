# Laelaps


## Notice
1. To test a new firmware, create a directory in the ```proj``` directory. The general naming rule is ```proj_devicename_appname```.
2. The last worked version of Angr is `8.19.2.4`.


## Installation
Make sure Ubuntu 18.04 and Python 3 are used.

1. Install [Python virtualenvwrapper](https://virtualenvwrapper.readthedocs.io/en/latest/) and create a virtual environment `laelaps`. All the following steps are operated inside this virtual environment. So, execute this command first.
```
$ workon laelaps
```
2. Build qemu-3.0.0.
```
$ sudo apt-get build-dep -y qemu
$ mkdir ../build && cd ../build
$ ../qemu-3.0.0/configure --python=python3 --target-list="arm-softmmu" --disable-vnc --disable-curses --disable-sdl --disable-hax --disable-rdma --enable-debug
$ make
```
   Then, `qemu-system-arm` can be found in this build directory and the path is: `arm-softmmu/qemu-system-arm`. Put `qemu-system-arm` in PATH.
   
3. Download [ARM GCC toolchain](https://developer.arm.com/open-source/gnu-toolchain/gnu-rm/downloads). The URL can be found at https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu-rm/9-2020q2/gcc-arm-none-eabi-9-2020-q2-update-x86_64-linux.tar.bz2. Unzip it and put the `bin` directory in PATH.
4. Install angr. 
   - Install angr dependencies.
     ```
     $ pip install angr==8.19.2.4; pip uninstall angr
     ```
   - Download angr's source code from PyPI and install angr from the source code.
     ```
     $ wget https://files.pythonhosted.org/packages/35/19/07442cc5789f6c40eae7ea2bd34a04402fa94f9e3d94cba0ab8354d231cf/angr-8.19.2.4.tar.gz
     $ tar xf angr-8.19.2.4.tar.gz
     $ cd angr-8.19.2.4
     $ pip install -e ./
     ```
5. CD to the root directory of angr and patch it using the following command.
```
patch -p1 < $(root_of_this_repo)/p.patch
```
6. Install the following dependencies with `pip`.
```
numpy
pygdbmi==0.9.0.0
intervaltree
posix_ipc>=1.0.0
capstone>=3.0.4
keystone-engine
parse
configparser
npyscreen
enum34
unicorn
```
7. Install avatar2.
```
$ cd avatar2
$ pip install -e ./
```
8. Install concolic.
```
$ cd concolic
$ pip install -e ./
```
9. Run tests in `proj` directory.


## Example
To get started, here is an example of using `Laelaps` to run the firmware inside `proj_nxp_frdmk66f_adc`.

```
$ workon laelaps
$ cd proj/proj_nxp_frdmk66f_adc
$ ./driver.py
```
After a while, qemu reaches the breakpoint `0x694`, which is set up after the usage of adc peripheral. Then Laelaps can be stopped by executing the shell script in another terminal.
```
$ ./scratch/kill.sh
```

When running the firmware with `uart`, the output is stored in the file `logfiles/debug.txt`. For example, when running the firmware inside `proj_nxp_frdmk66f_rtos_hello`, the *hello world* can be output.
```
$ workon laelaps
$ cd proj/proj_nxp_frdmk66f_rtos_hello
$ ./driver.py
```
In another terminal, execute
```
$ tail -f logfiles/debug.txt
```
Then, after a while, *hello world* is output. In the end, stop laelaps by executing
```
$ ./scratch/kill.sh
```

Certain logs can be found in the following directories:
- logfiles
- myavatar
