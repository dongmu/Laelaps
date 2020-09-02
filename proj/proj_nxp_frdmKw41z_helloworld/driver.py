#!/usr/bin/env python

from avatar2 import *

import logging
# logging.getLogger('angr').setLevel('DEBUG')
# logging.getLogger('angr').setLevel('INFO')

# logging.getLogger('concolic').setLevel(logging.DEBUG)
# logging.getLogger('concolic').setLevel(logging.INFO)

import concolic.utils as utils
import concolic.peripheral as peripheral

import random

# proj specific settings
RAM_START = 0x1FFF8000
RAM_SIZE = 0x20000
RAM_FILE = {'start': RAM_START, 'size': RAM_SIZE,
            'file': "/dev/shm/SHM.0." + format(RAM_SIZE, '#04x')
            }

sample = './frdmkw41z_helloworlddemo_apps_hello_world.bin'
OUT_DIR = "logfiles/myavatar"
QEMU_PATH = "qemu-system-arm"
ROM_START=0x0
ROM_SIZE=0x80000
ROM_FILE = {'start': ROM_START, 'size': ROM_SIZE,
            'file': sample, 'alias': None}
# binary starts at LOAD_OFFSET
LOAD_OFFSET=0x0
RAW_BIBARY=True

ASSERT_FUNC = {}

#DEBUG_PORT
DEBUG_PORT = 0x4005400c


# sometimes symbolic execution is unnecessarily slow, because no branch is taken. E.g., memory.
# we mandatorily exit angr and force concrete execution.
memcpy_addr = 0x3ab44 + 1
memset_addr = 0x3ab8c + 1
strlen_addr = 0x3abb4 + 1
i2c_release_bus_delay = 0x2ad6c + 1

stopHooks = {}
# stopHooks = {memcpy_addr, memset_addr, strlen_addr, i2c_release_bus_delay}
# stopHooks = {memset_addr}


logger = logging.getLogger('app')
logger.setLevel(logging.DEBUG)


ROM = bytearray()

if __name__ == "__main__":
    # Create avatar instance with custom output directory
    avatar = Avatar(arch=archs.arm.ARM_CORTEX_M3, output_directory=OUT_DIR)

    # Add first target
    logger.info("[+] Creating the QEMUTarget")
    qemu = avatar.add_target(QemuTarget, name='qemu',
                              gdb_executable="arm-none-eabi-gdb",
                              firmware=sample, cpu_model="cortex-m4",
                             # gdb_port = random.randint(300, 100000),
                             # qmp_port = random.randint(300, 100000),
                              executable=QEMU_PATH,
                              raw = RAW_BIBARY,
                             interval = 0.2)
    logger.info("[+] Creating the AngrTarget")
    angr = avatar.add_target(AngrTarget, binary=sample, ram_file=RAM_FILE, name='angr', \
            load_options={'main_opts': {'backend':'blob', 'custom_arch':'ARM', \
                                        'custom_base_addr': LOAD_OFFSET, 'custom_entry_point': 0x1001}})


    with open(sample, "rb") as binary_file:
            # Read the whole file at once
            ROM = binary_file.read()


    # add memory
    ram  = avatar.add_memory_range(RAM_FILE['start'], RAM_FILE['size'], name='ram',
                                   permissions='rw-')
    rom  = avatar.add_memory_range(ROM_FILE['start'], ROM_FILE['size'], name='rom',
                                   file=sample,
                                   permissions='r-x', alias = ROM_FILE['alias'])

    IgnorePeripheralList = {
            "all-device": (0x40000000, 0x60000000),
            }

    for name, addr in IgnorePeripheralList.items():
        avatar.add_memory_range(addr[0], addr[1], name=name, emulate=peripheral.IgnorePeripheral,
                                rom=ROM, rom_offset=ROM_START, stopHooks = stopHooks,
                                qemu_target=qemu, angr_target=angr, alg = utils.Alg_Enum.Explore_Single_Explore_All,
                                asserts = ASSERT_FUNC,
                                debug_port=DEBUG_PORT,
                                forward_depth=2,
                                depth=1,
                                his = 100,
                                permissions='rw-')

    # start
    logger.info("[+] Initializing the targets")
    avatar.init_targets()

    logger.info("[+] Running in QEMU until a peripherial is accessed")

    # sleep(1000)

    qemu.cont()
    qemu.wait()

    while True:
        pass
