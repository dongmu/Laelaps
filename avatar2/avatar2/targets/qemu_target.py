import json
from subprocess import Popen
from os.path import isfile, exists

import distutils
from avatar2.protocols.gdb import GDBProtocol
from avatar2.protocols.qmp import QMPProtocol
from avatar2.protocols.remote_memory import RemoteMemoryProtocol
from avatar2.targets import Target
from avatar2.targets import TargetStates

from threading import Thread, Lock
from time import sleep
from avatar2.installer.config import QEMU, GDB_ARM

class QemuTarget(Target):
    """
    """

    QEMU_CONFIG_FILE = "conf.json"

    def __init__(self, avatar,
                 executable=None,
                 cpu_model=None, firmware=None,
                 gdb_executable=None, gdb_port=3333,
                 additional_args=None, gdb_additional_args=None,
                 qmp_port=3334,
                 entry_address=None,
                 raw = False,
                 interval = 0.5,
                 **kwargs):
        super(QemuTarget, self).__init__(avatar, **kwargs)

        # Qemu parameters
        if hasattr(self, 'executable') is False: # May be initialized by subclass
            self.executable = (executable if executable is not None
                               else self._arch.get_qemu_executable())
            self.executable = distutils.spawn.find_executable(self.executable)

        self.fw = firmware
        self.cpu_model = cpu_model
        self.raw = raw
        if not raw:
            assert (entry_address is not None)
            self.entry_address = entry_address
        else:
            self.entry_address = 0
        self.additional_args = additional_args if additional_args else []

        # gdb parameters
        self.gdb_executable = (gdb_executable if gdb_executable is not None
                               else self._arch.get_gdb_executable())


        self.gdb_port = gdb_port
        self.gdb_additional_args = gdb_additional_args if gdb_additional_args else []

        self.qmp_port = qmp_port

        self._process = None
        self._entry_address = entry_address
        self._memory_mapping = avatar.memory_ranges

        self.rmem_rx_queue_name = '/%s_rx_queue'.format(self.name)
        self.rmem_tx_queue_name = '/%s_tx_queue'.format(self.name)
        # for interrupt injection
        self.mutex = Lock()
        self.interval = interval


    def assemble_cmd_line(self):
        if isfile(self.executable + self._arch.qemu_name):
            executable_name = [self.executable + self._arch.qemu_name]
        elif isfile(self.executable):
            executable_name = [self.executable]
        else:
            raise Exception("Executable for %s not found: %s" % (self.name,
                                                                 self.executable)
                            )

        if self.name == 'panda':
            machine = ["-machine", "configurable"]
        else:
            machine = ["-machine", "flex"]
        # no spacegti
        debug_log = ["-d", "unimp,in_asm"]
        # debug_log = ["-d", "nochain,in_asm"]
        kernel = ["-kernel", "%s/%s" %
                  (self.avatar.output_directory, self.QEMU_CONFIG_FILE)]
        gdb_option = ["-gdb", "tcp::" + str(self.gdb_port)]
        stop_on_startup = ["-S"]
        nographic = ["-nographic"]  # , "-monitor", "/dev/null"]
        qmp = ['-qmp', 'tcp:127.0.0.1:%d,server,nowait' % self.qmp_port]

        cmdl = executable_name + machine + debug_log + kernel + gdb_option \
               + stop_on_startup + self.additional_args + nographic + qmp
        print("cmdline:")
        print(' '.join(cmdl))
        return cmdl

    def shutdown(self):
        if self._process is not None:
            self._process.terminate()
            self._process.wait()
            self._process = None
        super(QemuTarget, self).shutdown()

    def _serialize_memory_mapping(self):
        ret = []
        for (start, end, mr) in self._memory_mapping:
            mr_dict = {
                'name': mr.name,
                'address': mr.address,
                'size': mr.size,
                'permissions': mr.permissions
            }
            if hasattr(mr, 'qemu_name'):
                mr_dict['qemu_name'] = mr.qemu_name
                mr_dict['properties'] = []
                mr_dict['bus'] = 'sysbus'
                if mr.qemu_name == 'avatar-rmemory':
                    size_properties = {'type': 'uint32',
                                       'value': mr.size,
                                       'name': 'size'}
                    mr_dict['properties'].append(size_properties)
                    address_properties = {'type': 'uint64',
                                          'value': mr.address,
                                          'name': 'address'}
                    mr_dict['properties'].append(address_properties)
                    rx_queue_properties = {'type': 'string',
                                           'value': self.rmem_rx_queue_name,
                                           'name': 'rx_queue_name'}
                    mr_dict['properties'].append(rx_queue_properties)
                    tx_queue_properties = {'type': 'string',
                                           'value': self.rmem_tx_queue_name,
                                           'name': 'tx_queue_name'}
                    mr_dict['properties'].append(tx_queue_properties)

                elif hasattr(mr, 'qemu_properties'):
                    if type(mr.qemu_properties) == list:
                        mr_dict['properties'] += mr.qemu_properties
                    else:
                        mr_dict['properties'].append(mr.qemu_properties)
            elif hasattr(mr, 'file') and mr.file is not None:
                mr_dict['file'] = mr.file
            ret.append(mr_dict)
        return ret

    def generate_configuration(self):
        """
        Generates the configuration passed to avatar-qemus configurable machine
        """
        conf_dict = {}
        if self.cpu_model is not None:
            conf_dict['cpu_model'] = self.cpu_model
        if self.fw is not None:
            conf_dict['kernel'] = self.fw
        if not self.raw:
            conf_dict['entry_address'] = self.entry_address
        if not self._memory_mapping.is_empty():
            conf_dict['memory_mapping'] = self._serialize_memory_mapping()
        else:
            self.log.warning("The memory mapping of QEMU is empty.")
        return conf_dict

        # def add_memory_range(self, mr, **kwargs):
        # self._memory_mapping[mr.address: mr.address + mr.size] = mr
        # TODO: add qemu specific properties to the memory region object

    @staticmethod
    def extract_index(value):
        tmp = [int(x) for x in '{:032b}'.format(value)]
        # output = [n if output[31 - n] else 0 for n in range(32)]
        output = []
        for n in range(32):
            if tmp[31 - n]:
                output.append(n)
        return output

    def interrupt_injection(self, qmp, interval):
        #should run exclusively with RMP
        sleep(60)
        # i = 0
        while True:
            # self.mutex.acquire()
            # print("lock acquired by int")

            cont = False

            if True:
                # either set pending all the active interrupts, for efficience

                # We have more than one peripheral ranges
                for peri in self.avatar.python_peripherals:
                    if peri.busy:
                        cont = True
                if cont:
                    continue

                qmp.inject_interruption_all()

                # i += 1
                # if i == 26:
                #     i = 0
                # elif i % 2 == 0:
                #     self.log.warning("-cc-> Interrupt: 44")
                #     qmp.inject_interruption(44)
                # elif i % 13 == 0:
                #     self.log.warning("-cc-> Interrupt: 31")
                #     qmp.inject_interruption(31)
                # self.log.warning("-cc-> interrupt_injection: i: " + str(i))


            else:
                # or one by one, for flexibility
                self.log.warning("++++++++probe active irqs")
                ret = qmp.get_active_irqs()


                indexes = QemuTarget.extract_index(ret['v0'])
                indexes += [x + 32 for x in QemuTarget.extract_index(ret['v1'])]
                for irq in indexes:
                    qmp.inject_interruption(irq)

                if len(indexes):
                    self.log.warning("++++++++inject_interruption OK" + str(indexes))

            # self.mutex.release()

            sleep(interval)


    def getQemuRegs(self, gdb):
        """
        Get register values through GDB protocol.
        """

        xregs = []
        xregs.append("start")
        xregs.append(gdb.read_register('r0'))
        xregs.append(gdb.read_register('r1'))
        xregs.append(gdb.read_register('r2'))
        xregs.append(gdb.read_register('r3'))
        xregs.append(gdb.read_register('r4'))
        xregs.append(gdb.read_register('r5'))
        xregs.append(gdb.read_register('r6'))
        xregs.append(gdb.read_register('r7'))
        xregs.append(gdb.read_register('r8'))
        xregs.append(gdb.read_register('r9'))
        xregs.append(gdb.read_register('r10'))
        xregs.append(gdb.read_register('r11'))
        xregs.append(gdb.read_register('r12'))
        xregs.append(gdb.read_register('sp'))
        xregs.append(gdb.read_register('lr'))
        xregs.append(gdb.read_register('pc'))
        xregs.append(gdb.read_register('cpsr'))
        xregs.append("end")
        self.log.warning("regs: ==> " + repr(xregs))

        return


    def saveVMSnapshot(self, qmp, gdb):
        """
        Save a vm snapshot when qemu is stopped.
        """

        while True:
            sleep(5)
            self.log.warning("state: " + str(self.get_status()['state']))

            if TargetStates.STOPPED == self.get_status()['state']:
                # self.log.warning("-cc-> save a vm snapshot!")
                # ret = qmp.saveVM()
                # self.log.warning("-cc-> " + str(ret))
                # self.log.warning("-cc-> save a vm snapshot ===== Done!")
                self.getQemuRegs(gdb)
        return


    def init(self):
        """
        Spawns a Qemu process and connects to it
        """

        if self.cpu_model is None:
            if hasattr(self._arch, 'cpu_model'):
                self.cpu_model = self.avatar.arch.cpu_model
            else:
                self.log.warning('No cpu_model specified - are you sure?')

        cmd_line = self.assemble_cmd_line()

        with open("%s/%s" % (self.avatar.output_directory,
                             self.QEMU_CONFIG_FILE), "w") as conf_file:
            conf_dict = self.generate_configuration()
            json.dump(conf_dict, conf_file)

        with open("%s/%s_out.txt" % (self.avatar.output_directory, self.name)
                , "wb") as out, \
                open("%s/%s_err.txt" % (self.avatar.output_directory, self.name)
                    , "wb") as err:
            self._process = Popen(cmd_line, stdout=out, stderr=err)
        self.log.debug("QEMU command line: %s" % ' '.join(cmd_line))
        self.log.info("QEMU process running")

        gdb = GDBProtocol(gdb_executable=self.gdb_executable,
                          arch=self.avatar.arch,
                          additional_args=self.gdb_additional_args,
                          avatar=self.avatar, origin=self)
        qmp = QMPProtocol(self.qmp_port, origin=self)  # TODO: Implement QMP

        if 'avatar-rmemory' in [i[2].qemu_name for i in
                                self._memory_mapping.iter() if
                                hasattr(i[2], 'qemu_name')]:
            rmp = RemoteMemoryProtocol(self.rmem_tx_queue_name,
                                       self.rmem_rx_queue_name,
                                       self.avatar.queue, self)
        else:
            rmp = None

        self.protocols.set_all(gdb)
        self.protocols.gdb = gdb
        self.protocols.monitor = qmp
        self.protocols.remote_memory = rmp

        if gdb.remote_connect(port=self.gdb_port) and qmp.connect():
            self.log.info("Connected to remote target")
        else:
            self.log.warning("Connection to remote target failed")
        if rmp:
            rmp.connect()


        thread = None
        # Save a vm snapshot and get register values
        # thread = Thread(target=self.saveVMSnapshot, args=(qmp,gdb,))

        if self.interval == 10:
            # start a mutually exclusive thread with RMP
            thread = Thread(target=self.interrupt_injection, args=(qmp,self.interval))

        if thread:
            thread.daemon = True
            thread.start()




        self.wait()
