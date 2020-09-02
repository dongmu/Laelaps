from capstone import *
from capstone.arm  import *
from avatar2 import *

import logging
import itertools
from enum import Enum


logger = logging.getLogger(__name__)

# ========= For compatibility, do not use it! =========
class Alg_Enum(Enum):
    Explore_Single_Explore_All = 1

# ==================




# ========= Normal Step method =========
def stepfunc_normal(simgr):
    """
    """
    if len(simgr.active) > 1:
        # Sometimes simgr.step() sets pri_periph *and* gets diverge.
        if GV.pri_periph:
            GV.pri_periph = False
        return simgr
    elif len(simgr.active) == 0:
        logger.debug("Dead state?")
        return simgr

    state = simgr.active[0]
    hook_skip(state)

    if turn_to_qemu(state):
        simgr.stopToQemu = True

    return simgr


# ========= Global variables =========
class Firmware_Info():
    code = bytearray()
    rom_offset = 0

    @staticmethod
    def hookingcode(state):
        """
        return real address of this state
        """
        return Firmware_Info.code[state.addr - 1 - Firmware_Info.rom_offset:]


class GV():
    his_vec = []
    his_vec_full = False
    pmr = []
    global_v = []
    explore = False
    
    # global configurations -- TODO - temporary place
    pri_periph = False




def inMemoryRange(addr):
    """
    Determine whether an address is in the peripheral memory ranges
    """
    for mr in GV.pmr:
        if mr[0] <= addr <= mr[1]:
            return True
    return False





# ========= Settings =========
class Settings():
    """
    - Peripheral Memory Range Settings
    """

    his = 50
    depth = 1
    forward_depth = 3

    # optimization
    stopSign = {}
    stopToTurn = {}
    fixedPV = {}
    pauseForManualInput = {}
    manualPathSelection = {}
    

    # uart debug
    debug_port = None
    firmware_debug = open("./logfiles/debug.txt", "a")


def has_stopsign(state):
    """
    Reduce the effort to know the first instruction of a state.
    """
    return state_in_addrlist(state, Settings.stopSign)

def has_stoptoturn(state):
    """
    Stop angr and turn to qemu
    """
    return state_in_addrlist(state, Settings.stopToTurn)

def has_fixedPV(addr, pc):
    """
    fixedPV has two kinds:
    1. one pc for the same peripheral has a value
    2. all peripheral read are the same value
    """
    if addr in Settings.fixedPV:
        if isinstance(Settings.fixedPV[addr], dict):
            if pc in Settings.fixedPV[addr]:
                logger.debug("-------> pc: " + format(pc, "#04x") + ", addr: " + format(addr, "#04x"))
                return Settings.fixedPV[addr][pc]
        else:
            return Settings.fixedPV[addr]
    return None

def hasDeadloops(state, sm):
    """
    return states in a deadloop with the root state.
    """
    deadstates = []
    for s in sm.active:
        if detect_deadLoop(s, state):
            deadstates.append(s)
    return deadstates

def hasPauseForManualInput(state):
    """
    pause angr for manual input to choose path
    """
    return state_in_addrlist(state, Settings.pauseForManualInput)

def hasManualPathSelection():
    """
    determine whether we need to check the state
    """
    return Settings.manualPathSelection

def manualSelectState(sm, l):
    """
    Select a path according to a list
    """
    for state in sm.active:
        if state_in_addrlist(state, l):
            return state.addr
    return None

def state_in_addrlist(state, l):
    """
    Determine whether the instruction addresses of a state are in a list
    provided by ...
    """
    if not l:
        # empty list
        return False
    for addr in state.block().instruction_addrs:
        if addr in l:
            return True
    return False





# ========= Turn to Qemu =========
def turn_to_qemu(state):
    """
    Determine whether it should transfer to Qemu
    TODO -- This function has a potential problem:
            If a peripheral value needs a long path to be generated, transferring to Qemu early leads
            to a wrong value.
    """
    if GV.pri_periph:
        logger.debug('[+] transfering to qemu due to private_peripheral')
        GV.pri_periph = False
        return True

    if state.addr >= 0xffff0000:
        logger.debug('[+] transfering to qemu due to interrupt ret')
        return True

    if has_stoptoturn(state):
        logger.debug('[+] transfering to qemu due to stopToTurn')
        return True

    # long loop such as memcpy?
    if len(GV.global_v) != 0 and in_longloop():
        logger.debug('[+] transfering to qemu due to detected long loop')
        return True

    if hasMRS(state):
        logger.debug('[+] transfering to qemu due to MRS instruction')
        return True

    return False


def hasMRS(state):
    """
    Determine whether this state contains a MRS instruction
    """
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
    md.detail = True
    insns = md.disasm(Firmware_Info.hookingcode(state), state.addr - 1,
                      state.block(state.addr).instructions)
    # logger.debug("-cc-> insns length: " + format(state.block(state.addr).instructions, "#04x"))
    for insn in insns:
        # logger.debug("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
        if insn.id in [ARM_INS_MRS]:
            return True

    return False


def in_longloop():
    """Test last 20 his if they contain more than 5 repeated cycles
    """
    if not GV.his_vec_full:
        return False

    # logger.debug("utils.GV.his_vec[-20:]: " + repr(utils.GV.his_vec[-20:]))
    if repeatedSubstringCount(GV.his_vec[-20:]) >= 5:
        return True
    return False


def repeatedSubstringCount(source):
    """Look for the shortest substring which when repeated equals
       the source string, without any left over characters.
       Return the maximum repeat count, 1 if none found.
    """
    length = len(source)
    maxLoop = 1

    for x in range(1, length // 2 + 1):
        substr = source[0-x:]

        for y in range(length//len(substr), 1, -1):
            if source[:length - y * len(substr)] + substr * y == source:
                maxLoop = maxLoop if maxLoop > y else y

    return maxLoop





# ========= Similarity match =========
def similarity_with_his(his, states):
    # return highest indexes
    scores = []
    for s in states:
        if len(s) == 0:
            # lease likely to be choosen. max similarity
            scores.append(100)
            continue
        scores.append(similarity([entry.addr for entry in s], his))
    logger.debug('scores:' + repr(scores))
    return [i for i, j in enumerate(scores) if j == min(scores)]

def similarity(vec, his):
    """
    0-100, 0 is the lest similar; 100 is the most similar;
    100 is exclusive for definite loop/assert etc.
    this function returns 0-90 for others
    """
    repeated_n = 0
    joint_set = set(vec) & set(his)
    for x in vec + his:
        if x in joint_set:
            repeated_n += 1
    score = repeated_n / float(len(vec + his))
    score *= 90
    return round(score)

def record_hisPath(addr):
    """
    Record path to be compared in the future.
    """
    logger.debug("Record history Path: addr: " + format(addr, "#04x"))
    if len(GV.his_vec) != Settings.his:
        GV.his_vec.append(addr)
    else:
        GV.his_vec.pop(0)
        GV.his_vec.append(addr)
        GV.his_vec_full = True





# ========= Infinite loop detection =========
def detect_deadLoop(state1, state2):
    """
    Detect whether two states are in a (dead) loop.
    """
    _deadloop = False
    if sameBasicBlock(state1, state2):
        # logger.debug("-cc-> sameBasicBlock: state1.addr: " + format(state1.addr, "#04x") + "  state2.addr: " + format(state2.addr, "#04x"))
        if state1.addr == state2.addr:
            if isDeadLoop([state1, state2]):
                _deadloop = True
        elif state1.addr > state2.addr:
            tmp = advance(state2, state1.addr)
            if isDeadLoop([state1, tmp]):
                _deadloop = True
        else:
            tmp = advance(state1, state2.addr)
            if isDeadLoop([tmp, state2]):
                _deadloop = True

    return _deadloop


def isDeadLoop(states):
    # TODO -- need more thinking.
    if len(states) == 0 or len(states) == 1:
        return False
    for pair in itertools.combinations(range(len(states)), r=2):
        if same_state(states[pair[0]], states[pair[1]]):
            return True
    return False


def advance(s, addr):
    # todo: may have skipaale inst?
    # why not simgr?
    succ = s.step(size=addr - s.addr, opt_level=0)
    tmp = succ.successors[0]
    assert(tmp.addr == addr)
    return tmp


def sameBasicBlock(state1, state2):
    """
    Determine wheter two states are in a same basic block
    """
    if state1.addr == state2.addr:
        return True

    if state1.addr in state2.block().instruction_addrs or \
       state2.addr in state1.block().instruction_addrs:
        return True

    return False


def same_state(s0, s1):
    """
    Determine whether two states are equal.
    """
    # TODO -- Potential bugs
    # Angr bug. state may have symbolic ip when do state stepping
    if s0.regs.ip.symbolic or s1.regs.ip.symbolic:
        return False
    if s0.addr != s1.addr:
        return False
    return compare_state_regs(s0, s1)


def compare_state_regs(s0, s1):
    """
    Compare two states' concrete registers.
    Return True, if each concrete register value is equal.
    """
    regs0 = s0.regs
    regs1 = s1.regs

    if regs0.r0.concrete and regs1.r0.concrete and (s0.solver.eval(regs0.r0) != s1.solver.eval(regs1.r0)):
        logger.debug("s0r0 :" + format(s0.solver.eval(regs0.r0)) + "  s1r0: " + format(s1.solver.eval(regs1.r0)))
        return False
    if regs0.r1.concrete and regs1.r1.concrete and (s0.solver.eval(regs0.r1) != s1.solver.eval(regs1.r1)):
        logger.debug("s0r1 :" + format(s0.solver.eval(regs0.r1)) + "  s1r1: " + format(s1.solver.eval(regs1.r1)))
        return False
    if regs0.r2.concrete and regs1.r2.concrete and (s0.solver.eval(regs0.r2) != s1.solver.eval(regs1.r2)):
        logger.debug("s0r2 :" + format(s0.solver.eval(regs0.r2)) + "  s1r2: " + format(s1.solver.eval(regs1.r2)))
        return False
    if regs0.r3.concrete and regs1.r3.concrete and (s0.solver.eval(regs0.r3) != s1.solver.eval(regs1.r3)):
        logger.debug("s0r3 :" + format(s0.solver.eval(regs0.r3)) + "  s1r3: " + format(s1.solver.eval(regs1.r3)))
        return False
    if regs0.r4.concrete and regs1.r4.concrete and (s0.solver.eval(regs0.r4) != s1.solver.eval(regs1.r4)):
        logger.debug("s0r4 :" + format(s0.solver.eval(regs0.r4)) + "  s1r4: " + format(s1.solver.eval(regs1.r4)))
        return False
    if regs0.r5.concrete and regs1.r5.concrete and (s0.solver.eval(regs0.r5) != s1.solver.eval(regs1.r5)):
        logger.debug("s0r5 :" + format(s0.solver.eval(regs0.r5)) + "  s1r5: " + format(s1.solver.eval(regs1.r5)))
        return False
    if regs0.r6.concrete and regs1.r6.concrete and (s0.solver.eval(regs0.r6) != s1.solver.eval(regs1.r6)):
        logger.debug("s0r6 :" + format(s0.solver.eval(regs0.r6)) + "  s1r6: " + format(s1.solver.eval(regs1.r6)))
        return False
    if regs0.r7.concrete and regs1.r7.concrete and (s0.solver.eval(regs0.r7) != s1.solver.eval(regs1.r7)):
        logger.debug("s0r7 :" + format(s0.solver.eval(regs0.r7)) + "  s1r7: " + format(s1.solver.eval(regs1.r7)))
        return False
    if regs0.r8.concrete and regs1.r8.concrete and (s0.solver.eval(regs0.r8) != s1.solver.eval(regs1.r8)):
        logger.debug("s0r8 :" + format(s0.solver.eval(regs0.r8)) + "  s1r8: " + format(s1.solver.eval(regs1.r8)))
        return False
    if regs0.r9.concrete and regs1.r9.concrete and (s0.solver.eval(regs0.r9) != s1.solver.eval(regs1.r9)):
        logger.debug("s0r9 :" + format(s0.solver.eval(regs0.r9)) + "  s1r9: " + format(s1.solver.eval(regs1.r9)))
        return False
    if regs0.r10.concrete and regs1.r10.concrete and (s0.solver.eval(regs0.r10) != s1.solver.eval(regs1.r10)):
        logger.debug("s0r10 :" + format(s0.solver.eval(regs0.r10)) + "  s1r10: " + format(s1.solver.eval(regs1.r10)))
        return False
    if regs0.r11.concrete and regs1.r11.concrete and (s0.solver.eval(regs0.r11) != s1.solver.eval(regs1.r11)):
        logger.debug("s0r11 :" + format(s0.solver.eval(regs0.r11)) + "  s1r11: " + format(s1.solver.eval(regs1.r11)))
        return False
    if regs0.r12.concrete and regs1.r12.concrete and (s0.solver.eval(regs0.r12) != s1.solver.eval(regs1.r12)):
        logger.debug("s0r12 :" + format(s0.solver.eval(regs0.r12)) + "  s1r12: " + format(s1.solver.eval(regs1.r12)))
        return False
    if regs0.r13.concrete and regs1.r13.concrete and (s0.solver.eval(regs0.r13) != s1.solver.eval(regs1.r13)):
        logger.debug("s0r13 :" + format(s0.solver.eval(regs0.r13)) + "  s1r13: " + format(s1.solver.eval(regs1.r13)))
        return False
    if regs0.r14.concrete and regs1.r14.concrete and (s0.solver.eval(regs0.r14) != s1.solver.eval(regs1.r14)):
        logger.debug("s0r14 :" + format(s0.solver.eval(regs0.r14)) + "  s1r14: " + format(s1.solver.eval(regs1.r14)))
        return False
    if regs0.r15.concrete and regs1.r15.concrete and (s0.solver.eval(regs0.r15) != s1.solver.eval(regs1.r15)):
        logger.debug("s0r15 :" + format(s0.solver.eval(regs0.r15)) + "  s1r15: " + format(s1.solver.eval(regs1.r15)))
        return False
    return True


def stateInStateList(state, states):
    # states is a list of states different from each other
    # state is compared with states
    if state is not None:
        for s in states:
            if same_state(s, state):
                return True
    return False


# ========= Hook system instructions, which angr cannot handle =========
def hook_skip(state):
    """
    Hook the code, which angr cannot handle, to be skipped
    """
    if state.addr >= 0xffff0000:
        logger.debug('Interrupt place, No hook, return directly')
        return
    for skipable_ins in disas_gethooks(Firmware_Info.hookingcode(state), state.addr - 1,
                                       state.block(state.addr).instructions):
        if not state.project.is_hooked(skipable_ins[0]):
            state.project.hook(skipable_ins[0], do_nothing, length=skipable_ins[1])


def do_nothing(state):
    logger.debug("[+] skipped instruction")
    logger.debug("[+] state.addr: " + format(state.addr, "#04x"))
    pass


def arm_branch(insn):
    #normal branch
    if insn.id in (ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX, ARM_INS_BXJ, ARM_INS_B, ARM_INS_CBZ, ARM_INS_CBNZ):
        return True
    #pop pc
    if insn.id in (ARM_INS_POP,):
        for i in insn.operands:
            if 'pc' == insn.reg_name(i.value.reg):
                return True
    #mov/add/sub pc
    if insn.id in (ARM_INS_MOV, ARM_INS_ADD, ARM_INS_SUB):
        if 'pc' == insn.reg_name(insn.operands[0].value.reg):
            return True
    return False

def canskip(insn):
    # no operands -> can be skipped?
    if insn.id in [ARM_INS_IT]:
        return False
    if insn.id in [ARM_INS_MRS] and GV.explore:
        # TODO -- Potential bugs
        logger.debug("skipped ins: 0x%x:\t%s\t%s -- Exploring" % (insn.address, insn.mnemonic, insn.op_str))
        return True
    if len(insn.operands) == 0 and insn.id != ARM_INS_NOP:
        logger.debug("skipped ins: 0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
        return True
    if insn.id in (ARM_INS_MSR, ARM_INS_BKPT):
        logger.debug("skipped ins: 0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
        return True
    return False

def combine_adjacent_ins(r):
    ret = []
    for ent in r:
        if len(ret) == 0:
            ret.append(ent)
            continue

        if ret[-1][0] + ret[-1][1] == ent[0]:
            ret[-1][1] += ent[1]
        else:
            ret.append(ent)
    return ret

def disas_gethooks(code, addr, length):
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_MCLASS)
    md.detail = True
    l = 0
    r = []
    for insn in md.disasm(code, addr, length):
        # logger.debug("0x%x:\t%s\t%s" %(insn.address, insn.mnemonic, insn.op_str))
        if canskip(insn):
            # logger.debug("can skip at " + format(addr + l, '#04x') + " size: " + format(insn.size))
            r.append([addr + l + 1, insn.size])
        l += insn.size
        if arm_branch(insn):
            break

    ret = combine_adjacent_ins(r)
    return ret




# ========= Utility functions =========
def log_realPath(angrPath):
    """
    Log the addr of each state in the path.
    """
    real_path = open("./logfiles/real_path.txt", "a")
    for path in angrPath:
        real_path.write(path + '\n')
    real_path.flush()
    real_path.close()



def history_states(state):
    """
    return state's history, i.e., a list of states 
    """
    ret = []
    his = state.history.parent
    while his.depth != 0:
        ret.insert(0, his.state)
        his = his.parent
    ret.insert(0, his.state)
    return ret


def arrary_to_dict(regs, pc):
    d = {'r0': regs[0], 'r1': regs[1], 'r2': regs[2], 'r3': regs[3], 'r4': regs[4],
         'r5': regs[5], 'r6': regs[6], 'r7': regs[7], 'r8': regs[8], 'r9': regs[9],
         'r10': regs[10], 'r11': regs[11], 'r12': regs[12], 'r13': regs[13], 'r14': regs[14],
         'r15': pc | 1 , 'sp': regs[13], 'lr': regs[14], 'pc': pc | 1, 'cpsr': regs[16]}
    return d



def get_registers(rr):
    all_regs = ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7', 'r8',
                'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc', 'cpsr']
    d = {}
    for r in all_regs:
        d[r] = rr(r)
        if r == 'pc':
            d[r] = d[r] | 1

    return d

