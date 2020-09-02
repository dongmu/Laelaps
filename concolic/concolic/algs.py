
from concolic.utils import *

logger = logging.getLogger(__name__)



class AlgEnum(Enum):
    AlgorithmSet1 = 1



# ========= Algorithm entry method =========
def algorithm(root_state, simgr, alg, proj, cpsr):
    if alg == AlgEnum.AlgorithmSet1 or alg == Alg_Enum.Explore_Single_Explore_All:
        return AlgSet1(root_state, simgr, alg, proj, cpsr)



class Alg():
    def __init__(self, root_state, simgr, alg, proj, cpsr):
        self.root_state = root_state
        self.sm = simgr
        self.alg = alg
        self.proj = proj
        self.cpsr = cpsr


    def process(self):
        if hasPauseForManualInput(self.root_state):
            # manual input to select a path
            class Dummy:
                branch = 0
            dummy = Dummy()
            logger.info('manually choose a path: (take a while to load terminal, ctrl+d after input)')
            logger.info('Hint: dummy.branch=')
            import IPython; IPython.embed()
            return dummy.branch


        if hasManualPathSelection():
            # manual selected path
            selection = manualSelectState(self.sm, Settings.manualPathSelection)
            if not selection:
                logger.debug("Manual selection: " + format(selection, "#04x"))
                return selection

        # Dead loop detection
        deadstates = hasDeadloops(self.root_state, self.sm)
        if len(self.sm.active) - len(deadstates) == 1:
            return (set(self.sm.active)-set(deadstates)).pop().addr

        return False



class AlgSet1(Alg):
    """
    Algorithm set 1
    """
    def __init__(self, root_state, simgr, alg, proj, cpsr):
        Alg.__init__(self, root_state, simgr, alg, proj, cpsr)

    def process(self):
        quickret = super().process()
        if quickret:
            return quickret

        GV.explore = True
        
        ret = self.explore_state(self.root_state)

        GV.explore = False
        return ret


    def _filter_loop(self, state):
        bucket = history_states(state)
        if stateInStateList(state, bucket):
            logger.debug('loop detected .. move to loop')
            return True
        return False

    def _filter_intret(self, state):
        if state.addr >= 0xffff0000:
            logger.debug('interrupt ret .. assume high priority, thus regard as diverge, mov to intret')
            return True
        return False

    def _filter_stopsign(self, state):
        if has_stopsign(state):
            logger.debug('stopSign detected .. move to stopsign')
            return True
        return False


    def stepfunc_filterstate(self, sm):
        for state in sm.active:
            hook_skip(state)

        assert(len(sm.active) != 0), "empty sm?"
        sm.move(from_stash='active', to_stash='loop', filter_func=self._filter_loop)
        sm.move(from_stash='active', to_stash='intret', filter_func=self._filter_intret)
        sm.move(from_stash='active', to_stash='stopsign', filter_func=self._filter_stopsign)

        if len(sm.active) != 0 and sm.active[0].history.depth > Settings.forward_depth:
            sm.move(from_stash='active', to_stash='candidates')

        return sm


    def handle_stash(self, sm):
        for s in sm.stashes['loop']:
            # bucket = history_states(s)
            # bucket.append(s)
            # logger.debug('loop: ' + repr(bucket))
            sm.ret.append([])

        for s in sm.stashes['stopsign']:
            sm.ret.append([])

        for s in sm.stashes['intret']:
            bucket = history_states(s)
            bucket.append(s)
            logger.debug('int ret: ' + repr(bucket))
            sm.ret.append(bucket)

        for s in sm.stashes['candidates']:
            bucket = history_states(s)
            bucket.append(s)
            logger.debug('candidates path: ' + repr(bucket))
            sm.ret.append(bucket)


    def explore_state(self, state):
        """
        Explore the root state to find the suitable path
        """
        # only hook skipable_ins for the init state. Others will be hooked by step_function
        hook_skip(state)

        state.history.depth = 0

        sm = self.proj.factory.simgr(state)

        sm.ret = []

        logger.debug("[+] Exploring " + format(state.addr, "#04x"))

        sm.run(step_func=self.stepfunc_filterstate, opt_level=0)
        self.handle_stash(sm)

        candidate_path_list = sm.ret

        # ======================================
        # check similarity with GV.his_vec
        min_scores = similarity_with_his(GV.his_vec, candidate_path_list)


        addrs = []
        for i in min_scores:
            if candidate_path_list[i][1].addr not in addrs:
                addrs.append(candidate_path_list[i][1].addr);

        if len(addrs) == 1:
            logger.debug("[+] select " + format(addrs[0]) + " due to similarity check")
            return addrs[0]
        else:
            addrs = sorted(addrs)

        # ======================================
        # Fall-back: default: the higher address
        # for interrupts, we choose lower address because we want to handle all cases

        # last 9 bits for interrupt number. 16 is for the first peripheral
        # if 0x000022A8 <= addrs[index[0]] <= 0x000027B2:
        if self.cpsr & 0x01FF >= 16: # interrupt is true
            logger.debug("[+] select " + format(addrs[0], "#04x") + " due to lower addr (in interrupt)")
            return addrs[0]
        else:
            logger.debug("[+] select " + format(addrs[-1], "#04x") + " due to higher addr")
            return addrs[-1]


