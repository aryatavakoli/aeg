
import angr
import claripy

def detectSTDIN(simgr):
    print(simgr)
    if len(simgr.unconstrained):
        for path in simgr.unconstrained:
            state1 = path
            eip = state1.regs.pc
            state = state1.copy()
            constraints = []
            for i in range(8): #64bits/8
                curr_byte = eip.get_byte(i)
                constraint = claripy.And(curr_byte == 0x41)
                constraints.append(constraint)
            if state.satisfiable(extra_constraints=constraints):
                for c in constraints:
                    state.add_constraints(c)
                if state.satisfiable():
                    print("[AEG +] Vulnerable path found!")
                    print(str(path))
                    simgr.stashes['mem_corrupt'].append(path)
                simgr.stashes['unconstrained'].remove(path)
                simgr.drop(stash='active')
    return simgr

def exploit_overflow(binary_name):
    return 0