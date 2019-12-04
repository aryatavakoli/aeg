"""
Sources:

https://github.com/angr/angr-doc/blob/master/docs/loading.md

https://github.com/angr/angr-doc/blob/master/CHEATSHEET.md

https://dev.to/denisnutiu/introduction-to-angr-kf8

https://web.wpi.edu/Pubs/E-project/Available/E-project-101816-114710/unrestricted/echeng_mqp_angr.pdf

"""

import angr
import claripy

def create(executable,input_type):

    #load binary in angr
    p = angr.Project(executable,load_options={"auto_load_libs": False})

    """
    SimProcedures: Map system calls to python functions will be using POSIX in this case
    factory: Provides access to path groups and symbolic execution results.
    full_init_state: calls each initializer function before execution reaches the entry point.
    args: a list of values to use as arguments to the program. May be mixed strings and bitvectors.
    globals: store arbitrary state data in a Map
    """

    """
    The executable (argv[0]) has to be passed as an argument
    Suppose input is now passed by arguments rather than by STDIN
    The program will have an additional argument-The program input (argv[1])
    Claripy allows the program input to be represented symbolically in a
    symbolic bitvector
    """
    argv = []
    argv_0 = executable    
    argv.append(argv_0)

    if input_type == "ARGUMENT":
        argv_1 = claripy.BVS("arg1", 256 * 8)
        argv.append(argv_1)
        state = p.factory.full_init_state(args=argv)
        # Store bitvector for program input into Map 
        state.globals['argv_1'] = argv_1
    else:
        # If input_type is STDIN only 
        state = p.factory.full_init_state(args=argv)

    state.globals['input_type'] = input_type
    print(str(state))
    simgr = p.factory.simulation_manager(state,save_unconstrained=True)
    
    return simgr