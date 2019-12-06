import angr
import claripy

"""
Take in program arguments and construct a SimulationManager
"""

"""
Determines what kind of input the program is expecting.
Either input from specfied arguments or from stdin
"""
import angr
def common_member(a,b):

    a_set = set(a)
    b_set = set(b)
    intersection = a_set.intersection(b_set)
    if len(intersection) > 0:
        return True
    return False


def detect(executable):

    stdin_functions = ['scanf','gets','read','fgets']
    binary_functions = []

    # Import executable
    p = angr.Project(executable,load_options={"auto_load_libs": False})

    """
    Generate Control Flow Graph (CFG)
    Knowledge Base(kb) Represents the artifacts of a project.
    Function Manager (functions) provides properties about a function

    A CFG can be better visualized in Radare2 Cutter
    """

    
    # Getting a list of all the function names
    cfg = p.analyses.CFGFast()
    
    print("[AEG +] Detecting Binary Functions")
    for items in cfg.kb.functions.items():
         # Stores function name into list
         binary_functions.append(str(items[1].name))
   
    print(*binary_functions, sep = " ")
    

    """
    loader: maps loaded binary objects to a single memory space
    main_object: memory of the main program (the main function)
    imports: maps symbol name to export symbols and registers the map to memory
    keys: identfies archtitecture and type of exectable

    binary_functions contains all functions in the executable 
    """
    
    binary_functions = p.loader.main_object.imports.keys()
    print("[AEG +] Looking for any STDIN Functions")
    print(*stdin_functions, sep = " ")

    # cross reference binary_functions and stdin_functions to determine what kind input the program is expecting
    # if it is a match, then its likley that the program uses STDIN
    print("[AEG +] Cross Reference Binary and STDIN functions")
    match = common_member(stdin_functions, binary_functions)
    if match:
        return "STDIN"
    return "ARGUMENT"


def create(executable,input_type):

    #load binary in angr
    p = angr.Project(executable,load_options={"auto_load_libs": False})

    class RandomHook(angr.SimProcedure):
        IS_FUNCTION = True
        def run(self):
            return 4
    
    """
    hook psudeocode:
        while(true):
            if(current address is hooked):
                Ignore(libc_function)
                run(hook)
    """
    # If our program runs into srand() or rand() during execution,
    # The hook makes sure both functions return a consistent value
    p.hook_symbol("rand",RandomHook())
    p.hook_symbol("srand",RandomHook())

    """
    hooks: replaces libc functions with a python function
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

    simgr = p.factory.simulation_manager(state,save_unconstrained=True)
    simgr.stashes['input_type'] = input_type
    simgr.stashes['mem_corrupt']  = []

    return simgr