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


def detect_input_type(binary_name):

    stdin_functions = ['scanf','gets','read','fgets']
    binary_functions = []

    # Import binary
    p = angr.Project(binary_name,load_options={"auto_load_libs": False})

    """
    Generate Control Flow Graph (CFG) - https://docs.angr.io/built-in-analyses/cfg
    Knowledge Base(kb) Represents the artifacts of a project.
    Function Manager (functions) provides properties about a function

    A CFG can be better visualized in Radare2 Cutter
    """

    """
    # Getting a list of all the function names
    cfg = p.analyses.CFGFast()
    
    for items in cfg.kb.functions.items():
         # Stores function name into list
         binary_functions.append(str(items[1].name))
    print(*binary_functions, sep = "\n")
    """

    """
    loader: maps loaded binary objects to a single memory space
    main_object: memory of the main program (the main function)
    imports: maps symbol name to export symbols and registers the map to memory
    keys: identfies archtitecture and type of exectable

    binary_functions contains all functions in the executable 
    """
    
    binary_functions = p.loader.main_object.imports.keys()

    # cross reference binary_functions and stdin_functions to determine what kind input the program is expecting
    # if it is a match, then its likley that the program uses STDIN
    match = common_member(stdin_functions, binary_functions)
    if match:
        print("STDIN")
        return "STDIN"
    print("ARGUMENT")
    return "ARGUMENT"