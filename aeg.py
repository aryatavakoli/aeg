"""
Sources:
https://docs.angr.io/extending-angr/simprocedures
https://docs.angr.io/built-in-analyses/cfg
https://github.com/angr/angr-doc/blob/master/docs/loading.md
https://github.com/angr/angr-doc/blob/master/CHEATSHEET.md
https://dev.to/denisnutiu/introduction-to-angr-kf8
https://web.wpi.edu/Pubs/E-project/Available/E-project-101816-114710/unrestricted/echeng_mqp_angr.pdf
https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/automated-exploit-development/buffer-overflows

Special Thanks:
Couldn't finish this project without Christopher Robert (@Sidragon1) resources
"""
import angr
import argparse
import IPython

from lib import create_simgr
from lib import overflow
import logging
def main() :
    print("[AEG +] Program Started")
    # Parse Arguments
    # https://docs.python.org/3/library/argparse.html
    parser = argparse.ArgumentParser(description='Generate Exploits for Overdlows & Format String Vulnerbilites')
    parser.add_argument('file', help='executable to Exploit')
    parser.add_argument('-v','--verbose',help="Enable Logging",action="store_true",default=False)
    arguments = parser.parse_args()
    
    if not arguments.verbose:
        logging.disable(logging.CRITICAL)

    executable = arguments.file
    
    print("[AEG +] " + "Executable " + str(executable) + " loaded")
    
    # Detect input type
    print("[AEG +] Checking Input Type")

    #create a map to store the properties of the executable
    input_type = create_simgr.detect(executable)

    print("[AEG +] " + "Executable " + str(executable) + " uses " + input_type + " Input Type")
    

    # Create Simulation Manager
    print("[AEG +] Create SimulationManager")
    simgr = create_simgr.create(executable,input_type)
    
    # Check for overflow
    print("[AEG +] Checking for" + str(simgr.stashes['input_type']) + "  Type Overflow")
    simgr.explore(step_func=overflow.detectSTDIN)


    # Detect Vulnerbility Mitigations
        # Grab any executable protection properties

    # Is there a simple win function? (An easy way to pwn a progam)

    # Exploit overflow or a format string

if __name__ == '__main__':
    main()