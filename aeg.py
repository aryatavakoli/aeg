import angr
import argparse
import logging

from lib import detect_input
from lib import create_simgr
from lib import detect_overflow
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
    executable_properties = {}
    input_type = detect_input.detect(executable)


    executable_properties['file'] = executable
    executable_properties['input_type'] = input_type
    print("[AEG +] " + "Executable " + str(executable) + " uses " + input_type + " Input Type")
    

    # Create Simulation Manager
    print("[AEG +] Create SimulationManager")
    simgr = create_simgr.create(executable,input_type)
    print(str(simgr))
    
    # Check for overflow
    print("[AEG +] Checking for Overflow Vulnerbility")
    executable_properties['check_overflow_type'] = detect_overflow.detect(simgr)


    # Detect Vulnerbility Mitigations
        # Grab any executable protection properties

    # Is there a simple win function? (An easy way to pwn a progam)

    # Exploit overflow or a format string

if __name__ == '__main__':
    main()