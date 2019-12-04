import angr
import argparse
import logging

from lib import detect_input
from lib import detect_overflow
def main() :
    # Parse Arguments
    # https://docs.python.org/3/library/argparse.html
    parser = argparse.ArgumentParser(description='Generate Exploits for Overdlows & Format String Vulnerbilites')
    parser.add_argument('file', help='executable to Exploit')
    parser.add_argument('-v','--verbose',help="Enable Logging",action="store_true",default=False)
    arguments = parser.parse_args()

    executable = arguments.file

    if executable is None:
        print("[AEG -] No executable Specficed")
        exit(1)
    
    if not arguments.verbose:
        logging.disable(logging.CRITICAL)
    
    print("[AEG +] " + "Executable " + str(executable) + " loaded")
    
    # Detect input type
    print("[AEG +] Checking Input Type")

    #create a map to store the properties of the executable
    executable_properties = {}
    input_type = detect_input.detect_input_type(executable)


    executable_properties['file'] = executable
    executable_properties['input_type'] = input_type
    print("[AEG +] " + "Executable " + str(executable) + " uses " + input_type + " Input Type")
    
    # Detect Vulnerbility Type
    print("[AEG +] Checking for Overflow Vulnerbility")
    executable_properties['vul_type'] = detect_overflow.check_overflow(executable,input_type)


    # Detect Vulnerbility Mitigations
        # Grab any executable protection properties

    # Is there a simple win function? (An easy way to pwn a progam)

    # Exploit overflow or a format string

if __name__ == '__main__':
    main()