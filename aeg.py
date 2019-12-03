import angr
import argparse
import logging

from lib import detect_input
def main() :
    # Parse Arguments
    # https://docs.python.org/3/library/argparse.html
    parser = argparse.ArgumentParser(description='Generate Exploits for Overdlows & Format String Vulnerbilites')
    parser.add_argument('file', help='Binary to Exploit')
    parser.add_argument('-v','--verbose',help="Enable Logging",action="store_true",default=False)
    arguments = parser.parse_args()

    if arguments.file is None:
        print("[AEG -] No Binary File Specficed")
        exit(1)
    
    if arguments.verbose:
        logging.disable(logging.CRITICAL)
    
    print("[AEG +] Checking Input Type")

    #create a map to store the properties of the binary
    binary_properties = {}
    binary_properties['file'] = arguments.file
    binary_properties['input_type'] = detect_input.detect_input_type(arguments.file)
    print(binary_properties['input_type'])
    # Detect Vulnerbility Type


    # Detect Vulnerbility Mitigations
        # Grab any binary protection properties

    # Is there a simple win function? (An easy way to pwn a progam)

    # Is it an exploit overflow or a format string

if __name__ == '__main__':
    main()