"""
Sources:
https://github.com/angr/angr-doc/blob/master/examples/insomnihack_aeg/solve.py
https://breaking-bits.gitbook.io/breaking-bits/vulnerability-discovery/automated-exploit-development/buffer-overflows
"""

import angr
import claripy

def detect(simgr):
    return 0