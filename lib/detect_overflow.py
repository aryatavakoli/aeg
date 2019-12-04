import angr

def check_overflow(executable,input_type):
    """
     https://github.com/angr/angr-doc/blob/master/docs/loading.md

    SimProcedures: Map system calls to python functions will be using
    POSIX in this case

    """
    p = angr.Project(executable,load_options={"auto_load_libs": False})
