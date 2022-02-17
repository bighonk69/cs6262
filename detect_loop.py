import angr
import sys
import os

def load_trace(trace_log):
    trace = []
    with open(trace_log, 'rb') as fr:
        for line in fr:
            addr, opcode = line.rstrip().split(',')
            trace.append({"address":addr, "opcode":opcode})
    return trace

def dynamic_call_sequence(func_list, trace):
    sequence = []
    ##### For Students
    ##### fill this function to return the call sequence
    ##### using the instruction trace of executed malware
    #####
    return sequence


def find_loop(sequence):
    loop_sequence = []
    ### For Students
    ### Find the functions repetead in the loop
    ### The malware tries to communicate with C&C server
    ### Since the communication is forbidden, 
    ### malware keep trying to establish a connection
    ###
    return loop_sequence



def main():

    binary_path = sys.argv[1]
    if not os.path.exists(binary_path):
      print("Error: binary does not exist at %s" % binary_path)
      quit()
      
    proj = angr.Project(binary_path,
    use_sim_procedures=True,
    default_analysis_mode='symbolic',
    load_options={'auto_load_libs': False})

    proj.hook_symbol('lstrlenA', angr.SIM_PROCEDURES['libc']['strlen'])
    proj.hook_symbol('StrCmpNIA', angr.SIM_PROCEDURES['libc']['strncmp'])

    r2cfg = proj.analyses.Radare2CFGRecover()
    r2cfg._analyze(binary_path)

    flist = r2cfg.function_list()

    trace = load_trace('./instrace.linux.log')
    sequence = dynamic_call_sequence(flist, trace)

    loop = find_loop(sequence)
    print loop










if __name__ == "__main__":

  if(len(sys.argv) != 2):
    print("Usage: %s [target-program] " \
             % sys.argv[0])
    quit()
  main()
