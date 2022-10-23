import pickle
from pickletools import genops, opcodes, OpcodeInfo


def eval_exec_attack(pickle, attack_str, attack_index, out_file):
    """
    Injects a string that is presumed to have an attack exec statement
    """

    import pdb
    opcode, arg, pos, end_pos = genops(pickle)
    pdb.set_trace()