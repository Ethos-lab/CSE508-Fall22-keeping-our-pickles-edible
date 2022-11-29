from distutils.command.config import config
import pickle
from pickletools import genops, opcodes, OpcodeInfo
import builtins
import collections
import inspect
import io
import logging
import pickle
import torch
import os


class Detector():
    def __init__(self, config_path, allowlist_file, safeclass_file):
        allowlist_file_path = os.path.join(config_path, allowlist_file)
        allowlist_file_data = open(allowlist_file_path).read()

        safeclass_file_path = os.path.join(config_path, safeclass_file)
        safeclass_file_data = open(safeclass_file_path).read()

        self._ALLOWLIST = allowlist_file_data.split('\n')
        self._SAFECLASS = safeclass_file_data.split('\n')

    def exists_attack(self, file_data):
        """
        Params:
            file_data: file object to perform detection on.

        Returns:
            Bool: If true, will return the specific argument that is called.

        Just prints if the file seems to be safe or unsafe.
        """
        proto = self.get_protocol(self, file_data)
        if proto < 4:
            return self._exists_attack_proto2(file_data)
        else:
            return self._exists_attack_proto4(file_data)

    def _exists_attack_proto2(self, file_data):
        """
        Params:
            file_data: file object to perform detection on.

        Returns:
            Bool: If true, will return the specific argument that is called.

        Just prints if the file seems to be safe or unsafe.
        """
        current_pointer = file_data.tell()
        file_data.seek(0)
        for info, arg, pos in genops(file_data):
            if info.name == 'GLOBAL':
                arg = arg.replace(' ', '.')
                if arg not in self._ALLOWLIST:
                    file_data.seek(current_pointer)
                    return True, arg

        else:
            file_data.seek(current_pointer)
            return False

    def _exists_attack_proto4(self, file_data, previous_pos=-1):
        """
        Params:
            file_data: A file object for the pickle file

        Returns:
               True if attack exists in protocol version 4 of pickle file, False otherwise

        """
        possible_attack_flag = False

        second_prev_binuni_data = {}
        first_prev_binuni_data = {}

        current_pointer = file_data.tell()
        file_data.seek(0)

        for info, arg, pos in genops(file_data):

            if pos < previous_pos:
                continue

            # Every STACK_GLOBAL requires it to be preceded by 2 BINUNICODE or SHORT_BINUNICODE opcodes
            if info.name == 'BINUNICODE' or info.name == 'SHORT_BINUNICODE':
                second_prev_binuni_data = first_prev_binuni_data
                first_prev_binuni_data = {'info': info, 'arg': arg, 'pos': pos}

                # Both are non-empty indicates a possible STACK_GLOBAL call, malicious code
                if len(second_prev_binuni_data) > 0 and len(first_prev_binuni_data) > 0:
                    possible_attack_flag = True
            # print({'info':info, 'arg': arg, 'pos':pos})

            elif info.name == 'STACK_GLOBAL' and possible_attack_flag:
                combined_arg = second_prev_binuni_data['arg'] + ' ' + first_prev_binuni_data['arg']
                combined_arg = combined_arg.replace(' ', '.')

                # Check if combined_arg is in whitelist or not to confirm about the attack
                if combined_arg not in self._ALLOWLIST:
                    file_data.seek(current_pointer)
                    return True, combined_arg
                else:
                    possible_attack_flag = False

        file_data.seek(current_pointer)
        return False

    def detect_pickle_safe_class(self, className) -> bool:
        """
            Placeholder. Not implemented yet. 
        """

        if className not in self._SAFECLASS:
            return False
        return True

    # considering non-nested attacks only

    def find_next_binput(self, file_data, start_pos):

        current_pointer = file_data.tell()
        file_data.seek(0)
        for info, arg, pos in genops(file_data):
            if pos < start_pos:
                continue
            if info.name == 'BINPUT':
                file_data.seek(current_pointer)
                return {'info': info, 'pos': pos, 'arg': arg}
            if info.name == 'LONG_BINPUT':
                file_data.seek(current_pointer)
                return {'info': info, 'pos': pos, 'arg': arg}
        file_data.seek(current_pointer)
        return {'info': None, 'pos': 1000000000000, 'arg': 1000000000000}

    def _find_previous_memoize(self, file_data, end_pos):
        
        current_pointer = file_data.tell()
        file_data.seek(0)

        memoize_counter = 0
        memoize_data_dict = {'info': None, 'pos': 0, 'arg': 0}
        
        for info, arg, pos in genops(file_data):

            if pos > end_pos:
                break

            if info.name == 'MEMOIZE':
                memoize_data_dict = {'info': info, 'arg': memoize_counter, 'pos': pos}
                memoize_counter += 1
                
        file_data.seek(current_pointer)
        return memoize_data_dict

    def _find_next_memoize(self, file_data, start_pos):
        current_pointer = file_data.tell()
        file_data.seek(0)

        count_memoize = 0
        for info, arg, pos in genops(file_data):

            if pos < start_pos:
                if info.name == 'MEMOIZE':
                    count_memoize += 1
                continue

            if info.name == 'MEMOIZE':
                file_data.seek(current_pointer)
                return {'info': info, 'pos': pos, 'arg': count_memoize}

        file_data.seek(current_pointer)
        return {'info': None, 'pos': 1000000000000, 'arg': 1000000000000}

    def get_protocol(self, file_data):
        protocol = 0

        current_pointer = file_data.tell()
        file_data.seek(0)

        for info, arg, pos in genops(file_data):
            if info.name == 'PROTO':
                protocol = arg
        file_data.seek(current_pointer)
        return protocol

    def get_global_reuse_data(self, file_data, proto=2):
        if proto < 4:
            return self._global_reuse_data_proto2(file_data)
        else:
            return self._global_reuse_data_proto4(file_data)

    def _global_reuse_data_proto2(self, file_data):
        """
        Params:
            file_data: The file object of the current pickle file

        Returns:
            Dict containing the indices as key and global opcode data as value and
            The protocol version number

        This function check for the possible global reuse attacks and stores the BINGET(those reuse calls)
        with the appropriate global calls along with its argument.
  
          """

        # To keep track of the global call and the immediate next BINPUT
        global_reuse_flag = False

        current_pointer = file_data.tell()
        file_data.seek(0)

        global_reuse_dict = dict()
        # To store the memo index and the global data at that particular index, in order to check for global reuse attack

        for info, arg, pos in genops(file_data):

            if info.name == 'GLOBAL':
                arg = arg.replace(' ', '.')

            if info.name == 'GLOBAL' and arg not in self._ALLOWLIST:
                global_reuse_flag = True
                # Set flag to true indicating if the next opcode is BINPUT then global call can be reused later
                global_data = {"info": info, "arg": arg}

            elif global_reuse_flag and (info.name == 'BINPUT ' or info.name == 'LONG_BINPUT'):
                global_reuse_flag = False
                # The next opcode is indeed BINPUT and store the global data at that particular argument index,
                # in order to check for global reuse attack
                global_reuse_dict[arg] = global_data

            else:

                # If anything other than BINPUT is encountered then reset the flag
                global_reuse_flag = False

        file_data.seek(current_pointer)

        return global_reuse_dict

    def _global_reuse_data_proto4(self, file_data):
        possible_global_flag = False
        global_reuse_flag = False

        global_reuse_dict = {}

        second_prev_binuni_data = {}
        first_prev_binuni_data = {}

        current_pointer = file_data.tell()
        file_data.seek(0)

        for info, arg, pos in genops(file_data):

            # Every STACK_GLOBAL requires it to be preceded by 2 BINUNICODE or SHORT_BINUNICODE opcodes
            if info.name == 'BINUNICODE' or info.name == 'SHORT_BINUNICODE':
                second_prev_binuni_data = first_prev_binuni_data
                first_prev_binuni_data = {'info': info, 'arg': arg, 'pos': pos}

                # Both are non-empty indicates a possible STACK_GLOBAL call, malicious code
                if len(second_prev_binuni_data) > 0 and len(first_prev_binuni_data) > 0:
                    possible_global_flag = True

            elif info.name == 'STACK_GLOBAL' and possible_global_flag:
                combined_arg = second_prev_binuni_data['arg'] + ' ' + first_prev_binuni_data['arg']
                combined_arg = combined_arg.replace(' ', '.')

                # Check if combined_arg is in whitelist or not to confirm about the attack
                if combined_arg not in self._ALLOWLIST:
                    global_reuse_flag = True
                    global_data = {'info': info, 'arg': combined_arg}
                else:
                    possible_global_flag = False
                    
            elif global_reuse_flag and (info.name == 'MEMOIZE'):
                global_reuse_flag = False
                memoize_dict = self._find_next_memoize(file_data, pos)
                # The next opcode is indeed BINPUT and store the global data at that particular argument index,
                # in order to check for global reuse attack
                global_reuse_dict[memoize_dict['arg']] = global_data
                
            else:
                # If anything other than BINPUT is encountered then reset the flag
                global_reuse_flag = False

        file_data.seek(current_pointer)
        return global_reuse_dict

    def exists_nested_attack(self, file_data, global_reuse_dict, previous_pos=-1, proto=2):
        if proto < 4:
            return self._exists_nested_attack_proto2(file_data, global_reuse_dict, previous_pos)
        else:
            return self._exists_nested_attack_proto4(file_data, global_reuse_dict, previous_pos)

    def _exists_nested_attack_proto2(self, file_data, global_reuse_dict, previous_pos):
        """
        Params:
            file_data: The file object of the current pickle file
            global_reuse_dict: To look for BINGETS reusing malicious GLOBAL calls
            previous_pos(int, optional): Defaults to -1. A pointer to check for the required opcodes after it.

        Returns:
            True if the file has nested attacks present, False otherwise.

        """
        # global_flag = False
        # global_reuse_flag = False

        current_pointer = file_data.tell()
        file_data.seek(0)

        global_nested_stack = []
        # global_nested_stack will contain data as soon as a global call in encountered,
        # this will help to check if nested attacks exists

        for info, arg, pos in genops(file_data):

            if pos <= previous_pos:
                continue

            # print(info.name)

            if info.name == 'GLOBAL':
                arg = arg.replace(' ', '.')

            if len(global_nested_stack) == 0 and info.name == 'GLOBAL' and arg not in self._ALLOWLIST:
                global_nested_stack.append(info.arg)

            elif len(global_nested_stack) == 0 and info.name == 'BINGET' and arg in global_reuse_dict.keys():
                # The way we check for global calls, simply also check for BINGET references which might reuse the previous
                # global calls
                global_nested_stack.append(global_reuse_dict[arg]["arg"])

            # If REDUCE is encountered before the next GLOBAL then that attack does not have attacks nested in it, so continue checking
            elif len(global_nested_stack) >= 1 and info.name == 'REDUCE':
                global_nested_stack.pop()

            elif len(global_nested_stack) >= 1 and info.name == 'BINGET' and arg in global_reuse_dict.keys():
                file_data.seek(current_pointer)
                return True

            elif len(global_nested_stack) >= 1 and info.name == 'GLOBAL' and arg not in self._ALLOWLIST:
                file_data.seek(current_pointer)
                return True

        file_data.seek(current_pointer)
        return False

    def _exists_nested_attack_proto4(self, file_data, global_reuse_dict, previous_pos = -1):
        """
        Params:
            file_data: The file object of the current pickle file
            global_reuse_dict: To look for BINGETS reusing malicious GLOBAL calls
            previous_pos(int, optional): Defaults to -1. A pointer to check for the required opcodes after it.

        Returns:
            True if the file has nested attacks present, False otherwise.

        """
        current_pointer = file_data.tell()
        file_data.seek(0)
        
        possible_attack_flag = False
        attack_end_flag = False

        second_prev_binuni_data = {}
        first_prev_binuni_data = {}

        bef_attack_memo_arg = None
        
        global_nested_stack = []
        # Global_nested_stack will contain the sub_list opcode data and bef_attack_memo

        for info, arg, pos in genops(file_data):

            # Every STACK_GLOBAL requires it to be preceded by 2 BINUNICODE or SHORT_BINUNICODE opcodes
            if info.name == 'BINUNICODE' or info.name == 'SHORT_BINUNICODE':
                second_prev_binuni_data = first_prev_binuni_data
                first_prev_binuni_data = {'info': info, 'arg': arg, 'pos': pos}
                
                # Both are non-empty indicates a possible STACK_GLOBAL call, malicious code
                if len(second_prev_binuni_data) > 0 and len(first_prev_binuni_data) > 0:
                    possible_attack_flag = True
                # print({'info':info, 'arg': arg, 'pos':pos})

            elif info.name == 'STACK_GLOBAL' and possible_attack_flag:
                combined_arg = second_prev_binuni_data['arg'] + ' ' + first_prev_binuni_data['arg']
                combined_arg = combined_arg.replace(' ', '.')

                if combined_arg not in self._ALLOWLIST:
                    
                    if len(global_nested_stack) >= 1:
                        file_data.seek(current_pointer)
                        return True
                    
                    stack_global_data = {'info': info, 'arg': arg, 'pos': pos}
                    
                    # Create a list containing first and second BINUNI calls and current STACK GLOBAL data
                    temp_list_data = [second_prev_binuni_data, first_prev_binuni_data, stack_global_data]
                    global_nested_stack.append([temp_list_data, bef_attack_memo_arg])
                    
                    # Reset the first prev and second prev binuni data dicts
                    second_prev_binuni_data = {}
                    first_prev_binuni_data = {}

                possible_attack_flag = False

            elif info.name == 'BINGET' and arg in global_reuse_dict.keys() and possible_attack_flag:
                combined_arg = second_prev_binuni_data['arg'] + ' ' + first_prev_binuni_data['arg']
                combined_arg = combined_arg.replace(' ', '.')

                if combined_arg not in self._ALLOWLIST:
                    
                    if len(global_nested_stack) >= 1:
                        file_data.seek(current_pointer)
                        return True
                    
                    global_reuse_data = global_reuse_dict[arg]
                    stack_global_data = {'info': global_reuse_data['info'], 'arg': global_reuse_data['arg'], 'pos': pos}
                    
                    # Create a list containing first and second BINUNI calls and current STACK GLOBAL data
                    temp_list_data = [second_prev_binuni_data, first_prev_binuni_data, stack_global_data]
                    global_nested_stack.append([temp_list_data, bef_attack_memo_arg])
                    
                    # Reset the first prev and second prev binuni data dicts
                    second_prev_binuni_data = {}
                    first_prev_binuni_data = {}

                possible_attack_flag = False

            elif len(global_nested_stack) >= 1 and info.name == 'REDUCE':
                reduce_data = {"info": info, "arg": arg, "pos": pos}
                
                attack_end_flag = True
                temp_list_data = global_nested_stack.pop()
                
                # Attack is complete so remove from global stack
                
        file_data.seek(current_pointer)
        
        return False
    # End of function

    def get_nested_attack_data(self, data_bytearray, file_data, global_reuse_dict, proto=2):
        if proto < 4:
            return self._get_nested_attack_data_proto2(data_bytearray, file_data, global_reuse_dict)
        else:
            return self._get_nested_attack_data_proto4(data_bytearray, file_data, global_reuse_dict)

    def _get_nested_attack_data_proto2(self, data_bytearray, file_data, global_reuse_dict):
        """
        Params:
            data_bytearray: To check for the POP after REDUCE opcode
            file_data: A file object for the pickle file
            global_reuse_dict: A dictionary containing the binget arguments where global calls are being reused

        Returns:
            nested_mal_opcode_data: A list containing the information about the nested attack calls.
               The global opcode (info, arg, pos), reduce opcode (info, arg, pos), and the memo ids
              used beforeand after the attack the elements of each list. There can be multiple such lists
            in nested_mal_opcode_data.

        """
        # global_flag = False
        # reduce_flag = False
        attack_end_flag = False
        # global_reuse_flag = False
        # To flag all the possible attacks that reuse the global opcode using BINGET

        bef_attack_binput_arg = 0
        aft_attack_binput_arg = 0

        nested_mal_opcode_data = []
        # Final list containing the data about the nested attack
        global_nested_stack = []
        # Global_nested_stack will contain the global opcode data and bef_attack_binput_arg
        nested_attack_stack = []
        # Nested_attack_stack will contain the global, reduce data and bef_attack_binput_arg

        current_pointer = file_data.tell()
        file_data.seek(0)

        for info, arg, pos in genops(file_data):

            if info.name == 'GLOBAL':
                arg = arg.replace(' ', '.')

            if info.name == 'BINPUT' or info.name == 'LONG_BINPUT':
                bef_attack_binput_arg = arg

                # If we have a complete attack(indicated by attack_end_flag) then check to store the first BINPUT after the attack
                if attack_end_flag:
                    # First binput after the attack is found
                    # Use data_bytearray to detect pop and binput
                    if info.name == 'BINPUT':

                        if data_bytearray[pos + 2:pos + 3] == bytearray(b'0'):
                            binput_dict = self.find_next_binput(file_data, pos + 3)
                            aft_attack_binput_arg = binput_dict['arg']

                        else:
                            aft_attack_binput_arg = arg
                    else:

                        if data_bytearray[pos + 5:pos + 6] == bytearray(b'0'):
                            binput_dict = self.find_next_binput(file_data, pos + 6)
                            aft_attack_binput_arg = binput_dict['arg']

                        else:
                            aft_attack_binput_arg = arg

                    # global_flag = False
                    # reduce_flag = False
                    temp_list_data = nested_attack_stack.pop()
                    if len(global_nested_stack) == 0:
                        # No further nesting inside this attack, so push it into the nested_mal_opcode_data
                        nested_mal_opcode_data.append(
                            [temp_list_data[0], temp_list_data[1], temp_list_data[2], aft_attack_binput_arg])
                    attack_end_flag = False

            elif info.name == 'GLOBAL' and arg not in self._ALLOWLIST:
                global_data = {"info": info, "arg": arg, "pos": pos}
                global_nested_stack.append([global_data, bef_attack_binput_arg])

            elif info.name == 'BINGET' and arg in global_reuse_dict.keys():
                # The way we check for global calls, simply also check for BINGET references which might reuse the previous
                # global calls
                # Arg in keys indicates that BINGET is refering to a GLOBAL attack call, i.e global reuse attack
                reused_global_data = global_reuse_dict[arg]
                global_data = {"info": reused_global_data["info"], "arg": reused_global_data["arg"], "pos": pos}
                global_nested_stack.append([global_data, bef_attack_binput_arg])

            elif len(global_nested_stack) >= 1 and info.name == 'REDUCE':
                reduce_data = {"info": info, "arg": arg, "pos": pos}
                attack_end_flag = True
                temp_list_data = global_nested_stack.pop()
                # Attack is complete so remove from global stack and append to nested_attack_stack to wait for BINPUT after the attack
                nested_attack_stack.append([temp_list_data[0], reduce_data, temp_list_data[1]])

        file_data.seek(current_pointer)
        return nested_mal_opcode_data
    
    def _get_nested_attack_data_proto4(self, data_bytearray, file_data, global_reuse_dict):
        """
        Params:
                file_data: A file object for the pickle file
                data_bytearray: To check for the POP after REDUCE opcode

        Returns:
                mal_opcode_data: A list containing the information about all the attack calls. The data in the
                list will be in the following format:
                [sub_list, REDUCE_data, bef_attack_memo_arg, after_attack_memo_arg] and the sub_list will be a
                list of [first_BINUNI_data, second_BINUNI_data, STACK_GLOBAL_data]. There can be
                multiple such lists in nested_mal_opcode_data.

                All the opcodes data are a dict of {'info', 'arg', 'pos'}
        """
        current_pointer = file_data.tell()
        file_data.seek(0)
        
        possible_attack_flag = False
        attack_end_flag = False

        second_prev_binuni_data = {}
        first_prev_binuni_data = {}

        aft_attack_memo_arg = 0
        bef_attack_memo_arg = 0

        nested_mal_opcode_data = []
        # Final list containing the data about the nested attack
        global_nested_stack = []
        # Global_nested_stack will contain the sub_list opcode data and bef_attack_memo
        nested_attack_stack = []
        # Nested_attack_stack will contain the sub_list, reduce data and bef_attack_memo

        for info, arg, pos in genops(file_data):

            # Every STACK_GLOBAL requires it to be preceded by 2 BINUNICODE or SHORT_BINUNICODE opcodes
            if info.name == 'BINUNICODE' or info.name == 'SHORT_BINUNICODE':
                second_prev_binuni_data = first_prev_binuni_data
                first_prev_binuni_data = {'info': info, 'arg': arg, 'pos': pos}
                
                # Both are non-empty indicates a possible STACK_GLOBAL call, malicious code
                if len(second_prev_binuni_data) > 0 and len(first_prev_binuni_data) > 0:
                    possible_attack_flag = True
                # print({'info':info, 'arg': arg, 'pos':pos})

            elif info.name == 'STACK_GLOBAL' and possible_attack_flag:
                combined_arg = second_prev_binuni_data['arg'] + ' ' + first_prev_binuni_data['arg']
                combined_arg = combined_arg.replace(' ', '.')

                if combined_arg not in self._ALLOWLIST:
                    stack_global_data = {'info': info, 'arg': arg, 'pos': pos}
                    
                    # Create a list containing first and second BINUNI calls and current STACK GLOBAL data
                    temp_list_data = [second_prev_binuni_data, first_prev_binuni_data, stack_global_data]
                    bef_attack_memo_arg = self._find_previous_memoize(file_data, second_prev_binuni_data['pos'])
                    global_nested_stack.append([temp_list_data, bef_attack_memo_arg['arg']])
                    
                    # Reset the first prev and second prev binuni data dicts
                    second_prev_binuni_data = {}
                    first_prev_binuni_data = {}

                possible_attack_flag = False

            elif info.name == 'BINGET' and arg in global_reuse_dict.keys() and possible_attack_flag:
                combined_arg = second_prev_binuni_data['arg'] + ' ' + first_prev_binuni_data['arg']
                combined_arg = combined_arg.replace(' ', '.')

                if combined_arg not in self._ALLOWLIST:
                    global_reuse_data = global_reuse_dict[arg]
                    stack_global_data = {'info': global_reuse_data['info'], 'arg': global_reuse_data['arg'], 'pos': pos}
                    
                    # Create a list containing first and second BINUNI calls and current STACK GLOBAL data
                    temp_list_data = [second_prev_binuni_data, first_prev_binuni_data, stack_global_data]
                    bef_attack_memo_arg = self._find_previous_memoize(file_data, second_prev_binuni_data['pos'])
                    global_nested_stack.append([temp_list_data, bef_attack_memo_arg['arg']])
                    
                    # Reset the first prev and second prev binuni data dicts
                    second_prev_binuni_data = {}
                    first_prev_binuni_data = {}

                possible_attack_flag = False

            elif len(global_nested_stack) >= 1 and info.name == 'REDUCE':
                reduce_data = {"info": info, "arg": arg, "pos": pos}
                
                attack_end_flag = True
                temp_list_data = global_nested_stack.pop()
                
                # Attack is complete so remove from global stack and append to nested_attack_stack to wait for BINPUT after the attack
                nested_attack_stack.append([temp_list_data[0], reduce_data, temp_list_data[1]])

            elif info.name == 'MEMOIZE' and attack_end_flag:
                # If we have a complete attack(indicated by attack_end_flag) then check to store the first MEMOIZE after the attack
                # First memoize after the attack is found

                # Use data_bytearray to detect pop and memoize
                if data_bytearray[pos+1:pos+2] == bytearray(b'0'):
                    memo_dict = self._find_next_memoize(file_data, pos+1)
                    aft_attack_memo_arg = memo_dict['arg']

                else:
                    memoize_dict = self._find_next_memoize(file_data, pos)
                    aft_attack_memo_arg = memoize_dict['arg']

                temp_list_data = nested_attack_stack.pop()

                # print([temp_list_data[0], temp_list_data[1], temp_list_data[2], aft_attack_memo_arg])
                if len(global_nested_stack) == 0:
                    # No further nesting inside this attack, so push it into the mal_opcode_data
                    nested_mal_opcode_data.append([temp_list_data[0], temp_list_data[1], temp_list_data[2], aft_attack_memo_arg])

                attack_end_flag = False

        file_data.seek(current_pointer)
        
        return nested_mal_opcode_data
    # End of function

    def get_global_reduce_data(self, data_bytearray, file_data, global_reuse_dict, previous_pos=-1, proto=2):
        if proto < 4:
            return self._get_global_reduce_data_proto2(data_bytearray, file_data, global_reuse_dict, previous_pos)
        else:
            return self._get_global_reduce_data_proto4(data_bytearray, file_data, global_reuse_dict, previous_pos)

    def _get_global_reduce_data_proto2(self, data_bytearray, file_data, global_reuse_dict, previous_pos=-1):
        """
        Params:
            data_bytearray: To check for the POP after REDUCE opcode
            file_data: a file object for the pickle file
            global_reuse_dict: To look for BINGETS reusing malicious GLOBAL calls
            previous_pos: a cursor to check if the opcode has been processed or not.

        Returns:
            mal_opcode_data: A list of places where malicious global calls were found.
                            The global opcode (info, arg, pos), reduce opcode (info, arg, pos),
                            and the memo ids used before and after the attack the elements of each list.
                            There are multiple such lists in mal_opcode_data.

        """
        global_flag = False
        reduce_flag = False
        bef_attack_binput_arg = 0
        aft_attack_binput_arg = 0
        mal_opcode_data = []
        global_data = {}
        reduce_data = {}

        current_pointer = file_data.tell()
        file_data.seek(0)

        for info, arg, pos in genops(file_data):
            if info.name == 'GLOBAL':
                arg = arg.replace(' ', '.')

            if not global_flag and not reduce_flag and (info.name == 'BINPUT' or info.name == 'LONG_BINPUT'):
                bef_attack_binput_arg = arg

            if info.name == 'GLOBAL' and pos > previous_pos and arg not in self._ALLOWLIST:
                global_flag = True
                global_data = {"info": info, "arg": arg, "pos": pos}

            elif info.name == 'BINGET' and arg in global_reuse_dict.keys():
                # The way we check for global calls, simply also check for BINGET references which might reuse the previous
                # global calls
                # Arg in keys indicates that BINGET is refering to a GLOBAL attack call, i.e global reuse attack
                reused_global_data = global_reuse_dict[arg]
                global_flag = True
                global_data = {"info": reused_global_data["info"], "arg": reused_global_data["arg"], "pos": pos}

            elif global_flag and info.name == 'REDUCE':
                reduce_flag = True
                reduce_data = {"info": info, "arg": arg, "pos": pos}
                # global_flag = False
                previous_pos = pos

            elif global_flag and reduce_flag and (info.name == 'BINPUT' or info.name == 'LONG_BINPUT'):
                # use data_bytearray to detect pop and binput
                if info.name == 'BINPUT':
                    if data_bytearray[pos + 2:pos + 3] == bytearray(b'0'):
                        binput_dict = self.find_next_binput(file_data, pos + 3)
                        aft_attack_binput_arg = binput_dict['arg']
                    else:
                        aft_attack_binput_arg = arg
                else:
                    if data_bytearray[pos + 5:pos + 6] == bytearray(b'0'):
                        binput_dict = self.find_next_binput(file_data, pos + 6)
                        aft_attack_binput_arg = binput_dict['arg']
                    else:
                        aft_attack_binput_arg = arg
                global_flag = False
                reduce_flag = False
                mal_opcode_data.append([global_data, reduce_data, bef_attack_binput_arg, aft_attack_binput_arg])
                bef_attack_binput_arg = aft_attack_binput_arg

        file_data.seek(current_pointer)
        return mal_opcode_data

    def _get_global_reduce_data_proto4(self, data_bytearray, file_data, global_reuse_dict, previous_pos=-1):
        """
        Params:
            data_bytearray: To check for the POP after REDUCE opcode
            file_data: a file object for the pickle file
            global_reuse_dict: To look for BINGETS reusing malicious GLOBAL calls
            previous_pos: a cursor to check if the opcode has been processed or not.

        Returns:
            mal_opcode_data: A list containing the information about all the attack calls. The data in the
            list will be in the following format:
            [sub_list, REDUCE_data, bef_attack_memo_arg, after_attack_memo_arg] and the sub_list will be a
            list of [first_BINUNI_data, second_BINUNI_data, STACK_GLOBAL_data]. There can be
            multiple such lists in mal_opcode_data.

            All the opcodes data are a dict of {'info', 'arg', 'pos'}

        """
        current_pointer = file_data.tell()
        file_data.seek(0)
        
        possible_attack_flag = False
        reduce_flag = False
        global_flag = False

        second_prev_binuni_data = {}
        first_prev_binuni_data = {}

        bef_attack_memo_arg = 0
        aft_attack_memo_arg = 0
        
        mal_opcode_data = []
        # Final list containing the data about the attacks
        temp_sub_list = []
        # Will contain the malicious stack_global opcode data
        reduce_data = {}
        # Will contain the reduce opcode data

        for info, arg, pos in genops(file_data):

            # Every STACK_GLOBAL requires it to be preceded by 2 BINUNICODE or SHORT_BINUNICODE opcodes
            if info.name == 'BINUNICODE' or info.name == 'SHORT_BINUNICODE':
                second_prev_binuni_data = first_prev_binuni_data
                first_prev_binuni_data = {'info': info, 'arg': arg, 'pos': pos}
                
                # Both are non-empty indicates a possible STACK_GLOBAL call, malicious code
                if len(second_prev_binuni_data) > 0 and len(first_prev_binuni_data) > 0:
                    possible_attack_flag = True
                # print({'info':info, 'arg': arg, 'pos':pos})

            elif info.name == 'STACK_GLOBAL' and possible_attack_flag:
                combined_arg = second_prev_binuni_data['arg'] + ' ' + first_prev_binuni_data['arg']
                combined_arg = combined_arg.replace(' ', '.')

                if combined_arg not in self._ALLOWLIST:
                    stack_global_data = {'info': info, 'arg': arg, 'pos': pos}
                    sub_list = [second_prev_binuni_data, first_prev_binuni_data, stack_global_data]
                    bef_attack_memo_arg = self._find_previous_memoize(file_data, second_prev_binuni_data['pos'])
                    temp_sub_list = [sub_list, bef_attack_memo_arg['arg']]
                    global_flag = True
                    
                    # Reset the first prev and second prev binuni data dicts
                    second_prev_binuni_data = {}
                    first_prev_binuni_data = {}

                possible_attack_flag = False

            elif info.name == 'BINGET' and arg in global_reuse_dict.keys() and possible_attack_flag:
                combined_arg = second_prev_binuni_data['arg'] + ' ' + first_prev_binuni_data['arg']
                combined_arg = combined_arg.replace(' ', '.')

                if combined_arg not in self._ALLOWLIST:
                    global_reuse_data = global_reuse_dict[arg]
                    stack_global_data = {'info': global_reuse_data['info'], 'arg': global_reuse_data['arg'], 'pos': pos}
                    sub_list = [second_prev_binuni_data, first_prev_binuni_data, stack_global_data]
                    bef_attack_memo_arg = self._find_previous_memoize(file_data, second_prev_binuni_data['pos'])
                    temp_sub_list = [sub_list, bef_attack_memo_arg['arg']]
                    global_flag = True
                    
                    # Reset the first prev and second prev binuni data dicts
                    second_prev_binuni_data = {}
                    first_prev_binuni_data = {}

                possible_attack_flag = False

            elif global_flag and info.name == 'REDUCE':
                reduce_data = {"info": info, "arg": arg, "pos": pos}
                reduce_flag = True

            elif info.name == 'MEMOIZE' and reduce_flag:
                # If we have a complete attack(indicated by reduce_flag) then check to store the first MEMOIZE after the attack
                # First memoize after the attack is found

                # Use data_bytearray to detect pop and memoize
                if data_bytearray[pos+1:pos+2] == bytearray(b'0'):
                    memo_dict = self._find_next_memoize(file_data, pos+1)
                    aft_attack_memo_arg = memo_dict['arg']
                    
                else:
                    memoize_dict = self._find_next_memoize(file_data, pos)
                    aft_attack_memo_arg = memoize_dict['arg']

                # Push data into the mal_opcode_data
                mal_opcode_data.append([temp_sub_list[0], reduce_data, temp_sub_list[1], aft_attack_memo_arg])
                
                # Reset the flags
                reduce_flag = False
                global_flag = False

        file_data.seek(current_pointer)
        
        return mal_opcode_data
    # End of function

    def get_memo_opcodes_between_memo_indexes(self, file_data, start_memo_ind, end_memo_ind):
        """
        Params:
            file_data: a file object for the pickle file
            start_memo_ind: the first binput/long_binput opcodes index for which opcode info is to be passed. 
            end_memo_ind: the last binput/long_binput opcodes index for which opcode info is to be passed   
        
        Returns:
            memo_opcode_data: A list of BINPUT and LONG_BINPUT opcode info between the start and end (inclusive). 
          
        """
        memo_opcodes_data = []

        current_pointer = file_data.tell()
        file_data.seek(0)

        for info, arg, pos, in genops(file_data):
            if info.name == 'BINPUT' or info.name == 'LONG_BINPUT':
                if start_memo_ind <= arg <= end_memo_ind:
                    memo_opcodes_data.append({'info': info, 'arg': arg, 'pos': pos})

        file_data.seek(current_pointer)
        return memo_opcodes_data

    def get_memo_get_calls(self, file_data):
        """
        Params:
            file_data: a file object for the pickle file
        
        Returns:
            memo_get_calls_data: A list of BINGET and LONG_BINGET opcode info in the file. 
          
        """
        memo_get_calls_data = []

        current_pointer = file_data.tell()
        file_data.seek(0)

        for info, arg, pos, in genops(file_data):
            if info.name == 'BINGET' or info.name == 'LONG_BINGET':
                memo_get_calls_data.append({'info': info, 'arg': arg, 'pos': pos})

        file_data.seek(current_pointer)
        return memo_get_calls_data

    def get_attack_data_proto4(self, data_bytearray, file_data, previous_pos=-1):
        """
        Params:
            file_data: A file object for the pickle file
            data_bytearray: To check for the POP after REDUCE opcode
        
        Returns:
            mal_opcode_data: A list containing the information about all the attack calls. The data in the
            list will be in the following format:
            [sub_list, REDUCE_data, bef_attack_memo_arg, after_attack_memo_arg] and the sub_list will be a
            list of [first_BINUNI_data, second_BINUNI_data, STACK_GLOBAL_data]. There can be
            multiple such lists in mal_opcode_data. 
          
            All the opcodes data are a dict of {'info', 'arg', 'pos'}
        """
        possible_attack_flag = False
        attack_end_flag = False

        second_prev_binuni_data = {}
        first_prev_binuni_data = {}

        bef_attack_memo_arg = None
        mal_opcode_data = []
        # Final list containing the data about the nested attack
        global_nested_stack = []
        # Global_nested_stack will contain the sub_list opcode data and bef_attack_memo
        nested_attack_stack = []
        # Nested_attack_stack will contain the sub_list, reduce data and bef_attack_memo

        current_pointer = file_data.tell()
        file_data.seek(0)

        for info, arg, pos in genops(file_data):

            # Every STACK_GLOBAL requires it to be preceded by 2 BINUNICODE or SHORT_BINUNICODE opcodes
            if info.name == 'BINUNICODE' or info.name == 'SHORT_BINUNICODE':
                second_prev_binuni_data = first_prev_binuni_data
                first_prev_binuni_data = {'info': info, 'arg': arg, 'pos': pos}
                # Both are non-empty indicates a possible STACK_GLOBAL call, malicious code
                if len(second_prev_binuni_data) > 0 and len(first_prev_binuni_data) > 0:
                    possible_attack_flag = True
            # print({'info':info, 'arg': arg, 'pos':pos})

            elif info.name == 'STACK_GLOBAL' and possible_attack_flag:
                combined_arg = second_prev_binuni_data['arg'] + ' ' + first_prev_binuni_data['arg']
                combined_arg = combined_arg.replace(' ', '.')

                if combined_arg not in self._ALLOWLIST:
                    stack_global_data = {'info': info, 'arg': arg, 'pos': pos}
                    # Create a list containing first and second BINUNI calls and current STACK GLOBAL data
                    temp_list_data = [second_prev_binuni_data, first_prev_binuni_data, stack_global_data]
                    global_nested_stack.append([temp_list_data, bef_attack_memo_arg])
                    # Reset the first prev and second prev binuni data dicts
                    second_prev_binuni_data = {}
                    first_prev_binuni_data = {}

                possible_attack_flag = False

            elif len(global_nested_stack) >= 1 and info.name == 'REDUCE':
                reduce_data = {"info": info, "arg": arg, "pos": pos}
                attack_end_flag = True
                temp_list_data = global_nested_stack.pop()
                # Attack is complete so remove from global stack and append to nested_attack_stack to wait for BINPUT after the attack
                nested_attack_stack.append([temp_list_data[0], reduce_data, temp_list_data[1]])

            elif info.name == 'MEMOIZE':
                bef_attack_memo_arg = self._find_next_memoize(file_data, pos - 1)['arg']
                # If we have a complete attack(indicated by attack_end_flag) then check to store the first MEMOIZE after the attack
                if attack_end_flag:
                    # First memoize after the attack is found

                    # Use data_bytearray to detect pop and memoize
                    if data_bytearray[pos + 1:pos + 2] == bytearray(b'0'):
                        memo_dict = self._find_next_memoize(file_data, pos + 1)
                        aft_attack_memo_arg = memo_dict['arg']
                    else:
                        aft_attack_memo_arg = self._find_next_memoize(file_data, pos - 1)['arg']

                    temp_list_data = nested_attack_stack.pop()

                    # print([temp_list_data[0], temp_list_data[1], temp_list_data[2], aft_attack_memo_arg])
                    if len(global_nested_stack) == 0:
                        # No further nesting inside this attack, so push it into the mal_opcode_data
                        mal_opcode_data.append(
                            [temp_list_data[0], temp_list_data[1], temp_list_data[2], aft_attack_memo_arg])

                    attack_end_flag = False

        file_data.seek(current_pointer)
        return mal_opcode_data


if __name__ == "__main__":
    print('input file path')
    config_path = 'config_files'
    allowlist_file = 'allowlist.config'
    safeclass_file = 'safeclasses.config'

    filePath = input()

    detector = Detector(config_path, allowlist_file, safeclass_file)
    detector._exists_attack_proto2(filePath)
