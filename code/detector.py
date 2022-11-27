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

	def detect_pickle_allow_list(self, filePath):
		"""
		Params: 
			filePath: detect if the pickle file has any global calls that are not a part of the whitelist. 

		Returns:
			None
		
		Just prints if the file seems to be safe or unsafe. 
		"""
		file = open(filePath, 'rb')
		for info, arg, pos in genops(file):
			if(info.name == 'GLOBAL'):
				arg = arg.replace(' ' , '.')
				if arg not in self._ALLOWLIST:
					print('❌ FILE CONTAINS UNNECESSARY FUNCTION CALLS, REFRAIN FROM OPENING')
					print('UNTRUSTED FUNCTION CALL: ' , arg, " SHOULD NOT HAVE BEEN CALLED")
					return
		
		print('✅ FILE SEEMS TO BE SAFE')
	
	def detect_pickle_safe_class(self, className) -> bool:
		"""
			Placeholder. Not implemented yet. 
		"""

		if className not in self._SAFECLASS:
			return False
		return True
	# considering non-nested attacks only

	def find_next_binput(self, file_data, start_pos):
		position_to_restore = file_data.tell()
		file_data.seek(0)
		for info, arg, pos in genops(file_data):
			if pos<start_pos:
				continue
			if info.name=='BINPUT':
				file_data.seek(position_to_restore)
				return {'info':info, 'pos':pos, 'arg':arg}
			if info.name=='LONG_BINPUT':
				file_data.seek(position_to_restore)
				return {'info':info, 'pos':pos, 'arg':arg}
		file_data.seek(position_to_restore)
		return {'info': None, 'pos': 1000000000000, 'arg': 1000000000000}

	def find_next_memoize(self, file_data, start_pos):
		current_position = file_data.tell()
		file_data.seek(0)

		for info, arg, pos in genops(file_data):

			if pos < start_pos:
				continue

			if info.name == 'MEMOIZE':
				file_data.seek(current_position)
				return {'info':info, 'pos':pos, 'arg':arg}

		file_data.seek(current_position)
		return {'info': None, 'pos': 1000000000000, 'arg': 1000000000000}

	def global_reuse_calls(self, file_data):
		"""
		Params:
			file_data: The file object of the current pickle file

		Returns:
			Dict containing the indices as key and global opcode data as value

		This function check for the possible global reuse attacks and stores the BINGET(those reuse calls)
		with the appropriate global calls along with its argument.
  
  		"""
    
		#To keep track of the global call and the immediate next BINPUT
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

	def exists_nested_attack(self, file_data, global_reuse_dict, previous_pos = -1):
		"""
  		Params:
			file_data: The file object of the current pickle file
			previous_pos(int, optional): Defaults to -1. A pointer to check for the required opcodes after it.

		Returns:
			True if the file has nested attacks present, False otherwise.
   
		"""
		# global_flag = False
		# global_reuse_flag = False
  
		current_pointer = file_data.tell()
		file_data.seek(0)
  
		global_nested_stack = []
		# global_nested_stack will contain data as soon as a global call in encountered, this will help to check if nested attacks exists
  
  
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

	def get_neseted_attack_data(self, data_bytearray, file_data, global_reuse_dict):
		"""
		Params:
			file_data: A file object for the pickle file
			global_reuse_dict: A dictionary containing the binget arguments where global calls are being reused
		
		Returns:
			nested_mal_opcode_data: A list containing the information about the nested attack calls. 
   			The global opcode (info, arg, pos), reduce opcode (info, arg, pos), and the memo ids
      		used beforeand after the attack the elements of each list. There are multiple such lists
        	in nested_mal_opcode_data. 
		  
		"""
		# global_flag = False
		# reduce_flag = False
		attack_end_flag = False
		# global_reuse_flag = False
		# To flag all the possible attacks that reuse the global opcode using BINGET
  
		bef_attack_binput_arg = 0
		aft_attack_binput_arg = 0
  
		nested_mal_opcode_data=[]
		# Final list containing the data about the nested attack 
		global_nested_stack = []
		# Global_nested_stack will contain the global opcode data and bef_attack_binput_arg
		nested_attack_stack = []
		# Nested_attack_stack will contain the global, reduce data and bef_attack_binput_arg
  
  
		for info, arg, pos in genops(file_data):
    
			if info.name == 'GLOBAL':
				arg = arg.replace(' ', '.')
   
			if info.name == 'BINPUT' or info.name == 'LONG_BINPUT':
				bef_attack_binput_arg = arg
    
				# If we have a complete attack(indicated by attack_end_flag) then check to store the first BINPUT after the attack
				if attack_end_flag:
					# First binput after the attack is found
					# Use data_bytearray to detect pop and binput
					if info.name=='BINPUT':
         
						if data_bytearray[pos+2:pos+3]==bytearray(b'0'):
							binput_dict=self.find_next_binput(file_data, pos+3)
							aft_attack_binput_arg = binput_dict['arg']
       
						else:
							aft_attack_binput_arg = arg
					else:
         
						if data_bytearray[pos+5:pos+6]==bytearray(b'0'):
							binput_dict = self.find_next_binput(file_data, pos+6)
							aft_attack_binput_arg = binput_dict['arg']
       
						else:
							aft_attack_binput_arg = arg

					# global_flag = False
					# reduce_flag = False
					temp_list_data = nested_attack_stack.pop()
					if len(global_nested_stack) == 0:
						# No further nesting inside this attack, so push it into the nested_mal_opcode_data
						nested_mal_opcode_data.append([temp_list_data[0], temp_list_data[1], temp_list_data[2], aft_attack_binput_arg])
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

		return nested_mal_opcode_data


	def get_global_reduce_data(self, data_bytearray, file_data, global_reuse_dict, previous_pos = -1):
		"""
		Params:
			file_data: a file object for the pickle file
			previous_pos: a cursor to check if the opcode has been processed or not. 
		
		Returns:
			mal_opcode_data: A list of places where malicious global calls were found. The global opcode (info, arg, pos), reduce opcode (info, arg, pos), 
			and the memo ids used before and after the attack the elements of each list. There are multiple such lists in mal_opcode_data. 
		  
		"""
		global_flag = False
		reduce_flag = False
		bef_attack_binput_arg = 0
		aft_attack_binput_arg = 0
		mal_opcode_data=[]
		global_data = {}
		reduce_data = {}
  
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
				if info.name=='BINPUT':
					if data_bytearray[pos+2:pos+3]==bytearray(b'0'):
						binput_dict=self.find_next_binput(file_data, pos+3)
						aft_attack_binput_arg = binput_dict['arg']
					else:
						aft_attack_binput_arg = arg
				else:
					if data_bytearray[pos+5:pos+6]==bytearray(b'0'):
						binput_dict = self.find_next_binput(file_data, pos+6)
						aft_attack_binput_arg = binput_dict['arg']
					else:
						aft_attack_binput_arg = arg
				global_flag = False
				reduce_flag = False
				mal_opcode_data.append([global_data, reduce_data, bef_attack_binput_arg, aft_attack_binput_arg])
				bef_attack_binput_arg = aft_attack_binput_arg

		return mal_opcode_data
	
	def get_memo_opcodes_between_memo_indexes(self, file_data, start_memo_ind, end_memo_ind):
		"""
		Params:
			file_data: a file object for the pickle file
			start_memo_ind: the first binput/long_binput opcodes index for which opcode info is to be passed. 
			end_memo_ind: the last binput/long_binput opcodes index for which opcode info is to be passed   
		
		Returns:
			memo_opcode_data: A list of BINPUT and LONG_BINPUT opcode info between the start and end (inclusive). 
		  
		"""
		memo_opcodes_data=[]
		file_data.seek(0)
		for info, arg, pos, in genops(file_data):
			if info.name == 'BINPUT' or info.name == 'LONG_BINPUT':
				if arg>=start_memo_ind and arg<=end_memo_ind:
					memo_opcodes_data.append({'info':info, 'arg': arg, 'pos':pos})
		return memo_opcodes_data

	def get_memo_get_calls(self, file_data):
		"""
		Params:
			file_data: a file object for the pickle file
		
		Returns:
			memo_get_calls_data: A list of BINGET and LONG_BINGET opcode info in the file. 
		  
		"""
		memo_get_calls_data=[]
		# current_pointer = file_data.tell()
		file_data.seek(0)
		for info, arg, pos, in genops(file_data):
			if info.name == 'BINGET' or info.name == 'LONG_BINGET':
				memo_get_calls_data.append({'info':info, 'arg': arg, 'pos':pos})
		# file_data.seek(current_pointer)
		return memo_get_calls_data

	# Initial Implementation
	def exists_attack_proto4(self, data_bytearray, file_data, previous_pos = -1):
		"""
		Params:
			file_data: A file object for the pickle file
		
		Returns:
   			True if attack exists in protocol version 4 of pickle file, False otherwise 
		  
		"""
		possible_attack_flag = False
		second_prev_binuni_data = {}
		first_prev_binuni_data = {}
  
  
		for info, arg, pos in genops(file_data):

			if pos < previous_pos:
				continue

			# Every STACK_GLOBAL requires it to be preceded by 2 BINUNICODE or SHORT_BINUNICODE opcodes
			if info.name == 'BINUNICODE' or info.name == 'SHORT_BINUNICODE':
				second_prev_binuni_data = first_prev_binuni_data
				first_prev_binuni_data = {'info':info, 'arg': arg, 'pos':pos}
				# Both are non-empty indicates a possible STACK_GLOBAL call, malicious code
				if len(second_prev_binuni_data) > 0 and len(first_prev_binuni_data) > 0:
					possible_attack_flag = True
				# print({'info':info, 'arg': arg, 'pos':pos})

			elif info.name == 'STACK_GLOBAL' and possible_attack_flag:
				combined_arg = second_prev_binuni_data['arg'] + first_prev_binuni_data['arg']
				combined_arg = combined_arg.replace(' ', '.')
				# Check if combined_arg is in whitelist or not to confirm about the attack
				if combined_arg not in self._ALLOWLIST:
					return True

		return False

	# Initial Implementation
	def get_attack_data_proto4(self, data_bytearray, file_data, previous_pos = -1):
		"""
		Params:
			file_data: A file object for the pickle file
		
		Returns:
			mal_opcode_data: A list containing the information about all the attack calls. 
   			The binunicode, stack global opcode (info, arg, pos), reduce opcode (info, arg, pos), and the memo ids
      		used beforeand after the attack the elements of each list. There can be multiple such lists
        	in mal_opcode_data. 
		  
		"""
		possible_attack_flag = False
		attack_end_flag = False
  
		second_prev_binuni_data = {}
		first_prev_binuni_data = {}
  
		mal_opcode_data=[]
		# Final list containing the data about the nested attack 
		global_nested_stack = []
		# Global_nested_stack will contain the stack_global opcode data and bef_attack_memo
		nested_attack_stack = []
		# Nested_attack_stack will contain the stack_global, reduce data and bef_attack_memo
  
  
		for info, arg, pos in genops(file_data):

			# Every STACK_GLOBAL requires it to be preceded by 2 BINUNICODE or SHORT_BINUNICODE opcodes
			if info.name == 'BINUNICODE' or info.name == 'SHORT_BINUNICODE':
				second_prev_binuni_data = first_prev_binuni_data
				first_prev_binuni_data = {'info':info, 'arg': arg, 'pos':pos}
				# Both are non-empty indicates a possible STACK_GLOBAL call, malicious code
				if len(second_prev_binuni_data) > 0 and len(first_prev_binuni_data) > 0:
					possible_attack_flag = True
				# print({'info':info, 'arg': arg, 'pos':pos})

			elif info.name == 'STACK_GLOBAL' and possible_attack_flag:
				combined_arg = second_prev_binuni_data['arg'] + first_prev_binuni_data['arg']
				combined_arg = combined_arg.replace(' ', '.')
				if combined_arg not in self._ALLOWLIST:
					print(combined_arg)
					global_nested_stack.append(combined_arg)
					possible_attack_flag = False
					# Reset the first prev and second prev binuni data dicts
					second_prev_binuni_data = {}
					first_prev_binuni_data = {}

			elif len(global_nested_stack) >= 1 and info.name == 'REDUCE':
				reduce_data = {"info": info, "arg": arg, "pos": pos}
				attack_end_flag = True
				temp_list_data = global_nested_stack.pop()
				# Attack is complete so remove from global stack and append to nested_attack_stack to wait for BINPUT after the attack
				nested_attack_stack.append([temp_list_data[0], reduce_data, temp_list_data[1]])

			elif info.name == 'MEMOIZE':
				bef_attack_binput_arg = arg
				aft_attack_memo_arg = arg
				# If we have a complete attack(indicated by attack_end_flag) then check to store the first MEMOIZE after the attack
				if attack_end_flag:
					# First memoize after the attack is found
					# Use data_bytearray to detect pop and memoize
					if data_bytearray[pos+1:pos+2]==bytearray(b'0'):
							memo_dict=self.find_next_memoize(file_data, pos+1)
							aft_attack_memo_arg = memo_dict['arg']
							# print(memo_dict['info'])
       
					else:
							aft_attack_memo_arg = arg

					# temp_list_data = nested_attack_stack.pop()
					# # print([temp_list_data[0], temp_list_data[1], temp_list_data[2], aft_attack_memo_arg])
					# if len(global_nested_stack) == 0:
					# 	# No further nesting inside this attack, so push it into the mal_opcode_data
					# 	mal_opcode_data.append([temp_list_data[0], temp_list_data[1], temp_list_data[2], aft_attack_memo_arg])
					attack_end_flag = False

		return mal_opcode_data

if __name__ == "__main__":
	print('input file path')
	config_path = 'config_files'
	allowlist_file = 'allowlist.config'
	safeclass_file = 'safeclasses.config'

	filePath = input()
 
	detector = Detector(config_path, allowlist_file, safeclass_file)
	detector.detect_pickle_allow_list(filePath)


