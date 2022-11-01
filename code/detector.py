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

	def find_next_binput(self, data_bytearray, start_pos):
		for i in range(start_pos, len(data_bytearray)):
			if data_bytearray[i:i+1] == bytearray(b'q'):
				arg = int.from_bytes(data_bytearray[i+1:i+2], 'little')
				return {'info':'BINPUT', 'pos':i, 'arg':arg}
			if data_bytearray[i:i+1] == bytearray(b'r'):
				arg = int.from_bytes(data_bytearray[i+1:i+5], 'little')
				return {'info':'LONG_BINPUT', 'pos':i, 'arg':arg}
		return {'info': 'FOUND_NONE', 'pos': -1, 'arg': -1}

	def get_global_reduce_data(self, data_bytearray, file_data, previous_pos = -1):
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
		bef_attack_memo_ind = 0
		after_attack_memo_ind = 0
		mal_opcode_data=[]
		global_data = {}
		reduce_data = {}
		
		for info, arg, pos in genops(file_data):
			if info.name == 'GLOBAL':
				arg = arg.replace(' ', '.')
			
			if not global_flag and not reduce_flag and (info.name == 'BINPUT' or info.name == 'LONG_BINPUT'):
				bef_attack_memo_ind = arg

			if info.name == 'GLOBAL' and pos > previous_pos and arg not in self._ALLOWLIST:
				global_flag = True
				global_data = {"info": info, "arg": arg, "pos": pos}	
			
			elif global_flag and info.name == 'REDUCE':
				reduce_flag = True
				reduce_data = {"info": info, "arg": arg, "pos": pos}
				# global_flag = False
				previous_pos = pos

			elif global_flag and reduce_flag and (info.name == 'BINPUT' or info.name == 'LONG_BINPUT'):
				# use data_bytearray to detect pop and binput
				if info.name=='BINPUT':
					if data_bytearray[pos+2:pos+3]==bytearray(b'0'):
						binput_dict=self.find_next_binput(data_bytearray, pos+3)
						after_attack_memo_ind = binput_dict['arg']
					else:
						after_attack_memo_ind = arg
				else:
					if data_bytearray[pos+5:pos+6]==bytearray(b'0'):
						binput_dict = self.find_next_binput(data_bytearray, pos+6)
						after_attack_memo_ind = binput_dict['arg']
					else:
						after_attack_memo_ind = arg
				global_flag = False
				reduce_flag = False
				mal_opcode_data.append([global_data, reduce_data, bef_attack_memo_ind, after_attack_memo_ind])
				bef_attack_memo_ind = after_attack_memo_ind

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
		file_data.seek(0)
		for info, arg, pos, in genops(file_data):
			if info.name == 'BINGET' or info.name == 'LONG_BINGET':
				memo_get_calls_data.append({'info':info, 'arg': arg, 'pos':pos})
		return memo_get_calls_data


if __name__ == "__main__":
	print('input file path')
	config_path = 'config_files'
	allowlist_file = 'allowlist.config'
	safeclass_file = 'safeclasses.config'

	filePath = input()
 
	detector = Detector(config_path, allowlist_file, safeclass_file)
	detector.detect_pickle_allow_list(filePath)


