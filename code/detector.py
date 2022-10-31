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
		if className not in self._SAFECLASS:
			return False
		return True
	# considering non-nested attacks only
	def get_global_reduce_data(self, file_data, previous_pos = -1):
    
		global_flag = False
		
		mal_opcode_data=[]

		global_data = {}
		reduce_data = {}
		
		for info, arg, pos in genops(file_data):
			if info.name == 'GLOBAL':
				arg = arg.replace(' ', '.')
			
			if info.name == 'GLOBAL' and pos > previous_pos and arg not in self._ALLOWLIST:
				global_flag = True
				global_data = {"info": info, "arg": arg, "pos": pos}	
			elif global_flag and info.name == 'REDUCE':
				reduce_data = {"info": info, "arg": arg, "pos": pos}
				mal_opcode_data.append((global_data, reduce_data))
				global_flag = False
				previous_pos = pos
			
		return mal_opcode_data

if __name__ == "__main__":
	print('input file path')
	config_path = 'config_files'
	allowlist_file = 'allowlist.config'
	safeclass_file = 'safeclasses.config'

	filePath = input()
 
	detector = Detector(config_path, allowlist_file, safeclass_file)
	detector.detect_pickle_allow_list(filePath)


