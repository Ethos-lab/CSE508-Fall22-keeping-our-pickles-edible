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
_ALLOWLIST = []
_SAFECLASS = []

	
def detect_pickle_allow_list(filePath):
	file = open(filePath, 'rb')
	for info, arg, pos in genops(file):
		if(info.name == 'GLOBAL'):
			arg = arg.replace(' ' , '.')
			if arg not in _ALLOWLIST:
				print('❌ FILE CONTAINS UNNECESSARY FUNCTION CALLS, REFRAIN FROM OPENING')
				print('UNTRUSTED FUNCTION CALL: ' , arg, " SHOULD NOT HAVE BEEN CALLED")
				return
	
	print('✅ FILE SEEMS TO BE SAFE')

def detect_pickle_safe_class(className) -> bool:
	if className not in _SAFECLASS:
		return False
	return True

if __name__ == "__main__":
	print('input file path')
	filePath = input()
 
	allowlist_file_path = os.path.join('config_files', 'allowlist.config')
	allowlist_file_data = open(allowlist_file_path).read()
 
	safeclass_file_path = os.path.join('config_files', 'safeclasses.config')
	safeclass_file_data = open(safeclass_file_path).read()
 
	_ALLOWLIST = allowlist_file_data.split('\n')
	_SAFECLASS = safeclass_file_data.split('\n')
 
	detect_pickle_allow_list(filePath)


