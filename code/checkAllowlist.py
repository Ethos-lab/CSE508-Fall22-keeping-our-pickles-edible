import pickle
from pickletools import genops, opcodes, OpcodeInfo
import builtins  
import collections
import inspect
import io
import logging
import pickle
import torch




	
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


if __name__ == "__main__":
	print('input file path')
	filePath = input()
	detect_pickle_allow_list(filePath)


