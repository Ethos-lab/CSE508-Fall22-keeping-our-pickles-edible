import pickle
from pickletools import genops, opcodes, OpcodeInfo
import os
import builtins  
import collections
import inspect
import io
import logging

# Considering only sequetial attack for now
def get_global_reduce_data(file_data, previous_pos = -1):
    
    global_flag = False
    reduce_flag = False
    
    global_data = dict()
    reduce_data = dict()
    opcode_after_reduce_data = dict()
    
    for info, arg, pos in genops(file_data):
        
        if info.name == 'GLOBAL' and pos > previous_pos:
            global_flag = True
            global_data = {"info": info, "arg": arg, "pos": pos}
            
        elif global_flag and info.name == 'REDUCE':
            reduce_data = {"info": info, "arg": arg, "pos": pos}
            break
            # Comment above and "break" and uncomment the below lines if we need data of statement just after "REDUCE"
            # reduce_flag = True
            
        # elif global_flag and reduce_flag:
        #     opcode_after_reduce_data = {"info": info, "arg": arg, "pos": pos}
        #     break
        
    return (global_data, reduce_data)
            
            

# If needed, to test the file 
# if __name__ == "__main__":
    
#     filePath = os.path.join('code', 'untrusted_picklefiles', 'yk.pickle')
#     file_data = open(filePath, 'rb')
    
#     global_data, reduce_data = get_global_reduce_data(file_data)
    
#     print(global_data)
#     print(reduce_data)
