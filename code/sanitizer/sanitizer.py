import pickletools
import io
import transformers
from transformers import AutoModel
import zipfile 
import os
from os.path import join

import sys
# to allow imports from parent directory
dir_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.abspath(os.path.join(dir_path, os.pardir)))

from extract_pickle import PickleEC
from detector import Detector

class Sanitizer():
    def __init__(self, config_path, allowlist_file, safeclass_file):
        self.pickle_ec = PickleEC()
        self.detector = Detector(config_path, allowlist_file, safeclass_file)
    
    @staticmethod
    def test_pkl(dir_name):
        print("loading model from ", dir_name)
        model = AutoModel.from_pretrained(dir_name) # or load from HF hub
        print(model)

    
    @staticmethod
    def write_bytes(data_bytearray, pos, value_bytearray):
        data_bytearray[pos:pos]=value_bytearray
        return data_bytearray
    
    @staticmethod
    def delete_bytes(data_bytearray, start_byte, end_byte):
        for i in range(start_byte, end_byte+1):
            del data_bytearray[start_byte]
        return data_bytearray
    
    def sanitize_pickle(self, dir_name, pickle_name, new_pickle_name):
        # general steps in sanitisation
        # 1. read pickle file and detect malicious opcodes, localize them
        # 2. use the above localization information to delete the relevant opcodes and replace with empty dictionary if necessary
        # 3. write to new pickle file
        path_to_pickle_file = join(dir_name, pickle_name)
        pickle_file_object = self.pickle_ec.read_pickle(path_to_pickle_file)
        mal_opcode_data = self.detector.get_global_reduce_data(pickle_file_object)
        data_bytearray = self.pickle_ec.read_pickle_to_bytearray(path_to_pickle_file)
        sanitizer_pos_offset = 0
        for i in mal_opcode_data:
            global_data = i[0]
            reduce_data = i[1]
            start_byte = global_data['pos']-sanitizer_pos_offset
            end_byte = reduce_data['pos']-sanitizer_pos_offset
            sanitizer_pos_offset+=(end_byte-start_byte)
            data_bytearray = self.delete_bytes(data_bytearray, start_byte, end_byte)

            # TODO check condition when the below line is is needed
            data_bytearray = self.write_bytes(data_bytearray, start_byte, bytearray(b'}'))        
            
        new_path_to_pickle_file = join(dir_name, new_pickle_name)
        self.pickle_ec.write_pickle_from_bytearray(data_bytearray, new_path_to_pickle_file)
        return

    def sanitize_bin(self, dir_name, bin_name):
        # general steps in sanitisation
        # 1. extract pickle file form .bin file
        # 2. read pickle file and detect malicious opcodes, localize them
        # 3. use the above localization information to delete the relevant opcodes and replace with empty dictionary if necessary
        # 4. write to new pickle file
        # 5. compress the new folder to form new .bin file
        self.pickle_ec.extract(dir_name, bin_name)
        
        
        unzipped_dir = 'archive'
        path_to_pickle_file = join(dir_name, unzipped_dir, 'data.pkl')        
        pickle_file_object = self.pickle_ec.read_pickle(path_to_pickle_file)
        mal_opcode_data=self.detector.get_global_reduce_data(pickle_file_object)
        data_bytearray = self.pickle_ec.read_pickle_to_bytearray(path_to_pickle_file)
        sanitizer_pos_offset=0
        for i in mal_opcode_data:
            global_data = i[0]
            reduce_data = i[1]
            start_byte = global_data['pos']-sanitizer_pos_offset
            end_byte = reduce_data['pos']-sanitizer_pos_offset
            sanitizer_pos_offset+=(end_byte-start_byte)

            data_bytearray = self.delete_bytes(data_bytearray, start_byte, end_byte)

            # TODO check condition when the below line is is needed
            data_bytearray = self.write_bytes(data_bytearray, start_byte, bytearray(b'}'))        
            
        
        self.pickle_ec.write_pickle_from_bytearray(data_bytearray, path_to_pickle_file)
        self.pickle_ec.compress(dir_name, bin_name, unzipped_dir)
        return

if __name__ == "__main__":
    config_path = '../config_files'
    allowlist_file = 'allowlist.config'
    safeclass_file = 'safeclasses.config'

    sanitizer = Sanitizer(config_path, allowlist_file, safeclass_file)
    bin_name = 'pytorch_model.bin'

    list_of_unsanitized_pickles=[i for i in os.listdir('../untrusted_picklefiles/') if i.split('.')[1]=='pickle' or i.split('.')[1]=='pkl']
    # list_of_unsanitized_pickles=['gpt_mul_middle_3.pickle']
    for unsan_name in list_of_unsanitized_pickles:
        print("Sanitizing ", unsan_name)        
        sanitizer.sanitize_pickle('../untrusted_picklefiles', unsan_name, "edited_"+unsan_name)


    # sanitizer.sanitize_bin('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal', bin_name)
    # sanitizer.test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal')
    
    

    # sanitizer.test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/ben')
    # while True:
    #     q=input()
    #     if q=='q':
    #         break
    # sanitizer.test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal_control')
