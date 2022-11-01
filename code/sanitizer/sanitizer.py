import pickletools
import io
import transformers
from transformers import AutoModel
from pickletools import opcodes as opcode_lib
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
        self.MAX_BYTE=0xFF
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
        del data_bytearray[start_byte:end_byte+1]
        return data_bytearray
    
    def change_memo_indexes(self, data_bytearray, pickle_file_obj, start_scope, end_scope, memo_id_offset, pos_offset):# start_scope and end_scope are args of binput/long_binput
        """
        Params:
            data_bytearray: a bytearray containing binary data that has been edited. 
            pickle_file_obj: the object to the unchanged pickle file
            start_scope: the first memo index that needs to be changed by "memo_id_offset"
            end_scope: the last memo index that needs to be changed by "memo_id_offset"
            memo_id_offset: the offset introduced due to deletion of binput/long_binput calls
            pos_offset: the current running position offset with respect to the undeleted version of pickle file (say from pickle_file obj)
        
        Returns:
            data_bytearray: a bytearray with all memo indexes adjusted by 'memo_id_offset'
            pos_offset: the running offset after changing memo indexes for binput/long_binput calls

        This takes into account that after index 0xFF, BINPUT can't handle the index numbers so LONG_BINPUT is used. 
        """
        memo_opcode_data=self.detector.get_memo_opcodes_between_memo_indexes(pickle_file_obj, start_scope, end_scope)
        binput_in_bytes = bytearray('q'.encode('raw_unicode_escape'))
        long_binput_in_bytes = bytearray('r'.encode('raw_unicode_escape'))

        for id, val in enumerate(memo_opcode_data):
            
            offsetted_ind = val['arg'] - memo_id_offset
            # print(offsetted_ind, memo_id_offset)
            offsetted_pos = val['pos'] - pos_offset
            if val['info'].name == 'BINPUT' and data_bytearray[offsetted_pos:offsetted_pos+1]==bytearray(b'q'):
                data_bytearray = self.delete_bytes(data_bytearray, offsetted_pos, offsetted_pos+1)
                data_bytearray = self.write_bytes(data_bytearray, offsetted_pos, binput_in_bytes+bytearray(offsetted_ind.to_bytes(1, 'little')))
            elif val['info'].name == 'LONG_BINPUT' and data_bytearray[offsetted_pos:offsetted_pos+1]==bytearray(b'r'):
                if offsetted_ind<=self.MAX_BYTE:
                    data_bytearray = self.delete_bytes(data_bytearray, offsetted_pos, offsetted_pos+4)
                    data_bytearray = self.write_bytes(data_bytearray, offsetted_pos, binput_in_bytes+bytearray(offsetted_ind.to_bytes(1, 'little')))
                    pos_offset+=3
                else:
                    data_bytearray = self.delete_bytes(data_bytearray, offsetted_pos, offsetted_pos+4)
                    data_bytearray = self.write_bytes(data_bytearray, offsetted_pos, long_binput_in_bytes+bytearray(offsetted_ind.to_bytes(4, 'little')))
        
        return data_bytearray, pos_offset
    
    def change_memo_references(self, pickle_file_obj, memo_offset_ranges):
        """
        Params:
            pickle_file_obj: the object to the changed pickle file with no running pos offsets to the changes made. 
            memo_offset_ranges: the offset ranges to rectfy binget/long_binget calls. the ranges include the ```start memo id```, ```end memo id``` and the offset for the range. 
        
        Returns:
            data_bytearray: a bytearray with all binget/long_bingets references rectified to correct memo indexes.

        This takes into account that after index 0xFF, BINGET can't handle the index numbers so LONG_BINGET is used. 
        This method is necessary because the attacker may have changed the memo indexes in BINGET references to make sure the model doesn't break
        """

        memo_get_calls_data = self.detector.get_memo_get_calls(pickle_file_obj)
        binget_in_bytes = bytearray('h'.encode('raw_unicode_escape'))
        long_binget_in_bytes = bytearray('j'.encode('raw_unicode_escape'))
        pos_offset=0
        for id, val in enumerate(memo_get_calls_data):
            memo_offset = -1
            for range_tup in memo_offset_ranges:
                if val['arg'] >= range_tup[0] and val['arg']<=range_tup[1]:
                    memo_offset = range_tup[2]
            if memo_offset == -1:
                print("The pickle file is corrupted beyond repair. Can't be sanitized.")
                sys.exit(0)
            
            offsetted_ind = val['arg'] - memo_offset
            offsetted_pos = val['pos'] - pos_offset
            if val['info'].name == 'BINGET':
                data_bytearray = self.delete_bytes(data_bytearray, offsetted_pos, offsetted_pos+1)
                data_bytearray = self.write_bytes(data_bytearray, offsetted_pos, binget_in_bytes+bytearray(offsetted_ind.to_bytes(1, 'little')))
            elif val['info'].name == 'LONG_BINGET':
                if offsetted_ind<=self.MAX_BYTE:
                    data_bytearray = self.delete_bytes(data_bytearray, offsetted_pos, offsetted_pos+4)
                    data_bytearray = self.write_bytes(data_bytearray, offsetted_pos, binget_in_bytes+bytearray(offsetted_ind.to_bytes(1, 'little')))
                    pos_offset+=3
                else:
                    data_bytearray = self.delete_bytes(data_bytearray, offsetted_pos, offsetted_pos+4)
                    data_bytearray = self.write_bytes(data_bytearray, offsetted_pos, long_binget_in_bytes+bytearray(offsetted_ind.to_bytes(4, 'little')))
        return data_bytearray

    def remove_binput(self, data_bytearray, start_pos, pos_offset):
        """
        Params:
            data_bytearray: input bytearray which needs removal of binput/long_binput after the global-to-reduce part of attack has already been removed. 
            start_pos: the index where the binput will be present, since the global-to-reduce part has already been removed.
            pos_offset: the current byte position offset between the data_bytearray and the unchanged pickle file. 
        
        Returns:
            data_bytearray: after removing binput/long_binput only if a pop is called after this binput/long_binput. 
            pos_offset: updated offset due to deletions in the data_bytearray. 
        """
        if data_bytearray[start_pos:start_pos+1]==bytearray(b'q'): # binput
            if data_bytearray[start_pos+2:start_pos+3] == bytearray(b'0'):
                del data_bytearray[start_pos:start_pos+2]
                pos_offset+=1
        elif data_bytearray[start_pos:start_pos+1]==bytearray(b'r'):
            if data_bytearray[start_pos+5:start_pos+6] == bytearray(b'0'):
                del data_bytearray[start_pos:start_pos+5]
                pos_offset+=5
        return data_bytearray, pos_offset

    def sanitize_pickle(self, dir_name, pickle_name, new_pickle_name):
        """
        Params:
            dir_name: the name of the directory where the pickle file is present. 
            pickle_name: the name of the pickle file
            new_pickle_name: the name of the new pickle file that needs to be created.
        
        Returns: 
            None
        
        General steps in sanitisation:
            1. read pickle file and detect malicious opcodes, localize them using the code in Detector
            2.1. use the above localization information to delete the relevant opcodes and replace with empty dictionary if necessary
            2.2. Make sure that the memo indexes in the BINPUT/LONG_BINPUT opcodes are rectified according to offset. 
            2.3. Make sure that the memo index references in the BINGET/LONG_BINGET opcodes are rectified according the reference range.
            3. write to new pickle file
        
        """
        
        # step 1
        path_to_pickle_file = join(dir_name, pickle_name)
        pickle_file_object = self.pickle_ec.read_pickle(path_to_pickle_file)
        data_bytearray = self.pickle_ec.read_pickle_to_bytearray(path_to_pickle_file)
        mal_opcode_data = self.detector.get_global_reduce_data(data_bytearray, pickle_file_object)
        # print(mal_opcode_data)
        
        # step 2

        sanitizer_pos_offset = 0
        sanitizer_memo_offset = 0
        
        next_prev_memo_ind = 0 # will be used to send to change_memo_indexes
        prev_after_memo_ind = 0

        memo_ind_offset_ranges = []
        for id, val in enumerate(mal_opcode_data):
            
            global_data = val[0]
            reduce_data = val[1]
            prev_memo_ind = val[2]
            after_memo_ind = val[3]
            
            if id == len(mal_opcode_data)-1:
                next_prev_memo_ind = -1
            else:
                next_prev_memo_ind = mal_opcode_data[id+1][2]
            
            start_byte = global_data['pos']-sanitizer_pos_offset
            end_byte = reduce_data['pos']-sanitizer_pos_offset
            sanitizer_pos_offset+=(end_byte-start_byte)
            data_bytearray = self.delete_bytes(data_bytearray, start_byte, end_byte)
            data_bytearray, sanitizer_pos_offset = self.remove_binput(data_bytearray, start_byte, sanitizer_pos_offset)

            data_bytearray = self.write_bytes(data_bytearray, start_byte, bytearray(b'}'))
            
            memo_ind_offset_ranges.append((prev_after_memo_ind, prev_memo_ind, sanitizer_memo_offset))
            print(after_memo_ind, prev_memo_ind)
            if after_memo_ind !=-1:
                if prev_memo_ind==0:
                    sanitizer_memo_offset += (after_memo_ind-prev_memo_ind)
                else:
                    sanitizer_memo_offset += (after_memo_ind-prev_memo_ind-1)
                data_bytearray, sanitizer_pos_offset = self.change_memo_indexes(data_bytearray, pickle_file_object, after_memo_ind, next_prev_memo_ind, sanitizer_memo_offset, sanitizer_pos_offset)
                prev_after_memo_ind = after_memo_ind
        
        memo_ind_offset_ranges.append((prev_after_memo_ind, len(data_bytearray)-1, sanitizer_memo_offset))
        
        # TODO: uncomment when alfredo corrects his attack
        # new_path_to_pickle_file = join(dir_name, new_pickle_name)
        # self.pickle_ec.write_pickle_from_bytearray(data_bytearray, new_path_to_pickle_file)
        # new_pickle_file_object=self.pickle_ec.read_pickle(new_path_to_pickle_file)
        # data_bytearray = self.change_memo_references(new_pickle_file_object, memo_ind_offset_ranges)

        # step 3    
        new_path_to_pickle_file = join(dir_name, new_pickle_name)
        self.pickle_ec.write_pickle_from_bytearray(data_bytearray, new_path_to_pickle_file)
        return

    def sanitize_bin(self, dir_name, bin_name):
        """
        Params:
            dir_name: the name of the directory where the pickle file is present. 
            pickle_name: the name of the pickle file
            new_pickle_name: the name of the new pickle file that needs to be created.
        
        Returns: 
            None
        
        General steps in sanitisation:
            1. extract pickle file form .bin file
            2. read pickle file and detect malicious opcodes, localize them using the code in Detector
            3.1. use the above localization information to delete the relevant opcodes and replace with empty dictionary if necessary
            3.2. Make sure that the memo indexes in the BINPUT/LONG_BINPUT opcodes are rectified according to offset. 
            3.3. Make sure that the memo index references in the BINGET/LONG_BINGET opcodes are rectified according the reference range.
            4. write to new pickle file
            5. compress the new folder to form new .bin file

        """
        
        # step 1
        self.pickle_ec.extract(dir_name, bin_name)
        
        ## step 2
        unzipped_dir = 'archive'
        path_to_pickle_file = join(dir_name, unzipped_dir, 'data.pkl')        
        pickle_file_object = self.pickle_ec.read_pickle(path_to_pickle_file)
        data_bytearray = self.pickle_ec.read_pickle_to_bytearray(path_to_pickle_file)
        mal_opcode_data = self.detector.get_global_reduce_data(data_bytearray, pickle_file_object)
        
        ## step 3
        
        sanitizer_pos_offset = 0
        sanitizer_memo_offset = 0
        
        next_prev_memo_ind = 0 # will be used to send to chane_memo_indexes
        prev_after_memo_ind = 0

        memo_ind_offset_ranges = []
        for id, val in enumerate(mal_opcode_data):
            global_data = val[0]
            reduce_data = val[1]
            prev_memo_ind = val[2]
            after_memo_ind = val[3]

            if id == len(mal_opcode_data)-1:
                next_prev_memo_ind = len(data_bytearray)-1
            else:
                next_prev_memo_ind = mal_opcode_data[id+1][2]


            start_byte = global_data['pos']-sanitizer_pos_offset
            end_byte = reduce_data['pos']-sanitizer_pos_offset
            sanitizer_pos_offset+=(end_byte-start_byte)

            data_bytearray = self.delete_bytes(data_bytearray, start_byte, end_byte)
            data_bytearray, sanitizer_pos_offset = self.remove_binput(data_bytearray, start_byte, sanitizer_pos_offset)

            data_bytearray = self.write_bytes(data_bytearray, start_byte, bytearray(b'}'))   

            memo_ind_offset_ranges.append((prev_after_memo_ind, prev_memo_ind, sanitizer_memo_offset))
            if after_memo_ind!=-1:    
                if prev_memo_ind==0:
                    sanitizer_memo_offset += (after_memo_ind-prev_memo_ind)
                else:
                    sanitizer_memo_offset += (after_memo_ind-prev_memo_ind-1)
                data_bytearray = self.change_memo_indexes(data_bytearray, pickle_file_object, after_memo_ind, next_prev_memo_ind, sanitizer_memo_offset, sanitizer_pos_offset)
                prev_after_memo_ind = after_memo_ind

        memo_ind_offset_ranges.append((prev_after_memo_ind, len(data_bytearray)-1, sanitizer_memo_offset))

        # TODO: uncomment when alfredo corrects his attack
        # self.pickle_ec.write_pickle_from_bytearray(data_bytearray, path_to_pickle_file)
        # pickle_file_object=self.pickle_ec.read_pickle(path_to_pickle_file)
        # data_bytearray = self.change_memo_references(pickle_file_object, memo_ind_offset_ranges)

        # step 4
        self.pickle_ec.write_pickle_from_bytearray(data_bytearray, path_to_pickle_file)
        
        # step 5 
        self.pickle_ec.compress(dir_name, bin_name, unzipped_dir)
        return

if __name__ == "__main__":
    config_path = '../config_files'
    allowlist_file = 'allowlist.config'
    safeclass_file = 'safeclasses.config'

    sanitizer = Sanitizer(config_path, allowlist_file, safeclass_file)
    bin_name = 'pytorch_model.bin'

    # list_of_unsanitized_pickles=[i for i in os.listdir('../untrusted_picklefiles/') if i.split('.')[1]=='pickle' or i.split('.')[1]=='pkl']
    list_of_unsanitized_pickles=['vit_4.pickle']

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
