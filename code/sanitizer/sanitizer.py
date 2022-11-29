import pickletools
import io
import transformers
from transformers import AutoModel
from transformers import RobertaTokenizer, RobertaModel
from pickletools import opcodes as opcode_lib
import zipfile
import os
from os.path import join
import pdb

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
        self.MAX_BYTE = 0xFF

    @staticmethod
    def test_pkl(class_to_load, dir_name):
        print("Loading model from ", dir_name)
        model = class_to_load.from_pretrained(dir_name)  # or load from HF hub
        print(model)

    @staticmethod
    def write_bytes(data_bytearray, pos, value_bytearray):
        data_bytearray[pos:pos] = value_bytearray
        return data_bytearray

    @staticmethod
    def delete_bytes(data_bytearray, start_byte, end_byte):
        del data_bytearray[start_byte:end_byte + 1]
        return data_bytearray

    def change_memo_indexes(self, data_bytearray, pickle_file_obj, start_scope, end_scope, binput_arg_offset,
                            pos_offset):
        """
        Params:
            data_bytearray: a bytearray containing binary data that has been edited. 
            pickle_file_obj: the object to the unchanged pickle file
            start_scope: the first memo index that needs to be changed by "binput_arg_offset"
            end_scope: the last memo index that needs to be changed by "binput_arg_offset"
            binput_arg_offset: the offset introduced due to deletion of binput/long_binput calls
            pos_offset: the current running position offset with respect to the undeleted version of pickle file (say
            from pickle_file obj)
        
        Returns:
            data_bytearray: a bytearray with all memo indexes adjusted by 'binput_arg_offset'
            pos_offset: the running offset after changing memo indexes for binput/long_binput calls

        This takes into account that after index 0xFF, BINPUT can't handle the index numbers so LONG_BINPUT is used. 
        """
        binput_in_bytes = bytearray('q'.encode('raw_unicode_escape'))
        long_binput_in_bytes = bytearray('r'.encode('raw_unicode_escape'))

        memo_opcode_data = self.detector.get_memo_opcodes_between_memo_indexes(pickle_file_obj, start_scope, end_scope)
        for id, val in enumerate(memo_opcode_data):

            offsetted_ind = val['arg'] - binput_arg_offset
            offsetted_pos = val['pos'] - pos_offset
            if val['info'].name == 'BINPUT':
                data_bytearray = self.delete_bytes(data_bytearray, offsetted_pos, offsetted_pos + 1)
                data_bytearray = self.write_bytes(data_bytearray, offsetted_pos,
                                                  binput_in_bytes + bytearray(offsetted_ind.to_bytes(1, 'little')))
            elif val['info'].name == 'LONG_BINPUT':
                if offsetted_ind <= self.MAX_BYTE:
                    data_bytearray = self.delete_bytes(data_bytearray, offsetted_pos, offsetted_pos + 4)
                    data_bytearray = self.write_bytes(data_bytearray, offsetted_pos,
                                                      binput_in_bytes + bytearray(offsetted_ind.to_bytes(1, 'little')))
                    pos_offset += 3
                else:
                    data_bytearray = self.delete_bytes(data_bytearray, offsetted_pos, offsetted_pos + 4)
                    data_bytearray = self.write_bytes(data_bytearray, offsetted_pos, long_binput_in_bytes + bytearray(
                        offsetted_ind.to_bytes(4, 'little')))

        return data_bytearray, pos_offset

    def change_memo_references(self, pickle_file_obj, memo_offset_ranges):
        """
        Params:
        pickle_file_obj: the object to the changed pickle file with no running pos offsets to the changes
        made.
        memo_offset_ranges: the offset ranges to rectify binget/long_binget calls. the ranges include the
        ```start memo id```, ```end memo id``` and the offset for the range.
        
        Returns:
            data_bytearray: a bytearray with all binget/long_bingets references rectified to correct memo indexes.

        This takes into account that after index 0xFF, BINGET can't handle the index numbers so LONG_BINGET is used. 
        This method is necessary because the attacker may have changed the memo indexes in BINGET references to make
        sure the model doesn't break.
        """

        binget_in_bytes = bytearray('h'.encode('raw_unicode_escape'))
        long_binget_in_bytes = bytearray('j'.encode('raw_unicode_escape'))
        pos_offset = 0

        data_bytearray = self.pickle_ec.read_pickle_from_file_obj_to_bytearray(pickle_file_obj)

        memo_get_calls_data = self.detector.get_memo_get_calls(pickle_file_obj)
        # print("Memo get calls data", memo_get_calls_data)
        for id, val in enumerate(memo_get_calls_data):
            memo_offset = -1
            for range_tup in memo_offset_ranges:
                if range_tup[0] <= val['arg'] <= range_tup[1]:
                    memo_offset = range_tup[2]
            if memo_offset == -1:
                print("The pickle file is corrupted and beyond repair as the malicious code contains some code necessary for the execution of the file, which if removed would break the structure of the pickle file.")
                sys.exit(0)

            offsetted_ind = val['arg'] - memo_offset
            offsetted_pos = val['pos'] - pos_offset
            if val['info'].name == 'BINGET':
                data_bytearray = self.delete_bytes(data_bytearray, offsetted_pos, offsetted_pos + 1)
                data_bytearray = self.write_bytes(data_bytearray, offsetted_pos,
                                                  binget_in_bytes + bytearray(offsetted_ind.to_bytes(1, 'little')))
            elif val['info'].name == 'LONG_BINGET':
                if offsetted_ind <= self.MAX_BYTE:
                    data_bytearray = self.delete_bytes(data_bytearray, offsetted_pos, offsetted_pos + 4)
                    data_bytearray = self.write_bytes(data_bytearray, offsetted_pos,
                                                      binget_in_bytes + bytearray(offsetted_ind.to_bytes(1, 'little')))
                    pos_offset += 3
                else:
                    data_bytearray = self.delete_bytes(data_bytearray, offsetted_pos, offsetted_pos + 4)
                    data_bytearray = self.write_bytes(data_bytearray, offsetted_pos, long_binget_in_bytes + bytearray(
                        offsetted_ind.to_bytes(4, 'little')))
        return data_bytearray

    @staticmethod
    def remove_binput(data_bytearray, start_pos, pos_offset):
        """
        Params:
        data_bytearray: input bytearray which needs removal of binput/long_binput after the global-to-reduce
        part of attack has already been removed.
        start_pos: the index where the binput will be present, since the global-to-reduce part has already been removed.
        pos_offset: the current byte position offset between the data_bytearray and the unchanged pickle file.
        
        Returns:
            data_bytearray: after removing binput/long_binput only if a pop is called after this binput/long_binput. 
            pos_offset: updated offset due to deletions in the data_bytearray. 
        """
        if data_bytearray[start_pos:start_pos + 1] == bytearray(b'q'):  # binput
            if data_bytearray[start_pos + 2:start_pos + 3] == bytearray(b'0'):
                del data_bytearray[start_pos:start_pos + 2]
                pos_offset += 2
        elif data_bytearray[start_pos:start_pos + 1] == bytearray(b'r'):
            if data_bytearray[start_pos + 5:start_pos + 6] == bytearray(b'0'):
                del data_bytearray[start_pos:start_pos + 5]
                pos_offset += 5
        return data_bytearray, pos_offset

    @staticmethod
    def remove_memoize(data_bytearray, start_pos, pos_offset):
        """
        Params:
        data_bytearray: input bytearray which needs removal of binput/long_binput after the global-to-reduce
        part of attack has already been removed.
        start_pos: the index where the binput will be present, since the global-to-reduce part has already been removed.
        pos_offset: the current byte position offset between the data_bytearray and the unchanged pickle file.

        Returns:
            data_bytearray: after removing binput/long_binput only if a pop is called after this binput/long_binput.
            pos_offset: updated offset due to deletions in the data_bytearray.
        """
        if data_bytearray[start_pos:start_pos + 1] == bytearray(b'\x94'):  # binput
            if data_bytearray[start_pos + 2:start_pos + 3] == bytearray(b'0'):
                del data_bytearray[start_pos:start_pos + 2]
                pos_offset += 2
        return data_bytearray, pos_offset

    def delete_and_rectify(self, dir_name, new_pickle_name, data_bytearray, file_obj, mal_opcode_data, proto=2):
        if proto < 4:
            return self._delete_and_rectify_proto2(dir_name, new_pickle_name, data_bytearray, file_obj, mal_opcode_data)
        else:
            return self._delete_and_rectify_proto4(dir_name, new_pickle_name, data_bytearray, file_obj, mal_opcode_data)

    def _delete_and_rectify_proto2(self, dir_name, new_pickle_name, data_bytearray, file_obj, mal_opcode_data):

        sanitizer_pos_offset = 0  # needed coz deletions will happen
        sanitizer_memo_offset = 0  # needed coz binput args will get changed

        next_attack_bef_binput_arg = 0  # will be used to set scope in change_memo_indexes
        prev_attack_aft_binput_arg = 0  # will be used to set offset ranges for binput args

        binput_arg_offset_ranges = []
        for id, val in enumerate(mal_opcode_data):

            global_data = val[0]
            reduce_data = val[1]
            bef_attack_binput_arg = val[2]
            aft_attack_binput_arg = val[3]

            if id == len(mal_opcode_data) - 1:
                next_attack_bef_binput_arg = 1000000000000
            else:
                next_attack_bef_binput_arg = mal_opcode_data[id + 1][2]

            start_byte = global_data['pos'] - sanitizer_pos_offset
            end_byte = reduce_data['pos'] - sanitizer_pos_offset
            sanitizer_pos_offset += (end_byte - start_byte)
            data_bytearray = self.delete_bytes(data_bytearray, start_byte, end_byte)
            data_bytearray, sanitizer_pos_offset = self.remove_binput(data_bytearray,
                                                                      start_byte, sanitizer_pos_offset)

            data_bytearray = self.write_bytes(data_bytearray, start_byte, bytearray(b'}'))

            binput_arg_offset_ranges.append((prev_attack_aft_binput_arg,
                                             bef_attack_binput_arg, sanitizer_memo_offset))
            if aft_attack_binput_arg != 1000000000000:
                if bef_attack_binput_arg == 0:
                    sanitizer_memo_offset += (aft_attack_binput_arg - bef_attack_binput_arg)
                else:
                    sanitizer_memo_offset += (aft_attack_binput_arg - bef_attack_binput_arg - 1)
                data_bytearray, sanitizer_pos_offset = self.change_memo_indexes(data_bytearray, file_obj,
                                                                                aft_attack_binput_arg,
                                                                                next_attack_bef_binput_arg,
                                                                                sanitizer_memo_offset,
                                                                                sanitizer_pos_offset)
                prev_attack_aft_binput_arg = aft_attack_binput_arg

        binput_arg_offset_ranges.append((prev_attack_aft_binput_arg, 1000000000000, sanitizer_memo_offset))

        new_path_to_pickle_file = join(dir_name, new_pickle_name)
        # print(new_path_to_pickle_file)

        self.pickle_ec.close_fileobj(file_obj)

        self.pickle_ec.write_pickle_from_bytearray(data_bytearray, new_path_to_pickle_file)
        new_pickle_file_object = self.pickle_ec.read_pickle(new_path_to_pickle_file)
        data_bytearray = self.change_memo_references(new_pickle_file_object, binput_arg_offset_ranges)

        return data_bytearray

    def _delete_and_rectify_proto4(self, dir_name, new_pickle_name, data_bytearray, file_obj, mal_opcode_data):
        """
        Params:
            ...
            mal_opcode_data: A list containing the information about all the attack calls. The data in the
            list will be in the following format:
            [sub_list, REDUCE_data, bef_attack_memo_arg, after_attack_memo_arg] and the sub_list will be a
            list of [first_BINUNI_data, second_BINUNI_data, STACK_GLOBAL_data]. There can be
            multiple such lists in mal_opcode_data.

            All the opcodes data are a dict of {'info', 'arg', 'pos'}
        """
        sanitizer_pos_offset = 0  # needed coz deletions will happen
        sanitizer_memo_offset = 0  # needed coz binput args will get changed

        next_attack_bef_binput_arg = 0  # will be used to set scope in change_memo_indexes
        prev_attack_aft_binput_arg = 0  # will be used to set offset ranges for binput args

        binput_arg_offset_ranges = []
        for id, val in enumerate(mal_opcode_data):

            stack_global_data = val[0]
            reduce_data = val[1]
            bef_attack_binput_arg = val[2]
            aft_attack_binput_arg = val[3]

            if id == len(mal_opcode_data) - 1:
                next_attack_bef_binput_arg = 1000000000000
            else:
                next_attack_bef_binput_arg = mal_opcode_data[id + 1][2]

            start_byte = stack_global_data[0]['pos'] - sanitizer_pos_offset
            end_byte = reduce_data['pos'] - sanitizer_pos_offset
            sanitizer_pos_offset += (end_byte - start_byte)
            data_bytearray = self.delete_bytes(data_bytearray, start_byte, end_byte)
            data_bytearray, sanitizer_pos_offset = self.remove_memoize(data_bytearray,
                                                                      start_byte, sanitizer_pos_offset)

            data_bytearray = self.write_bytes(data_bytearray, start_byte, bytearray(b'}'))

            binput_arg_offset_ranges.append((prev_attack_aft_binput_arg,
                                             bef_attack_binput_arg, sanitizer_memo_offset))
            if aft_attack_binput_arg != 1000000000000:
                if bef_attack_binput_arg == 0:
                    sanitizer_memo_offset += (aft_attack_binput_arg - bef_attack_binput_arg)
                else:
                    sanitizer_memo_offset += (aft_attack_binput_arg - bef_attack_binput_arg - 1)
                prev_attack_aft_binput_arg = aft_attack_binput_arg

        binput_arg_offset_ranges.append((prev_attack_aft_binput_arg, 1000000000000, sanitizer_memo_offset))
        # print(binput_arg_offset_ranges)
        new_path_to_pickle_file = join(dir_name, new_pickle_name)
        # print(new_path_to_pickle_file)

        self.pickle_ec.close_fileobj(file_obj)

        self.pickle_ec.write_pickle_from_bytearray(data_bytearray, new_path_to_pickle_file)
        new_pickle_file_object = self.pickle_ec.read_pickle(new_path_to_pickle_file)
        data_bytearray = self.change_memo_references(new_pickle_file_object, binput_arg_offset_ranges)

        return data_bytearray

    def sanitize_pickle(self, dir_name, pickle_name, new_pickle_name):
        """
        Params:
            dir_name: the name of the directory where the pickle file is present. 
            pickle_name: the name of the pickle file
            new_pickle_name: the name of the new pickle file that needs to be created.
        
        Returns: 
            None
        
        General steps in sanitization:
            1.1. read pickle file
            1.2 Detect protocol and reuse of attack global calls
            1.3 Localize them using the code in Detector depending on the presence of nested attack or not.
            2.1. use the above localization information to delete the relevant opcodes and replace with empty dictionary
             if necessary
            2.2. Make sure that the memo indexes in the BINPUT/LONG_BINPUT opcodes are rectified according to offset. 
            2.3. Make sure that the memo index references in the BINGET/LONG_BINGET opcodes are rectified according the
             reference range.
            3. write to new pickle file
        
        """
        
        # step 1.1
        path_to_pickle_file = join(dir_name, pickle_name)
        pickle_file_object = self.pickle_ec.read_pickle(path_to_pickle_file)
        data_bytearray = self.pickle_ec.read_pickle_to_bytearray(path_to_pickle_file)

        # step 1.2
        proto = self.detector.get_protocol(pickle_file_object)
        print("PROTO", proto)
        global_reuse_dict = self.detector.get_global_reuse_data(pickle_file_object, proto=proto)
        # print("global_reuse_data", global_reuse_dict)
        # step 1.3: detected parts with malicious code that needs to be removed.

        if self.detector.exists_nested_attack(pickle_file_object, global_reuse_dict, proto=proto):
            mal_opcode_data = self.detector.get_nested_attack_data(data_bytearray, pickle_file_object,
                                                                   global_reuse_dict, proto=proto)
        else:
            mal_opcode_data = self.detector.get_global_reduce_data(data_bytearray, pickle_file_object,
                                                                   global_reuse_dict, proto=proto)
        # print("mal_opcode_data", mal_opcode_data)
        # mal_opcode_data: contains global opcode info, reduce opcode info, info about next
        # binput arg and prev binput arg.

        # step 2
        data_bytearray = self.delete_and_rectify(dir_name, new_pickle_name, data_bytearray,
                                                 pickle_file_object, mal_opcode_data, proto=proto)

        # print("After step 2")
        # step 3    
        new_path_to_pickle_file = join(dir_name, new_pickle_name)
        self.pickle_ec.write_pickle_from_bytearray(data_bytearray, new_path_to_pickle_file)

        print('Sanitization successful')
        return

    def sanitize_bin(self, dir_name, binname):
        """
        Params:
            dir_name: the name of the directory where the pickle file is present. 
            pickle_name: the name of the pickle file
            new_pickle_name: the name of the new pickle file that needs to be created.
        
        Returns: 
            None
        
        General steps in sanitisation:
            1. extract pickle file form .bin file
            2. call sanitize_pickle
            3. compress the new folder to form new .bin file

        """

        # step 1
        self.pickle_ec.extract(dir_name, binname)

        # step 2
        if os.path.isdir(join(dir_name, 'archive')):
            unzipped_dir = 'archive'
            path_to_pickle_dir = join(dir_name, unzipped_dir)
            self.sanitize_pickle(path_to_pickle_dir, 'data.pkl', 'data.pkl')
        elif os.path.isdir(join(dir_name, 'pickle_files')):
            unpickled_dir = 'pickle_files'
            path_to_pickle_dir = join(dir_name, unpickled_dir)
            for i in os.listdir(path_to_pickle_dir):
                try:
                    self.sanitize_pickle(path_to_pickle_dir, i, i)
                except Exception as e:
                    print("Can't sanitize "+i+" due to some error", e)
        else:
            # for tar types
            pass

        # step 3 
        self.pickle_ec.compress(dir_name, binname)
        return


if __name__ == "__main__":
    config_path = '../config_files'
    allowlist_file = 'allowlist.config'
    safeclass_file = 'safeclasses.config'

    sanitizer = Sanitizer(config_path, allowlist_file, safeclass_file)
    bin_name = 'pytorch_model.bin'

    # list_of_unsanitized_bin_dir = ['../../../patch-torch-save/example_bins/maskformer/mask_end',
    #                                '../../../patch-torch-save/example_bins/maskformer/mask_end_nested',
    #                                '../../../patch-torch-save/example_bins/resnet',
    #                                '../../../patch-torch-save/example_bins/vit/vit_start',
    #                                '../../../patch-torch-save/example_bins/vit/vit_mul',
    #                                '../../../patch-torch-save/example_bins/yk_automodel',
    #                                '../../../patch-torch-save/roberta/']

    # sanitizer.test_pkl(RobertaModel, list_of_unsanitized_bin_dir[6])
    # while True:
    #     q = input()
    #     if q == 'q':
    #         break

    # sanitizer.sanitize_bin(list_of_unsanitized_bin_dir[6], bin_name)
    # sanitizer.test_pkl(RobertaModel, list_of_unsanitized_bin_dir[6])
    # list_of_unsanitized_pickles=['mask_end_nested.pickle']

    # for unsan_name in list_of_unsanitized_pickles:
    #     print("Sanitizing ", unsan_name)        
    #     sanitizer.sanitize_pickle('../untrusted_picklefiles', unsan_name, "edited_"+unsan_name)
    
    dir_path = '../untrusted_picklefiles/'
    sanitizer.sanitize_pickle(dir_path, 'skops-yu3ifopn-infected.pkl', 'new_pickle.pkl')
    
    # list_of_unsanitized_pickles=['yk_attacked.pickle']

    # for unsan_name in list_of_unsanitized_pickles:
    #     print("Sanitizing ", unsan_name)        
    #     sanitizer.sanitize_pickle('../untrusted_picklefiles', unsan_name, "edited_"+unsan_name)
    
    # sanitizer.test_pkl('C:\Users\Admin\Downloads\patch-torch-save\mal')
    # sanitizer.sanitize_bin('C:\Users\Admin\Downloads\patch-torch-save\mal', bin_name)
    # sanitizer.test_pkl('C:\Users\Admin\Downloads\patch-torch-save\mal')

    # sanitizer.test_pkl('C:\Users\Admin\Downloads\patch-torch-save\patch-torch-save\ben')

    # sanitizer.test_pkl('C:\Users\Admin\Downloads\patch-torch-save\mal_control')

    # sanitizer.test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal')
    # sanitizer.sanitize_bin('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal', bin_name)
    # sanitizer.test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal')

    # sanitizer.test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/ben')

    # sanitizer.test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal_control')
