import pickletools
import io
import transformers
from transformers import AutoModel
import zipfile 
import os
from os.path import join

import sys
dir_path = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.abspath(os.path.join(dir_path, os.pardir)))

from extract_pickle import PickleEC

class Sanitizer():
    def __init__(self):
        self.pickle_ec = PickleEC()
    
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
    
    def sanitize(self, dir_name, bin_name):
        # general steps in sanitisation
        # 1. extract pickle file form .bin file
        # 2. read pickle file and detect malicious opcodes, localize them
        # 3. use the above localization information to delete the relevant opcodes and replace with empty dictionary if necessary
        # 4. write to new pickle file
        # 5. compress the new folder to form new .bin file
        self.pickle_ec.extract(dir_name, bin_name)
        
        ## TODO: write detection part

        start_byte=2
        end_byte=220

        unzipped_dir = 'archive'
        path_to_pickle_file = join(dir_name, unzipped_dir, 'data.pkl')
        data_bytearray = self.pickle_ec.read_pickle_to_bytearray(path_to_pickle_file)
        data_bytearray = self.delete_bytes(data_bytearray, start_byte, end_byte)

        # TODO check condition when the below line is is needed
        data_bytearray = self.write_bytes(data_bytearray, start_byte, bytearray(b'}'))        
        
        
        self.pickle_ec.write_pickle_from_bytearray(data_bytearray, path_to_pickle_file)
        self.pickle_ec.compress(dir_name, bin_name, unzipped_dir)


sanitizer = Sanitizer()
bin_name = 'pytorch_model.bin'

sanitizer.sanitize('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal', bin_name)

# Sanitizer.delete_bytes('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal', bin_name, start_byte, end_byte)
# Sanitizer.compress_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal', bin_name)
sanitizer.test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/ben')
sanitizer.test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal')
while True:
    q=input()
    if q=='q':
        break
sanitizer.test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal_control')



# import pickletools
# import io
# import transformers
# from transformers import AutoModel
# import zipfile 
# import os
# import subprocess
# # import zipfile
# # with zipfile.ZipFile(path_to_zip_file, 'r') as zip_ref:
# #     zip_ref.extractall(directory_to_extract_to)
# import shutil 
# # shutil.make_archive(output_filename, 'zip', dir_name)


# dir_name = './local_folder'
# bin_name = 'pytorch_model.bin'
# start_byte=2
# end_byte=220

# def extract_pkl(dir_name, bin_name):
#     with zipfile.ZipFile(os.path.join(dir_name, bin_name), 'r') as zip_ref:
#         zip_ref.extractall(dir_name)
#     return

# def compress_pkl(dir_name, bin_name):
#     print('cd '+dir_name+'; zip -r '+bin_name+' '+'archive/')
#     subprocess.run('cd '+dir_name+'; zip -r '+bin_name+' '+'archive/', shell=True, capture_output=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#     # shutil.make_archive(os.path.join(dir_name, bin_name), 'zip', os.path.join(dir_name, 'archive'))
#     # os.rename(str(os.path.join(dir_name, bin_name))+".zip", os.path.join(dir_name, bin_name))
#     return

# def test_pkl(dir_name):
#     print("loading model from ", dir_name)
#     from transformers import AutoModel
#     model = AutoModel.from_pretrained(dir_name) # or load from HF hub
#     print(model)

# def delete_bytes(dir_name, bin_name, start_byte, end_byte):

#     extract_pkl(dir_name, bin_name)
    
#     unzipped_path = 'archive/data.pkl'

#     with open(os.path.join(dir_name, unzipped_path), 'rb') as f:
#         data=io.BytesIO(f.read())

#     data_bytearray=bytearray(data.read())
#     for i in range(start_byte, end_byte+1):
#         del data_bytearray[start_byte]
#     data_bytearray[start_byte:start_byte]=bytearray(b'}')
#     new_unzipped_path = 'archive/data_new.pkl'
#     with open(os.path.join(dir_name, new_unzipped_path), 'wb') as f:
#         f.write(data_bytearray)
#     os.remove(os.path.join(dir_name, unzipped_path))
#     os.rename(os.path.join(dir_name, new_unzipped_path), os.path.join(dir_name, unzipped_path))
#     return
# # extract_pkl('./ben', bin_name)
# delete_bytes('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal', bin_name, start_byte, end_byte)
# compress_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal', bin_name)
# test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/ben')
# test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal')
# while True:
#     q=input()
#     if q=='q':
#         break
# test_pkl('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal_control')