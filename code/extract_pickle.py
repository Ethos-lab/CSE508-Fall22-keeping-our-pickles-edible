import zipfile 
import io
import os
from os.path import join
import subprocess

class PickleEC():
    def __init__(self):
        pass
    
    @staticmethod
    def extract(dir_name, bin_name):
        with zipfile.ZipFile(join(dir_name, bin_name), 'r') as zip_ref:
            zip_ref.extractall(dir_name)
        return

    @staticmethod
    def compress(working_dir, bin_name, source_dir):
        print('cd '+working_dir+'; zip -r '+bin_name+' '+source_dir+'/')
        subprocess.run('cd '+working_dir+'; zip -r '+bin_name+' '+source_dir+'/', shell=True, capture_output=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return
    
    @staticmethod
    def read_pickle_to_bytearray(path_to_pickle_file):
        with open(path_to_pickle_file, 'rb') as f:
            data=io.BytesIO(f.read())
        data_bytearray=bytearray(data.read())
        return data_bytearray
    
    @staticmethod
    def read_pickle(path_to_pickle_file):
        f = open(path_to_pickle_file, 'rb') 
        return f

    @staticmethod
    def write_pickle_from_bytearray(data_bytearray, path_to_pickle_file):
        if os.path.isfile(path_to_pickle_file):
            os.remove(path_to_pickle_file)
        with open(path_to_pickle_file, 'wb') as f:
            f.write(data_bytearray)