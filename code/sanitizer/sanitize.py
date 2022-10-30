import pickletools
import io
import transformers
from transformers import AutoModel
import zipfile 
import os
# import zipfile
# with zipfile.ZipFile(path_to_zip_file, 'r') as zip_ref:
#     zip_ref.extractall(directory_to_extract_to)
import shutil 
# shutil.make_archive(output_filename, 'zip', dir_name)


dir_name = './local_folder'
bin_name = 'pytorch_model.bin'
start_byte=2
end_byte=220

def extract_pkl(dir_name, bin_name):
    with zipfile.ZipFile(os.path.join(dir_name, bin_name), 'r') as zip_ref:
        zip_ref.extractall(dir_name)
    return

def compress_pkl(dir_name, bin_name):
    print('cd '+dir_name+'; zip -r '+bin_name+' '+'archive/')
    os.system('cd '+dir_name+'; zip -r '+bin_name+' '+'archive/')
    # shutil.make_archive(os.path.join(dir_name, bin_name), 'zip', os.path.join(dir_name, 'archive'))
    # os.rename(str(os.path.join(dir_name, bin_name))+".zip", os.path.join(dir_name, bin_name))
    return

def test_pkl(dir_name):
    print("loading model from ", dir_name)
    from transformers import AutoModel
    model = AutoModel.from_pretrained(dir_name) # or load from HF hub
    print(model)

def delete_bytes(dir_name, bin_name, start_byte, end_byte):

    extract_pkl(dir_name, bin_name)
    
    unzipped_path = 'archive/data.pkl'

    with open(os.path.join(dir_name, unzipped_path), 'rb') as f:
        data=io.BytesIO(f.read())

    data_bytearray=bytearray(data.read())
    for i in range(start_byte, end_byte+1):
        del data_bytearray[start_byte]
    data_bytearray[start_byte:start_byte]=bytearray(b'}')
    new_unzipped_path = 'archive/data_new.pkl'
    with open(os.path.join(dir_name, new_unzipped_path), 'wb') as f:
        f.write(data_bytearray)
    os.remove(os.path.join(dir_name, unzipped_path))
    os.rename(os.path.join(dir_name, new_unzipped_path), os.path.join(dir_name, unzipped_path))
    return
# extract_pkl('./ben', bin_name)
delete_bytes('./mal', bin_name, start_byte, end_byte)
compress_pkl('./mal', bin_name)
test_pkl('./ben')
test_pkl('./mal')
while True:
    q=input()
    if q=='q':
        break
test_pkl('./mal_control')