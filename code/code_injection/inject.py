import json
from args import parse_args

# Parse our arguments
args = parse_args(None)

# Load in our config file we'll be using to define which models to attack
conf = json.load(args.attack_config)
model_imports = conf["model_imports"]
model_pre_dirs = conf["model_pre_dirs"]
attack_types = conf["attack_types"]
attack_indices = conf["attack_indices"]

# Move on to attacking each listed model

