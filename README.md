# Keeping Our Pickles Edible
A allowlist-based detection+sanitation library for pytorch models saved using state_dict. This library has the following features:
* An allowlist-based detector that can detect all attacks outside the allowlist for pytorch models that are saved using a state_dict for pickle protocol 2 and below. 
  * The same allowlist-based detector can also detect most attacks outside the allowlist in pickle protocol 4 or below, barring the attacks that bind the attack opcodes with necessary code. 
* An allowlist-based sanitiser for pytorch models saved using state_dict barring attacks that bind attack opcodes with necessary opcodes. 
* A module to inject attacks into a given pytorch binary file saved using state_dict. 

## Usage
Run ```python pipeline.py``` and input the directory in which the binary file exists and the binary file name.
Make sure that the allowlist config file paths are correct. 

```pipeline.py``` does the detection of imports outside the allowlist and asks if a sanitation is required. 
The sanitation will be done in an inplace fashion. 
The sanitation outputs a binary file that can be directly used.


## Add usage for attack injection. 