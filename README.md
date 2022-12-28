# Keeping Our Pickles Edible
A allowlist-based detection+sanitation library for pytorch models saved using state_dict. This library has the following features:
* An allowlist-based detector that can detect all attacks outside the allowlist for pytorch models that are saved using a state_dict for pickle protocol 2 and below. 
  * The same allowlist-based detector can also detect most attacks outside the allowlist in pickle protocol 5 or below, barring the attacks that bind the attack opcodes with necessary code. 
* An allowlist-based sanitiser for pytorch models saved using state_dict barring attacks that bind attack opcodes with necessary opcodes. 
* A module to inject attacks into a given pytorch binary file saved using state_dict. 

## Usage (Sanitation)
Run ```python code/pipeline.py``` and input the directory in which the binary file exists and the binary file name.
Make sure that the allowlist config file paths are correct. 

```code/pipeline.py``` does the detection of imports outside the allowlist and asks if a sanitation is required. 
The sanitation will be done in an inplace fashion. 
The sanitation outputs a binary file that can be directly used.


## Usage (Attack Injection)
Multiple attack injection samples have been provided with clear usage instructions within the code. Each sample is labled ```code/attacks/attack_sample_<suffix>.py```, with each acheiving a different kind of attack. All but any with suffix "pickle" takes a Hugging Face model binary as input (pickle file otherwise).


  - attack_sample.py: Sequential execution attack that inserts a single webpage
  - attack_sample_email.py: Sequential execution attack that copies the contents of a google drive and emails them to a third party
  - attack_sample_memo.py: Sequential execution attack that leverages the memo to insert a single webpage
  - attack_sample_nested.py: Nested execution attack that inserts a two webpages
  - attack_sample_nested_pickle_proto_4.py: Nested execution attack that inserts a two webpages in protocol 4 to a pickle file
  - attack_sample_pickle_proto_4.py: Sequential execution attack that inserts a single webpage in protocol 4


All of these files can be executed as follows

```
python attacks/attack_sample_<suffix>.py
```
