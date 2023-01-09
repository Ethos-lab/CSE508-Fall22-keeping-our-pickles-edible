# Keeping Our Pickles Edible

**Class Project for CSE508: Network Security - Fall 2022**

A allowlist-based detection+sanitation library for pytorch models saved using state_dict. This library has the following features:
* An allowlist-based detector that can detect all attacks outside the allowlist for pytorch models that are saved using a state_dict for pickle protocol 2 and below. 
  * The same allowlist-based detector can also detect most attacks outside the allowlist in pickle protocol 5 or below, barring the attacks in which the stack_global call is not obfuscated. 
* An allowlist-based sanitiser for pytorch models saved using state_dict barring attacks with obfuscated code. 
* A module to inject attacks into a given pytorch binary file saved using state_dict. 

The allowlist is specified in ```config_files/allowlist.config```. Note that this allowlist covers a majority of "allowed" pytorch imports, and is not comprehensive. Please edit it to your needs. 

### Limitations:
* For Protocols 4 and above, the attacker can obfuscate the module import opcodes, making it difficult to detect "restricted" imports.
* For all protocols, the attacker can obfuscate the attack code and make it look like the carrier code, thus making the deletion of attack code (sanitation) difficult to generalize. 

For more details, please read the following project report: [Keeping Our Pickles Edible](https://drive.google.com/file/d/1TP7_19WM1JuN0CLnzLN0C_GV9kn8Q25R/view?usp=sharing)

## Requirements:
* python>=3.4
* tqdm

To run tests:
* torch
* transformers


## Usage (Sanitation)
Run ```python code/pipeline.py``` and input the directory in which the binary file exists and the binary file name.
Make sure that the allowlist config file paths inside ```pipeline.py``` are correct. 

```code/pipeline.py``` does the detection of imports outside the allowlist and asks if a sanitation is required. 
The sanitation will be done in an inplace fashion. 
The sanitation outputs a binary file that can be directly used.


## Usage (Attack Injection)
Multiple attack injection samples have been provided with clear usage instructions within the code. Each sample is labeled ```code/attacks/attack_sample_<suffix>.py```, with each acheiving a different kind of attack. All but any with suffix "pickle" takes a Hugging Face model binary as input (pickle file otherwise).

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

Please edit the variables ```in_bin_dir``` and ```out_bin_dir``` in these files for the input binary file path and output binary file path respectively. 

## Credits
This project is a joint effort by [Alfredo Rivero](https://github.com/alrivero), [Shreejay Jahagirdar](https://github.com/shreejay23), Sanskar Sehgal and [Sai Tanmay Reddy](https://github.com/starc52). This project was conducted as part of CSE508: Network Security course at Stony Brook University in Fall of 2022 and was made public as part of students' request.
