import os
import sys
from os.path import join, isfile, isdir
from sanitizer.sanitizer import Sanitizer
from detector import Detector
from extract_pickle import PickleEC


class Pipeline:
    def __init__(self, config_path, allowlist_file, safeclass_file):
        self.detector = Detector(config_path, allowlist_file, safeclass_file)
        self.sanitizer = Sanitizer(config_path, allowlist_file, safeclass_file)
        self.pickle_ec = PickleEC()

    def magic(self):
        """
        Params:
            None
        Returns:
            None

        General steps in pipeline:
            1. extract pickle file form .bin file
            2. call exists_attack, check for attacks
            3. if attack exists, give option of sanitizer.
            4. sanitize
            5. compress the new folder to form new .bin file
        """
        dir_name = input("Input directory name: ")
        if not isdir(dir_name):
            print("Enter a valid directory name")
            sys.exit(0)
        bin_name = input("Input a binary name: ")
        if not isfile(join(dir_name, bin_name)):
            print("Enter a valid binary name in", dir_name)
            sys.exit(0)

        # step 1
        self.pickle_ec.extract(dir_name, bin_name)

        # step 2
        if os.path.isdir(join(dir_name, 'archive')):
            unzipped_dir = 'archive'
            path_to_pickle_dir = join(dir_name, unzipped_dir)
            exists_attack = self.detector.exists_attack(join(path_to_pickle_dir, 'data.pkl'))
            if exists_attack['result']:
                print("Found attack!")
                for attack in exists_attack['cause']:
                    print(f"Found {attack['arg']} at byte position {attack['pos']} in proto {attack['proto']} opcodes!")
                sanitation_request = \
                    input("Do you want to proceed to sanitation? We provide no guarantees on the functionality of the sanitized file.\nThe sanitation will happen in place. [Y/N]: ")
                if sanitation_request == 'Y':
                    self.sanitizer.sanitize_pickle(path_to_pickle_dir, 'data.pkl', 'data.pkl')
            else:
                print("No attack found! This however provides no guarantee on the non-existence attacks in the file.")
        elif os.path.isdir(join(dir_name, 'pickle_files')):
            unpickled_dir = 'pickle_files'
            path_to_pickle_dir = join(dir_name, unpickled_dir)
            for pickle_file in os.listdir(path_to_pickle_dir):
                try:
                    exists_attack = self.detector.exists_attack(join(path_to_pickle_dir, pickle_file))
                    if exists_attack['result']:
                        print("Found attack!")
                        for attack in exists_attack['cause']:
                            print(f"Found {attack['arg']} at byte position {attack['pos']} in proto {attack['proto']} opcodes!")
                        sanitation_request = \
                            input("Do you want to proceed to sanitation? We provide no guarantees on the functionality of the sanitized file.\nThe sanitation will happen in place. [Y/N]: ")
                        if sanitation_request == 'Y':
                            self.sanitizer.sanitize_pickle(path_to_pickle_dir, pickle_file, pickle_file)
                    else:
                        print("No attack found! This however provides no guarantee on the non-existence attacks in the file.")

                except Exception as e:
                    print("Can't run magic on " + pickle_file + " due to some error ", e)
        else:
            # for tar types
            pass

        # step 3
        self.pickle_ec.compress(dir_name, bin_name)

        return


if __name__ == "__main__":
    config_path = 'config_files'
    allowlist_file = 'allowlist.config'
    safeclass_file = 'safeclasses.config'
    pipeline = Pipeline(config_path, allowlist_file, safeclass_file)
    pipeline.magic()
