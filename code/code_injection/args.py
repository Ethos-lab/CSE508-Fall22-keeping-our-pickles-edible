import argparse

def parse_args(callback=None):
    parser = argparse.ArgumentParser()
    # File Arguments
    parser.add_argument(
        "--in_file", "-f", type=str, default="untitled.pickle", help="File to inject attack into"
    )
    parser.add_argument(
        "--out_file", "-o", type=str, default=None, help="Out file to save modified pickle into"
    )

    # Attack-Specific Parameters
    parser.add_argument(
        "--attack_index", "-N", type=int, default=None, help="Opcode index to introduce attack in"
    )
    parser.add_argument(
        "--attack_type", type=str, default="eval/exec", help="Type of attack to carry out"
    )
    parser.add_argument(
        "--attack_contents", type=str, default="attack.txt", help="File containing contents of attack"
    )

    # Might want to use a callback to retroactively add more arguments
    if callback is not None:
        parser = callback(parser)

    # Retrieve our arguments
    args = parser.parse_args()
    return args