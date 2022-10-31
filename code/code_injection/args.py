import argparse

def parse_args(callback=None):
    parser = argparse.ArgumentParser()
    # File Arguments
    parser.add_argument(
        "--in_file", "-f", type=str, default="untitled.pickle", help="File to inject attack into"
    )
    parser.add_argument(
        "--out_file", "-o", type=str, default="out.pickle", help="Out file to save modified pickle into"
    )
    parser.add_argument(
        "--attack_config", "-a", type=str, default="attacks.json", help="Config file on what and how to attack files"
    )

    # Might want to use a callback to retroactively add more arguments
    if callback is not None:
        parser = callback(parser)

    # Retrieve our arguments
    args = parser.parse_args()
    return args