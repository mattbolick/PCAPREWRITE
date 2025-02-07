# pickle_viewer.py
import pickle
import argparse

def view_pickle(pickle_file):
    """
    Loads and prints the contents of a pickle file.

    Args:
        pickle_file: Path to the pickle file.
    """
    try:
        with open(pickle_file, "rb") as f:
            data = pickle.load(f)
        print(data)

        # Nicely formatted output
        if isinstance(data, dict):
            for key, value in data.items():
                print(f"Key: {key}")
                if isinstance(value, dict):
                    for sub_key, sub_value in value.items():
                         print(f"  {sub_key}: {sub_value}")
                else:
                    print(f"  Value: {value}")
    except Exception as e:
        print(f"Error loading or printing pickle file: {e}")


def main():
    parser = argparse.ArgumentParser(description="View the contents of a pickle file.")
    parser.add_argument("pickle_file", help="Path to the pickle file.")
    args = parser.parse_args()
    view_pickle(args.pickle_file)

if __name__ == "__main__":
    main()
