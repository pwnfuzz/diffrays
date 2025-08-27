#!/usr/bin/env python3

import argparse
from pathlib import Path
import ida_domain
from ida_domain.database import IdaCommandOptions

def sanitize_filename(name):
    # Replace every character that is not a letter, number, or underscore with _
    return re.sub(r'[^A-Za-z0-9_]', '_', name)

def create_folder(file_path):
    file_path = Path(file_path)
    folder_name = file_path.stem
    folder_path = Path(folder_name)
    folder_path.mkdir(parents=True, exist_ok=True)
    return folder_name

def analyze_functions(db_path):
    """Find and analyze functions matching a pattern."""
    ida_options = IdaCommandOptions(auto_analysis=True, new_database=True)
    with ida_domain.Database.open(db_path, ida_options, False) as db:

        folder = create_folder(db_path)
        function_count = 0
        for _ in db.functions:
            function_count += 1
        print(f'Total functions: {function_count}')

        functions = db.functions.get_all()
        for func in functions:
            try:
                name = db.functions.get_name(func)
                print(f'Function: {name}')
                print(f'Address: {hex(func.start_ea)} - {hex(func.end_ea)}')
                signature = db.functions.get_signature(func)
                print(f'Signature: {signature}')
                pseudo = db.functions.get_pseudocode(func)
                safe_name = sanitize_filename(name)
                file_path = os.path.join(folder, f"{safe_name}.c")
                with open(file_path, "w") as f:
                    for line in pseudo:
                        f.write(line + "\n")
                print("-"*50)
            except:
                pass

def main():
    """Main entry point with argument parsing."""
    parser = argparse.ArgumentParser(description='Database exploration example')
    parser.add_argument(
        '-f', '--input-file', help='Binary input file to be loaded', type=str, required=True
    )
    args = parser.parse_args()
    analyze_functions(args.input_file)

if __name__ == '__main__':
    main()