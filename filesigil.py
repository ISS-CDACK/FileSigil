'''
Developed By CDAC Kolkata ICTS Team Members Shabdik Chakraborty and Hrishikesh Patra

For Clients To Run Before Closure Report
The primary objective of the program is to identify any prohibited files, folders, or extensions that might contain sensitive information, version details, or coding-related data. These items should not be included in the public release of the application. Additionally, the program will generate hash values for all files within the project directory. This hashing process will help maintain a record to address potential certificate concerns. Lastly, the program will create a compressed version of the project directory in zip format and generate a hash value for the resulting zip file.

For Any Issue or Query related to this program please contact
Hrishikesh Patra<hrishikesh.skl044@cdac.in>
Shabdik Chakraborty <shabdik.skl049@cdac.in>

For Administrative Query Contact
Abhijit Chatterjee <abhijit.chatterjee@cdac.in>, 
Information Security Services, CDAC Kolkata <iss-kol@cdac.in>
'''

'''
File Signature (Don't Delete or Modify this lines unless you know what you are doing)
82 71 86 50 90 87 120 118 99 71 86 121 99 121 66 79 89 87 49 108 79 105 66 73 99 109 108 122 97 71 108 114 90 88 78 111 73 70 66 104 100 72 74 104 73 67 89 103 85 50 104 104 89 109 82 112 97 121 66 68 97 71 70 114 99 109 70 105 98 51 74 48 101 81 61 61
'''

'''
Application Name: FileSigil
Version: 1.2 (Stable)
Release Date: 31st October 2023
File Name: filesigil_v1.2.py
Python Version: 3
Best Suitable Python Version: 3.7
Compiled Python Version:
Supported OS: Windows, Windows Server, Linux
Tested OS Versions: Windows 10, Windows 11
'''

#!/usr/bin/python
import os
import sys
import csv
import shutil
import zipfile
import hashlib
from colorama import Fore, Back, Style, init
import argparse
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from prompt_toolkit.shortcuts import CompleteStyle

# Version of the tool
version = "1.2"
init(autoreset=True)  # Initialize colorama for colored output

# Check if the current OS is Windows (Backslash for Windows / Forward slash for Linux and other Unix-like systems)
path_separator = os.path.sep

# List of forbidden files, folders, and extensions
forbidden_files = ["changelog.txt", "changelogs.txt", "changelogs", "changelog", "changelog.md", "changelogs.md", "readme.md", "readme.txt", "readme"]
forbidden_folders = [".git"]
forbidden_extensions = ['.sql', '.gitignore', '.db', '.log', '.rar', '.zip', '.tar', '.7z']

# Output filenames
output_single_csv = "FilesHashes.csv"
zip_filename = "archive.zip"
output_zip_csv = "zip_hash.csv"

# Project directory (to be set later)
project_dir = ""

# Get the current directory of the script
current_directory = os.path.dirname(__file__)

# Get the path separator based on the operating system
path_separator = os.path.sep

# Get the directory of the executable or script
if getattr(sys, 'frozen', False):
    # If running as a bundled executable
    executable_dir = os.path.dirname(sys.executable)
else:
    # If running as a script
    executable_dir = os.path.dirname(os.path.abspath(__file__))

# Output directory for the tool's generated files
output_dir = os.path.join(executable_dir, "CDAC-K_IntegrityTool_Output")

# Custom action to parse comma-separated lists from command-line arguments
class CommaSeparatedListAction(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        setattr(namespace, self.dest, values.split(','))

# Function for user input with tab completion
def input_with_tab_completion(prompt_text):
    completer = PathCompleter()  # Path completer for file/folder paths
    user_input = prompt(prompt_text, completer=completer, complete_style=CompleteStyle.READLINE_LIKE)
    return user_input

# path Check
def pathCheck(wd, pd_ud):
    # False Stop the program 
    if os.name == "nt":
        if os.path.abspath(pd_ud.lower()).startswith(os.path.abspath(wd.lower())):
            return False
        else:
            return True
    else:
        if os.path.abspath(pd_ud).startswith(os.path.abspath(wd)):
            return False
        else:
            return True

# Function for show banner
def show_banner():
    os.system('cls')
    ascii_art = [
        Fore.CYAN + " _____ _ _      ____  _       _ _ ",
        Fore.CYAN + "|  ___(_) | ___/ ___|(_) __ _(_) |",
        Fore.CYAN + "| |_  | | |/ _ \___ \| |/ _` | | |",
        Fore.CYAN + "|  _| | | |  __/___) | | (_| | | |",
        Fore.CYAN + "|_|   |_|_|\___|____/|_|\__, |_|_|",
        Fore.CYAN + "                        |___/     "
    ]

    developed_by = Back.BLUE + "Developed by CDAC-K ICTS Team" + Style.RESET_ALL
    description_line1 = "Check for sensitive files, calculates file and zip hash"
    description_line2 = "Ensuring project integrity and security"
    description_line3 = "--help or -h for more options"
    version_text = Back.YELLOW + "Version " + version + Style.RESET_ALL
    combined_text = ascii_art + [developed_by, description_line1, description_line2, description_line3, version_text]
    max_width = max(len(line) for line in combined_text)
    terminal_width, _ = shutil.get_terminal_size()
    logo_indentation = (terminal_width - max_width) // 2
    developed_by_indentation = logo_indentation + 2
    description_indentation = logo_indentation - 2
    version_indentation = logo_indentation + 3
    for idx, line in enumerate(combined_text):
        if line == developed_by:
            print(" " * developed_by_indentation + line.center(max_width))
        elif line == description_line1:
            print(" " * description_indentation + line.center(max_width))
        elif line == description_line2:
            print(" " * description_indentation + line.center(max_width))
        elif line == description_line3:
            print(" " * description_indentation + line.center(max_width))
        elif line == version_text:
            print(" " * version_indentation + line.center(max_width))
        else:
            print(" " * logo_indentation + line.center(max_width))
    print(Style.RESET_ALL)

# Function for Check forbidden files folders and extensions
def check_files_in_folder(folder_path, forbidden_files=[], forbidden_folders=[], forbidden_extensions=[]):
    found_forbidden_files = []
    found_forbidden_folders = []
    found_forbidden_extensions = []
    if not os.path.exists(folder_path) or not os.path.isdir(folder_path):
        return found_forbidden_files, found_forbidden_folders, found_forbidden_extensions
    folder_contents = os.listdir(folder_path)
    for item in folder_contents:
        item_path = os.path.join(folder_path, item)
        lower_item = item.lower()
        if lower_item in [name.lower() for name in forbidden_files]:
            found_forbidden_files.append(item_path)
        if lower_item in [name.lower() for name in forbidden_folders]:
            found_forbidden_folders.append(item_path)
        if any(lower_item.endswith(ext.lower()) for ext in forbidden_extensions):
            found_forbidden_extensions.append(item_path)
        if os.path.isdir(item_path):
            nested_results = check_files_in_folder(item_path, forbidden_files, forbidden_folders, forbidden_extensions)
            if nested_results:
                nested_forbidden_files, nested_forbidden_folders, nested_forbidden_extensions = nested_results
                found_forbidden_files.extend(nested_forbidden_files)
                found_forbidden_folders.extend(nested_forbidden_folders)
                found_forbidden_extensions.extend(nested_forbidden_extensions)
    if not found_forbidden_files and not found_forbidden_folders and not found_forbidden_extensions:
        return False
    else:
        return found_forbidden_files, found_forbidden_folders, found_forbidden_extensions

# Function for creating zip
def zip_folder(folder_path, zip_filename):
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                arcname = os.path.relpath(file_path, folder_path)
                zipf.write(file_path, arcname)

# Function for calculate hash of provided file
def calculate_hashes(file_path):
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        chunk = f.read(8192)
        while chunk:
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
            chunk = f.read(8192)
    return md5_hash.hexdigest(), sha256_hash.hexdigest()

# Function for calculate hash of files and save them in csv
def hash(folder_path, output_csv):
    with open(output_csv, "w", newline="") as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(["File Path", "MD5 Hash", "SHA256 Hash"])
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                md5_hash, sha256_hash = calculate_hashes(file_path)
                csv_writer.writerow([file_path, md5_hash, sha256_hash])

# Function for calculating hash of provided zip file
def calculate_hash_zip(file_path, hash_algorithm):
    hash_object = hashlib.new(hash_algorithm)
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_object.update(chunk)
    return hash_object.hexdigest()

# Function for calculating hash of provided zip file and save it in csv
def hash_zip(file_path, output_csv):
    md5_hash = calculate_hash_zip(file_path, 'md5')
    sha256_hash = calculate_hash_zip(file_path, 'sha256')
    with open(output_csv, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(['Zip Path', 'MD5 Hash', 'SHA256 Hash'])
        csv_writer.writerow([file_path, md5_hash, sha256_hash])
    return md5_hash, sha256_hash

def main():
    if mode == "Default":
        print(f"Operation Mode: " + Back.GREEN + "Default" + Style.RESET_ALL)
    else:
        print(f"Operation Mode: " + Back.RED + "Manual" + Style.RESET_ALL)
    
    if forbidden_files:
        print(f"Blacklisted Files: {', '.join([Back.RED + item + Style.RESET_ALL for item in forbidden_files])}")
    else:
        print(f"Blacklisted Files: " + Back.RED + "None" + Style.RESET_ALL + Fore.RED + " (Everything Allowed)" + Style.RESET_ALL)
    
    if forbidden_folders:
        print(f"Blacklisted Folders: {', '.join([Back.RED + item + Style.RESET_ALL for item in forbidden_folders])}")
    else:
        print(f"Blacklisted Folders: " + Back.RED + "None" + Style.RESET_ALL + Fore.RED + " (Everything Allowed)" + Style.RESET_ALL)
    
    if forbidden_extensions:
        print(f"Blacklisted Extensions: {', '.join([Back.RED + item + Style.RESET_ALL for item in forbidden_extensions])}")
    else:
        print(f"Blacklisted Extensions: " + Back.RED + "None" + Style.RESET_ALL + Fore.RED + " (Everything Allowed)" + Style.RESET_ALL)

    print(Back.MAGENTA + "Output Directory:" + Style.RESET_ALL + " " + output_dir)
    print(Back.MAGENTA + "CSV File Name:" + Style.RESET_ALL + " " + output_single_csv + " (" + output_dir + path_separator + output_single_csv +")")
    print(Back.MAGENTA + "ZIP File Name:" + Style.RESET_ALL + " " + zip_filename + " (" + output_dir + path_separator + zip_filename +")")
    print(Back.MAGENTA + "ZIP CSV File Name:" + Style.RESET_ALL + " " + output_zip_csv + " (" + output_dir + path_separator + output_zip_csv +")")
    if project_dir == "":
        while True:
            print()
            folder_path = input_with_tab_completion("Enter the path of the folder: ")
            if folder_path.lower() == "exit()":
                print(Fore.RED + "\nExit command detected. Exiting..." + Style.RESET_ALL)
                sys.exit()
            if not os.path.exists(folder_path):
                print(Fore.RED + "Error: Input path do not exist. Please try again, or type exit()" + Style.RESET_ALL)
                continue
            else:
                break
    else:
        print(Back.MAGENTA + "Path of the folder:" + Style.RESET_ALL + " " + project_dir)
        folder_path = project_dir
    folder_path = os.path.abspath(folder_path)
    if not pathCheck(folder_path, current_directory):
        print(Fore.RED + "Run this program from outside of the project directory." + Style.RESET_ALL)
        sys.exit()
    if not pathCheck(folder_path, output_dir):
        print(Fore.RED + "Output directory must outside of the project directory." + Style.RESET_ALL)
        sys.exit()
    found_files = check_files_in_folder(folder_path, forbidden_files, forbidden_folders, forbidden_extensions)
    if found_files != False:
        forbidden_files_found, forbidden_folders_found, forbidden_extensions_found = found_files
        print("")
        if len(forbidden_files_found) != 0:
            print(Back.RED + "Found forbidden file(s):" + Style.RESET_ALL + "\n" + ("\n").join(forbidden_files_found))
            print("")
        if len(forbidden_folders_found) != 0:
            print(Back.RED + "Found forbidden folder(s):" + Style.RESET_ALL + "\n" + ("\n").join(forbidden_folders_found))
            print("")
        if len(forbidden_extensions_found) != 0:
            print(Back.RED + "Found forbidden extension(s):" + Style.RESET_ALL + "\n" + ("\n").join(forbidden_extensions_found))
            print("")
        print(Fore.RED + "!!Aborting Further Operations!! Please Clean Your Work Environment and try again" + Style.RESET_ALL)
    else:
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        print("\n" + Back.GREEN + "No forbidden files, folders, or extensions found." + Style.RESET_ALL)
        hash(folder_path, output_dir + path_separator + output_single_csv)
        print("\n" + Fore.GREEN + "Successfully computed MD5 and SHA256 hashes for all files in the working directory."  + Style.RESET_ALL)
        print("\n" + Back.MAGENTA + "Please Collect the CSV file from:" + Style.RESET_ALL + " " + output_dir + path_separator + output_single_csv)
        print("\n" + Fore.LIGHTYELLOW_EX + "Creating Zip of working directory..." + Style.RESET_ALL)
        zip_folder(folder_path, output_dir + path_separator + zip_filename)
        print("\n" + Back.GREEN + "Zip Operation Successful" + Style.RESET_ALL + " (Path: " + output_dir + path_separator + zip_filename + ")\n")
        zip_md5, zip_sha256 = hash_zip(output_dir + path_separator + zip_filename, output_dir + path_separator + output_zip_csv)
        print("MD5 Hash of ZIP File:\t " + Back.LIGHTYELLOW_EX + str(zip_md5) + Style.RESET_ALL)
        print("SHA256 Hash of ZIP File: " + Back.LIGHTYELLOW_EX + str(zip_sha256) + Style.RESET_ALL)
        print("\n" + Back.GREEN + "Successfully stored Zip Hashes in CSV " + Style.RESET_ALL + " (Path: " + output_dir + path_separator + output_zip_csv + ")")

if __name__ == "__main__":
    show_banner()
    parser = argparse.ArgumentParser(description="A python program developed by " + Back.BLUE + "CDAC-K ICTS Team" + Style.RESET_ALL + ". Current version " + Back.BLUE + str(version) + Style.RESET_ALL + ". Which check for blacklisted files (default files names are " + f"{', '.join([Back.RED + item + Style.RESET_ALL for item in forbidden_files])}" + "); blacklisted folders (default blacklisted folders are " + f"{', '.join([Back.RED + item + Style.RESET_ALL for item in forbidden_folders])}" + "); and also blacklisted file extensions (default blacklisted file extensions are " + f"{', '.join([Back.RED + item + Style.RESET_ALL for item in forbidden_extensions])}" + "). If the check is successful then the code will calculate MD5 and SHA256 hashes for all files that are present in the project directory and save it in a csv, and finally it's create a zip file of the files and directories and calculate MD5 and SHA256 hash of the zip files and save it also in a csv file.")
    parser.add_argument("--input", "-i", type=str, help="Input project directory full path")
    parser.add_argument("--output", "-o", type=str, help="Output directory full path")
    parser.add_argument("--hashcsv", "-hc", type=str, help="enter a name for the hash csv file")
    parser.add_argument("--zipcsv", "-zc", type=str, help="enter a name for the zip hash csv file")
    parser.add_argument("--zip", "-z", type=str, help="enter a name for the zip file")
    parser.add_argument("--file", "-f", help="Enter custom list of blacklisted files (coma separated without space), None for allow everything", action=CommaSeparatedListAction)
    parser.add_argument("--directory", "-d", help="Enter custom list of blacklisted directory's (coma separated  without space), None for allow everything", action=CommaSeparatedListAction)
    parser.add_argument("--extension", "-e", help="Enter custom list of blacklisted extension's (coma separated  without space), None for allow everything", action=CommaSeparatedListAction)
    args = parser.parse_args()
    custom_file = args.file
    custom_dicts = args.directory
    custom_extension = args.extension
    user_input_working_dict = args.input
    user_input_output_dict = args.output
    if user_input_working_dict and user_input_working_dict.endswith('"'):
        user_input_working_dict = os.path.abspath(user_input_working_dict[:-1])
    if user_input_output_dict and user_input_output_dict.endswith('"'):
        user_input_output_dict = os.path.abspath(user_input_output_dict[:-1])
    
    if not custom_file and not custom_dicts and not custom_extension:
        mode = "Default"
    else:
        mode = "Manual"
        if custom_file:
            if (custom_file[0].lower()) == "none" or custom_file[0].strip() == "":
                forbidden_files = []
            else:
                forbidden_files = custom_file
        if custom_dicts:
            if (custom_dicts[0].lower()) == "none" or custom_dicts[0].strip() == "":
                forbidden_folders = []
            else:
                forbidden_folders = custom_dicts
        if custom_extension:
            if (custom_extension[0].lower()) == "none" or custom_extension[0].strip() == "":
                forbidden_extensions = []
            else:
                forbidden_extensions = custom_extension
    if user_input_working_dict is not None:
        if not os.path.exists(user_input_working_dict):
            print(Fore.RED + "Error: Input path do not exist." + Style.RESET_ALL)
            sys.exit()
        else:
            project_dir = user_input_working_dict
            if not pathCheck(user_input_working_dict, current_directory):
                print(Fore.RED + "Place the program out side of project directory." + Style.RESET_ALL)
                sys.exit()
    if user_input_output_dict is not None:
        if not os.path.exists(user_input_output_dict):
            print(Fore.RED + "Error: Output path do not exist." + Style.RESET_ALL)
            sys.exit()
        else:
            output_dir = user_input_output_dict
            if user_input_working_dict is not None:
                if not pathCheck(user_input_working_dict, output_dir):
                    print(Fore.RED + "Output directory must outside of the project directory." + Style.RESET_ALL)
                    sys.exit()
    if args.hashcsv is not None:
        output_single_csv = args.hashcsv
    if args.zipcsv is not None:
        output_zip_csv = args.zipcsv
    if args.zip is not None:
        zip_filename = args.zip
    if (output_single_csv and output_zip_csv) and (output_single_csv != output_zip_csv):
        if output_single_csv.endswith('.csv') and output_zip_csv.endswith('.csv'):
            if not os.path.isabs(output_single_csv) and not os.path.isabs(output_zip_csv):
                if zip_filename.endswith('.zip'):
                    pass
                else:
                    print(Fore.RED + "Error: Not a valid ZIP filename." + Style.RESET_ALL)
                    sys.exit()
            else:
                print(Fore.RED + "Error: Filenames should not be absolute paths." + Style.RESET_ALL)
                sys.exit()
        else:
            print(Fore.RED + "Error: Both Filenames must be valid CSV filenames." + Style.RESET_ALL)
            sys.exit()
    else:
        print(Fore.RED + "Error: Filenames must not be the same."+ Style.RESET_ALL)
        sys.exit()
    try:
        main()
    except KeyboardInterrupt:
        print(Fore.RED + "\nKeyboard interrupt detected. Exiting..." + Style.RESET_ALL)
    finally:
        try:
                try:
                    input(Fore.BLUE + "\nGood Bye.." + Style.RESET_ALL)
                except ValueError:
                    print()
                    pass
        except KeyboardInterrupt:
            pass