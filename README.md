# FileSigil - Project Integrity and Security Tool

## Table of Contents
- [Overview](#overview)
- [How to Use FileSigil](#how-to-use-filesigil)
  - [Using Python:](#using-python)
  - [Using Executable:](#using-executable)
- [Results](#results)
- [Contact Information](#contact-information)
- [Disclaimer](#disclaimer)
- [Note](#note)

## Overview

FileSigil is a Python tool developed by CDAC Kolkata ISS Team to help ensure the integrity and security of a pre-production web application. The tool checks for prohibited files, folders, and extensions that may contain sensitive information, version details, or coding-related data. It also generates hash values for all files within the project directory, which can be used to address potential certificate concerns. Additionally, FileSigil creates a compressed version of the project directory in zip format and generates hash values for the resulting zip file.

<p align="center">
  <img src="https://github.com/ISS-CDACK/FileSigil/blob/extras/poc1.png?raw=true" alt="FileSigil"/>
</p>

## How to Use FileSigil

### Using Python:

1. **Prerequisites:**
    * Ensure you have Python 3.7 or a compatible Python 3 version installed on your system.
    * Clone the FileSigil repository using the following command:
    ```
    git clone https://github.com/ISS-CDACK/FileSigil.git
    ```

2. **Install Required Modules:**
    * Navigate to the cloned repository directory.
    * Install the necessary modules using pip (Python's package installer) with the following command:
    ```
    pip install -r requirements.txt
    ```
    or
    ```
    pip3 install -r requirements.txt
    ```

3. **Execute the Script:**
    * Run the `filesigil.py` script using Python with either of the following commands:
    ```
    python filesigil.py
    ```
    or
    ```
    python3 filesigil.py
    ```

### Using Executable:

1. **Download and Extract:**
    * Download the latest release of the executable version from the 'Releases' section.
    * For Linux:
        * Extract the `Linux.tar` file:
        ```
        tar -xf Linux.tar
        ```
        * Provide executable permission to the extracted file:
        ```
        chmod +x filesigil
        ```
        or
        ```
        sudo chmod +x filesigil
        ```
        * Run the tool:
        ```
        ./filesigil
        ```

    * For Windows:
        * Extract the `windows.zip` file.
        * Double click on the application to execute it.

2. **Specify Input and Output Directories:**
    * Utilize the `--input` option to specify the project directory to be checked. The default is the current directory.
    * Utilize the `--output` option to specify the output directory for the generated files. The default is a subdirectory named "CDAC-K_IntegrityTool_Output" within the script's location.

3. **Specify Output File Names:**
    * Use `--hashcsv` to specify the name of the CSV file storing file hashes. Default is "FilesHashes.csv".
    * Use `--zip` to set the name of the generated ZIP file. Default is "archive.zip".
    * Use `--zipcsv` to specify the name of the CSV file containing ZIP file hashes. Default is "zip_hash.csv".

4. **Run the Tool:**
    * After configuring your options, execute the tool. It will identify any blacklisted items, generate file hashes, create a ZIP file, and compute ZIP file hashes.

5. **Exiting the Program:**
    * You can exit the program by pressing Ctrl+C, typing `exit`, or simply closing the terminal.

Now you are ready to use FileSigil efficiently for your integrity checks and file analysis needs.


## Results

The tool will display the results, including any blacklisted items found and the calculated hashes.
You can find the CSV files with the hashes in the output directory.

## Contact Information

If you have any questions or encounter issues related to this program, please contact the following team members:

* Hrishikesh Patra: hrishikesh.skl044@cdac.in
* Shabdik Chakraborty: shabdik.skl049@cdac.in

## Disclaimer

This tool is provided by CDAC Kolkata ISS Team to help ensure the integrity and security of your software projects. It is your responsibility to review the results and take necessary actions to address any issues found. Use this tool with caution and ensure that you have the necessary permissions to analyze the project directory.

## Note

This README provides an overview of FileSigil. For more details, consult the in-code comments and command-line help (use `--help` or `-h` with the script).
