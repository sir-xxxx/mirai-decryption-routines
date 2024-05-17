# Mirai Decryption Routines
The Mirai String Decryption Script is designed to automate the identification and decryption of strings in Mirai malware samples. This script is implemented as generically as possible to support different processor architectures.       
Currently, it detects and supports three different types of decryption routines:

- **Shift XOR**
- **RC4**
- **Bruteforce XOR**

The first two routines are primarily used for string decryption, while the Bruteforce XOR is used for decrypting brute force credentials.If the strings can be loaded, the script also decrypts and prints them out. However, this functionality is not fully generic and may not work in all cases. In such instances, decryption needs to be done manually, or new methods for loading strings can be implemented in the script.

## Features
- **Automated Detection and Decryption**: Automatically identifies and decrypts strings in Mirai malware samples.
- **Support for Multiple Architectures**: Designed to be generic and support different processor architectures.
- **Decryption Routine Types**:
  - **Shift XOR**: Used for string decryption.
  - **RC4**: Used for string decryption.
  - **Bruteforce XOR**: Used for decrypting brute force credentials.
- **String Loading and Decryption**: Attempts to load and decrypt strings, printing them out if successful. Contributions are welcome to improve this functionality for unsupported cases.

## Usage

To use the Mirai String Decryption script, follow these steps:

**Clone the repository**:
   ```sh
   git clone https://github.com/sir-xxxx/mirai-decryption-routines.git
   ```

### Ghidra UI

1. Open Ghidra and navigate to the **Script Manager**.
2. Add the directory of the downloaded Git repository to the Script directories:
   - Click the **Manage Script Directories** button.
   - Add the directory of the cloned repository.
3. Refresh the script list:
   - Click the **Refresh Script List** button.
4. The script should now be visible under `Analysis/Mirai/` and can be executed for the currently open binary.

### Ghidra Headless

1. After downloading the repository, run the headless command against an existing Ghidra project to analyze the binaries in that project for the Mirai decryption routines:
   ```sh
   analyzeHeadless $(pwd)/<ghidra-project> <ghidra-mirai-project> -scriptPath $(pwd) -postScript miraiDecryptionRoutines.java "verbose" -process -scriptlog mirai.log```

## Contact
For more information, please contact ([@Sir_X](mailto:sir_xxxx@protonmail.com)).