# DLL Injector

## Description
This project is a DLL Injector written in C++ that allows you to inject a selected DLL file into a specified process. The program utilizes standard Windows API functions to interact with processes and threads, allocate memory, and execute code within the target process.

## Features
- Opens a file dialog to select a DLL file.
- Allows you to select a target process for injection.
- Uses Windows API functions to inject the DLL into the process.

## How It Works
1. The user selects a DLL file using the file dialog.
2. The user specifies the target process by entering its name.
3. The injector locates the process by its name and attempts to inject the selected DLL into it.
4. The injection process is carried out by allocating memory in the target process, writing the DLL path into that memory, and using the `LoadLibraryW` function to load the DLL into the process's memory space.

## Requirements
- Windows Operating System
- Visual Studio or any C++ compatible IDE for building the project.
- Administrator privileges may be required for injecting into system processes.

## Compilation
To compile the project, follow these steps:
1. Open the project in Visual Studio (or your preferred IDE).
2. Build the project in **Release** mode.
3. Run the compiled executable with **Administrator privileges**.

## Usage
1. Launch the program.
2. Select the DLL file to inject.
3. Enter the process name you want to inject the DLL into (e.g., `notepad.exe`).
4. The program will find the process and inject the DLL.

## Notes
- Make sure the DLL you are trying to inject is compatible with the target process.
- The injection method used in this project may trigger antivirus software or security software, as it involves modifying the memory of another running process.
  
## Disclaimer
This tool is intended for educational purposes only. Use responsibly and ensure you have permission to interact with the target processes. Unauthorized use may violate the terms of service of certain applications or platforms.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
