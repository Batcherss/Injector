# encTeamed Injector

`encTeamed Injector` is a utility for injecting a DLL into a target process using **Manual Mapping**. This method allows injecting a DLL into the memory of a process without using standard API functions like `LoadLibrary`, making the injection more stealthy and harder to detect.

## Description

This project utilizes **Windows API** and low-level functions to inject a DLL into the target process's memory. It features a simple dialog for selecting a DLL file and a target process for injection. The injection is performed using manual mapping, which ensures that the process remains undetected by common antivirus software.

### Key Features
- **Manual Mapping**: Injects DLLs using manual mapping, bypassing the standard `LoadLibrary` API.
- **Loading Animation**: Displays a simple loading animation during the injection process.
- **File Dialog**: Allows the user to select the DLL to inject.
- **Process List**: Displays a list of running processes for easy selection of the target process.

## How it Works

1. **DLL Selection**: The user is prompted to choose a DLL file to inject into the target process.
2. **Process Selection**: After selecting the DLL, the user is prompted to enter the name of the target process.
3. **Manual Mapping**: The tool performs manual mapping of the DLL into the target process's memory by allocating space, copying headers and sections, and creating a new thread to start the DLL's execution.

## Requirements

- **Windows Operating System**: The injector relies on Windows-specific APIs.
- **Visual Studio**: For compiling the source code.
- **ntdll.lib**: The project uses functions from `ntdll.dll`, so you must link with `ntdll.lib`.

## How to Use

1. **Compile the Code**: Build the project in Visual Studio.
2. **Run the Injector**: Execute the compiled injector.
3. **Select the DLL**: Use the file dialog to choose the DLL you wish to inject.
4. **Enter the Process Name**: After selecting the DLL, enter the name of the target process you want to inject into (e.g., `example.exe`).
5. **Injection**: The DLL is injected into the selected process using manual mapping.

## Functions

- `AnimateLoading`: Displays an animation while the injector is running.
- `OpenFileDialog`: Opens a dialog to select the DLL to inject.
- `GetProcessList`: Retrieves the list of running processes.
- `FindProcessId`: Finds the process ID based on the process name.
- `ManualMapInject`: Handles the manual mapping injection process.

## Notes

- **Error Handling**: The injector handles several error cases such as invalid DLL format, failure to open processes, and memory allocation issues.
- **Compatibility**: This tool works on modern 64-bit Windows systems.

## Disclaimer

This tool is intended for educational purposes only. Use it responsibly and ensure you have permission to perform injections in the processes you are targeting. Unauthorized usage may violate terms of service or laws in your region.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

