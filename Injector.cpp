#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <processthreadsapi.h>
#include <chrono>

#pragma comment(lib, "ntdll.lib")

using namespace std;

typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG AllocationType,
    ULONG Protect);

typedef NTSTATUS(NTAPI* pNtWriteVirtualMemory)(
    HANDLE ProcessHandle,
    PVOID BaseAddress,
    PVOID Buffer,
    ULONG NumberOfBytesToWrite,
    PULONG NumberOfBytesWritten);

typedef struct _PS_ATTRIBUTE {
    ULONG Attribute;
    union {
        ULONG_PTR Value;
        HANDLE Handle;
    };
} PS_ATTRIBUTE, * PPS_ATTRIBUTE;

typedef struct _PS_ATTRIBUTE_LIST {
    ULONG TotalLength;
    PS_ATTRIBUTE Attributes[1];
} PS_ATTRIBUTE_LIST, * PPS_ATTRIBUTE_LIST;


typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PPS_ATTRIBUTE_LIST AttributeList);

typedef NTSTATUS(NTAPI* pNtClose)(HANDLE Handle);

struct MANUAL_MAPPING_DATA
{
    PVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseReloc;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
    pNtCreateThreadEx fnNtCreateThreadEx;
    pNtClose fnNtClose;
    pNtAllocateVirtualMemory fnNtAllocateVirtualMemory;
    pNtWriteVirtualMemory fnNtWriteVirtualMemory;
};

void AnimateLoading(const wstring& message, bool& active) {
    const vector<wstring> frames = { L".  ", L".. ", L"..." };
    int frame = 0;
    while (active) {
        wcout << L"\r" << message << frames[frame];
        frame = (frame + 1) % frames.size();
        this_thread::sleep_for(chrono::milliseconds(300));
    }
    wcout << L"\r" << message << "done!" << endl;
}

wstring OpenFileDialog() {
    wstring path(MAX_PATH, L'\0');

    OPENFILENAME ofn = { 0 };
    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = &path[0];
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = L"DLL Files\0*.dll\0All Files\0*.*\0";
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR;

    if (GetOpenFileName(&ofn)) {
        bool readingActive = true;
        thread animation(AnimateLoading, L"[#] Reading DLL", ref(readingActive));
        this_thread::sleep_for(chrono::seconds(1));
        readingActive = false;
        animation.join();
        return path;
    }
    return L"";
}

vector<pair<DWORD, wstring>> GetProcessList() {
    vector<pair<DWORD, wstring>> processes;
    DWORD aProcesses[1024], cbNeeded;

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return processes;
    }

    DWORD cProcesses = cbNeeded / sizeof(DWORD);
    for (DWORD i = 0; i < cProcesses; i++) {
        if (aProcesses[i] != 0) {
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
            if (hProcess) {
                WCHAR szProcessName[MAX_PATH] = L"<unknown>";
                if (GetModuleFileNameExW(hProcess, NULL, szProcessName, MAX_PATH)) {
                    const wstring name = wcsrchr(szProcessName, L'\\') ? wcsrchr(szProcessName, L'\\') + 1 : szProcessName;
                    processes.emplace_back(aProcesses[i], name);
                    wcout << L"[" << aProcesses[i] << L"] " << name << endl;
                }
                CloseHandle(hProcess);
            }
        }
    }

    return processes;
}

DWORD FindProcessId(const wstring& processName) {
    auto processes = GetProcessList();
    for (const auto& proc : processes) {
        if (_wcsicmp(proc.second.c_str(), processName.c_str()) == 0) {
            return proc.first;
        }
    }
    return 0;
}

bool ManualMapInject(DWORD pid, const wstring& dllPath) {
    bool injectionActive = true;
    thread animation(AnimateLoading, L"[#] Manual Mapping", ref(injectionActive));

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
        FALSE, pid);
    if (!hProcess) {
        wcout << L"[-] Failed to open process: " << GetLastError() << endl;
        injectionActive = false;
        animation.join();
        return false;
    }

    HANDLE hFile = CreateFileW(dllPath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wcout << L"[-] Failed to open DLL: " << GetLastError() << endl;
        CloseHandle(hProcess);
        injectionActive = false;
        animation.join();
        return false;
    }

    DWORD fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        wcout << L"[-] Failed to get DLL size: " << GetLastError() << endl;
        CloseHandle(hFile);
        CloseHandle(hProcess);
        injectionActive = false;
        animation.join();
        return false;
    }

    BYTE* pFileData = new BYTE[fileSize];
    DWORD bytesRead;
    if (!ReadFile(hFile, pFileData, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
        wcout << L"[-] Failed to read DLL: " << GetLastError() << endl;
        delete[] pFileData;
        CloseHandle(hFile);
        CloseHandle(hProcess);
        injectionActive = false;
        animation.join();
        return false;
    }
    CloseHandle(hFile);

    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pFileData;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        wcout << L"[-] Invalid DLL format" << endl;
        delete[] pFileData;
        CloseHandle(hProcess);
        injectionActive = false;
        animation.join();
        return false;
    }

    PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + pDosHeader->e_lfanew);
    if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) {
        wcout << L"[-] Invalid PE header" << endl;
        delete[] pFileData;
        CloseHandle(hProcess);
        injectionActive = false;
        animation.join();
        return false;
    }

    pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAllocateVirtualMemory");
    pNtWriteVirtualMemory NtWriteVirtualMemory = (pNtWriteVirtualMemory)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtWriteVirtualMemory");
    pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
    pNtClose NtClose = (pNtClose)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtClose");

    PVOID pRemoteImage = NULL;
    SIZE_T size = pNtHeaders->OptionalHeader.SizeOfImage;
    NTSTATUS status = NtAllocateVirtualMemory(hProcess, &pRemoteImage, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (status != 0) {
        wcout << L"[-] Failed to allocate memory: " << status << endl;
        delete[] pFileData;
        CloseHandle(hProcess);
        injectionActive = false;
        animation.join();
        return false;
    }

    DWORD headersSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
    status = NtWriteVirtualMemory(hProcess, pRemoteImage, pFileData, headersSize, NULL);
    if (status != 0) {
        wcout << L"[-] Failed to write headers: " << status << endl;
        NtClose(hProcess);
        delete[] pFileData;
        injectionActive = false;
        animation.join();
        return false;
    }

    PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
    for (DWORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i) {
        PVOID pRemoteSection = (BYTE*)pRemoteImage + pSectionHeader[i].VirtualAddress;
        PVOID pLocalSection = (BYTE*)pFileData + pSectionHeader[i].PointerToRawData;
        DWORD sectionSize = pSectionHeader[i].SizeOfRawData;

        if (sectionSize > 0) {
            status = NtWriteVirtualMemory(hProcess, pRemoteSection, pLocalSection, sectionSize, NULL);
            if (status != 0) {
                wcout << L"[-] Failed to write section: " << status << endl;
                NtClose(hProcess);
                delete[] pFileData;
                injectionActive = false;
                animation.join();
                return false;
            }
        }
    }

    MANUAL_MAPPING_DATA data{ 0 };
    data.ImageBase = pRemoteImage;
    data.NtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pRemoteImage + pDosHeader->e_lfanew);
    data.BaseReloc = (PIMAGE_BASE_RELOCATION)((BYTE*)pRemoteImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    data.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pRemoteImage + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    data.fnNtAllocateVirtualMemory = NtAllocateVirtualMemory;
    data.fnNtWriteVirtualMemory = NtWriteVirtualMemory;
    data.fnNtCreateThreadEx = NtCreateThreadEx;
    data.fnNtClose = NtClose;

    PVOID pRemoteData = NULL;
    SIZE_T dataSize = sizeof(MANUAL_MAPPING_DATA);
    status = NtAllocateVirtualMemory(hProcess, &pRemoteData, 0, &dataSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (status != 0) {
        wcout << L"[-] Failed to allocate data memory: " << status << endl;
        NtClose(hProcess);
        delete[] pFileData;
        injectionActive = false;
        animation.join();
        return false;
    }

    status = NtWriteVirtualMemory(hProcess, pRemoteData, &data, sizeof(MANUAL_MAPPING_DATA), NULL);
    if (status != 0) {
        wcout << L"[-] Failed to write data: " << status << endl;
        NtClose(hProcess);
        delete[] pFileData;
        injectionActive = false;
        animation.join();
        return false;
    }

    HANDLE hThread = NULL;
    PVOID pLoader = (PVOID)((BYTE*)pRemoteImage + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
    status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)pLoader, pRemoteData, 0, 0, 0, 0, NULL);
    if (status != 0) {
        wcout << L"[-] Failed to create thread: " << status << endl;
        NtClose(hProcess);
        delete[] pFileData;
        injectionActive = false;
        animation.join();
        return false;
    }

    WaitForSingleObject(hThread, INFINITE);
    NtClose(hThread);
    NtClose(hProcess);
    delete[] pFileData;

    injectionActive = false;
    animation.join();
    wcout << L"[+] Manual Mapping successful!" << endl;
    return true;
}

int main() {
    wcout << L"=== encTeamed injector ===" << endl;

    wcout << L"\n[?] Select DLL file to inject..." << endl;
    wstring dllPath = OpenFileDialog();

    if (dllPath.empty()) {
        wcout << L"[-] No file selected. Exiting." << endl;
        return 1;
    }

    wcout << L"\n[+] Selected file: " << dllPath << endl;

    wcout << L"\n[?] Enter process name to inject into: ";
    wstring processName;
    wcin >> processName;

    DWORD pid = FindProcessId(processName);
    if (pid == 0) {
        wcout << L"[-] Process not found." << endl;
        return 1;
    }

    wcout << L"[+] Found process ID: " << pid << endl;

    if (ManualMapInject(pid, dllPath)) {
        wcout << L"[+] Done! Injected." << endl;
    }
    else {
        wcout << L"[-] Injection failed." << endl;
    }

    return 0;
}
