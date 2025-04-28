#include <windows.h>
#include <tlhelp32.h>
#include <shlobj.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>

using namespace std;

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
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;

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
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return processes;
    }

    if (Process32First(hSnapshot, &pe32)) {
        do {
            processes.emplace_back(pe32.th32ProcessID, pe32.szExeFile);
            wcout << L"[" << pe32.th32ProcessID << L"] " << pe32.szExeFile << endl;
        } while (Process32Next(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);
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

bool StealthInject(DWORD pid, const wstring& dllPath) {
    bool injectionActive = true;
    thread animation(AnimateLoading, L"Injecting", ref(injectionActive));

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        wcout << L"Failed to open process: " << GetLastError() << endl;
        injectionActive = false;
        animation.join();
        return false;
    }

    // memory control here 
    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, (dllPath.size() + 1) * sizeof(wchar_t),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!pDllPath) {
        wcout << L"Failed to allocate memory: " << GetLastError() << endl;
        CloseHandle(hProcess);
        injectionActive = false;
        animation.join();
        return false;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dllPath.c_str(),
        (dllPath.size() + 1) * sizeof(wchar_t), NULL)) {
        wcout << L"Failed to write memory: " << GetLastError() << endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        injectionActive = false;
        animation.join();
        return false;
    }

    LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)
        GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
    // poor library
    if (!pLoadLibrary) {
        wcout << L"[-] Failed to find LoadLibraryW" << endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        injectionActive = false;
        animation.join();
        return false;
    }

    // fucking brainroot bitch 
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        wcout << L"[-] failed to get thread snapshot: " << GetLastError() << endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        injectionActive = false;
        animation.join();
        return false;
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    bool injected = false;
    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
                if (hThread) {
                    // injecting py apc method , maybe been banned by vac :)
                    QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)pDllPath);
                    CloseHandle(hThread);
                    injected = true;
                    break; 
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    CloseHandle(hProcess);

    injectionActive = false;
    animation.join();

    if (!injected) {
        wcout << L"Failed to find suitable thread for injection" << endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        return false;
    }

    wcout << L"Injection successful!" << endl;
    return true;
}
// shit 
int main() {
    wcout << L"=== DLL EncJector ===" << endl;

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

    if (StealthInject(pid, dllPath)) {
        wcout << L"Done!" << endl;
    }
    else {
        wcout << L"[-] Injection failed." << endl;
    }

    return 0;
}