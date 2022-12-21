#include <Windows.h>
#include <psapi.h>
#include <tchar.h>
#include <iostream>
#include <stdlib.h>
#include <conio.h>

HMODULE dll;
HOOKPROC proc;
HHOOK hook = NULL;

BOOL WINAPI ExitCallback(
    _In_ DWORD dwCtrlType
) {
    if (hook) {
        UnhookWindowsHookEx(hook);
    }
    return FALSE;
}

int PrintModules(DWORD processID)
{
    HMODULE hMods[1024];
    HANDLE hProcess;
    DWORD cbNeeded;
    unsigned int i;

    // Print the process identifier.

    printf("\nProcess ID: %u\n", processID);

    // Get a handle to the process.

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);
    if (NULL == hProcess)
        return 1;

    // Get a list of all the modules in this process.

    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
    {
        for (i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
        {
            TCHAR szModName[MAX_PATH];

            // Get the full path to the module's file.

            if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
                sizeof(szModName) / sizeof(TCHAR)))
            {
                // Print the module name and handle value.

                _tprintf(TEXT("\t%s (0x%08X)\n"), szModName, hMods[i]);
            }
        }
    }

    // Release the handle to the process.

    CloseHandle(hProcess);

    return 0;
}


void ProcessHookTest(DWORD threadID)
{
    if (!hook) {
        hook = SetWindowsHookEx(
            WH_KEYBOARD,
            proc,
            dll,
            threadID
        );
    }
    
    if (!hook) {
        wprintf(L"hook failed %lu\n", GetLastError());
    }
    else {
        _getch();
        if (hook)
            UnhookWindowsHookEx(hook);
        hook = NULL;
    }

}


void PrintProcessNameAndID(DWORD processID)
{
    TCHAR szProcessName[MAX_PATH] = TEXT("<unknown>");

    // Get a handle to the process.

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ,
        FALSE, processID);

    // Get the process name.

    if (NULL != hProcess)
    {
        HMODULE hMod;
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod),
            &cbNeeded))
        {
            GetModuleBaseName(hProcess, hMod, szProcessName,
                sizeof(szProcessName) / sizeof(TCHAR));
        }
    }

    // Print the process name and identifier.

    wprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);

    
    // Release the handle to the process.

    CloseHandle(hProcess);
}

void processEnum() {
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;


    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return;
    }


    cProcesses = cbNeeded / sizeof(DWORD);


    for (i = 0; i < cProcesses; i++)
    {
        if (aProcesses[i] != 0){
            PrintProcessNameAndID(aProcesses[i]);
            PrintModules(aProcesses[i]);
        }
    }
}


BOOL CALLBACK EnumWindowsProc(
    _In_ HWND   hwnd,
    _In_ LPARAM lParam
) {
    wchar_t fname[MAX_PATH];

    WINDOWINFO WindowInfo = { 0 };

    WindowInfo.cbSize = sizeof(WINDOWINFO);

    GetWindowInfo(hwnd, &WindowInfo);
    TITLEBARINFO TitlebarInfo = { 0 };
    TitlebarInfo.cbSize = sizeof(TITLEBARINFO);
    GetTitleBarInfo(hwnd, &TitlebarInfo);


    SetLastError(0);
    if ((WindowInfo.dwStyle & WS_VISIBLE) &&
        !(WindowInfo.dwExStyle & WS_EX_TOOLWINDOW)) {
        int wtl = GetWindowText(
            hwnd,
            fname,
            MAX_PATH
        );

        DWORD error = 0;
        if ((error = GetLastError()) != 0) {
            wprintf(L"Error: %d\n", error);
        }
        else {
            wprintf(L"Window name: %s\n", fname);
        }
        DWORD threadId = GetWindowThreadProcessId(
            hwnd,
            0
        );
        wprintf(L"Thread ID: %d\n\n", threadId);
    }
    return TRUE;
}

void windowEnum() {
    BOOL RET = EnumWindows(
        EnumWindowsProc,
        0
    );


}

int main()
{
    dll = LoadLibrary(L"C:\\InjectDLL\\InjectDLL.dll");
    if (!dll) {
        wprintf(L"DLL not found\n");
        return 1;
    }
    
    proc = (HOOKPROC)GetProcAddress(dll, "getFPS");
    if (!proc) {
        wprintf(L"FUNCTION not found");
    }
    SetConsoleCtrlHandler(ExitCallback, TRUE);
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hToken;
    BOOL res = false;
    if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        CloseHandle(hToken);
    }
    if (!res) {
        wprintf(L"Failed to set priviledge\n");
        DWORD error = GetLastError();
        if (error == ERROR_NOT_ALL_ASSIGNED) {
            wprintf(L"ERROR_NOT_ALL_ASSIGNED\n");
        }
    }
    
    //processEnum();
    windowEnum();

    int input_id = -1;

    while (input_id != 0) {
        std::cout << "Proc Id:\n";
        std::cin >> input_id;
        ProcessHookTest(input_id);
    }
}
