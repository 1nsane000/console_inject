#define INITGUID
#include <Windows.h>
#include <winnt.h>
#include <psapi.h>
#include <Wmistr.h>
#include <evntrace.h>
#include <tchar.h>
#include <stdio.h>
#include <algorithm>
#include <stdlib.h>
#include <search.h>
#include <iostream>
#include "externals.h"
#include <stdint.h>
#include <tdh.h>
#include <TraceLoggingProvider.h>

#include "tdh_ms_example.hpp"
#pragma comment(lib, "tdh.lib")

#define MAX_GUID_SIZE 39

constexpr uint32_t _16MB = 16384;
constexpr uint32_t _64KB = 64;
constexpr uint32_t _32KB = 32;


void PrintProcessNameAndID(DWORD processID);
BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
void ProcessHookTest(DWORD processID);


#define arrsize(x) sizeof(x)/sizeof(x[0])

//CA11C036-0102-4A2D-A6AD-F03CFED5D3C9
static const GUID Microsoft_Windows_DXGI =
{ 0xCA11C036, 0x0102, 0x4A2D, {0xA6, 0xAD, 0xF0, 0x3C, 0xFE, 0xD5, 0xD3, 0xC9 } };

//83ACA0A-790E-4D7F-8451-AA850511C6B9
static const GUID Microsoft_Windows_D3D9 =
{ 0x783ACA0A, 0x790E, 0x4D7F, {0x84, 0x51, 0xAA, 0x85, 0x05, 0x11, 0xC6, 0xB9 } };

//BD568F20 - FCCD - B948 - 054E - DB3421115D61
static const GUID DNETLIB =
{ 0xBD568F20, 0xFCCD, 0xB948, {0x05, 0x4E, 0xDB, 0x34, 0x21, 0x11, 0x5D, 0x61 } };
ULONG g_TimerResolution = 0;

// Used to determine if the session is a private session or kernel session.
// You need to know this when accessing some members of the EVENT_TRACE.Header
// member (for example, KernelTime or UserTime).
BOOL g_bUserMode = FALSE;

//Start time value for the start event.
ULONG g_StartKernelTime = 0;
ULONG g_StartUserTime = 0;
ULONG64 g_StartProcessTime = 0;

VOID WINAPI ProcessEvent(PEVENT_TRACE pEvent) {
    ULONG64 CPUProcessUnits = 0;
    ULONG CPUUnits = 0;
    double CPUTime = 0;


    // Skips the event if it is the event trace header. Log files contain this event
    // but real-time sessions do not. The event contains the same information as 
    // the EVENT_TRACE_LOGFILE.LogfileHeader member that you can access when you open 
    // the trace. 

    if (IsEqualGUID(pEvent->Header.Guid, EventTraceGuid) &&
        pEvent->Header.Class.Type == EVENT_TRACE_TYPE_INFO)
    {
        ; // Skip this event.
    }
    else
    {
        if (IsEqualGUID(Microsoft_Windows_DXGI, pEvent->Header.Guid))
        {
            // This example assumes that the start and end events are paired.
            // If this is the start event type, retrieve the start time values from the 
            // event; otherwise, retrieve the end time values from the event.

            if (pEvent->Header.Class.Type == EVENT_TRACE_TYPE_START)
            {
                // If the session is a private session, use the ProcessorTime
                // value to calculate the CPU time; otherwise, use the 
                // KernelTime and UserTime values.

                if (g_bUserMode) // Private session
                {
                    g_StartProcessTime = pEvent->Header.ProcessorTime;
                }
                else  // Kernel session
                {
                    g_StartKernelTime = pEvent->Header.KernelTime;
                    g_StartUserTime = pEvent->Header.UserTime;
                }
            }
            else if (pEvent->Header.Class.Type == EVENT_TRACE_TYPE_END)
            {
                if (g_bUserMode) // Private session
                {
                    // Calculate CPU time units used.

                    CPUProcessUnits = pEvent->Header.ProcessorTime - g_StartProcessTime;
                    wprintf(L"CPU time units used, %I64u.\n", CPUProcessUnits);

                    // Processor time is in CPU ticks. Convert ticks to seconds.
                    // 1000000000 = nanoseconds in one second.

                    CPUTime = (double)(CPUProcessUnits) / 1000000000;
                    wprintf(L"Process CPU usage in seconds, %Lf.\n", CPUTime);
                }
                else  // Kernel session
                {
                    // Calculate the kernel mode CPU time units used for the set of instructions.

                    CPUUnits = pEvent->Header.KernelTime - g_StartKernelTime;
                    wprintf(L"CPU time units used (kernel), %d.\n", CPUUnits);

                    // Calculate the kernel mode CPU time in seconds for the set of instructions.
                    // 100 = 100 nanoseconds, 1000000000 = nanoseconds in one second

                    CPUTime = (double)(g_TimerResolution * CPUUnits * 100) / 1000000000;
                    wprintf(L"Kernel mode CPU usage in seconds, %Lf.\n", CPUTime);

                    // Calculate user mode CPU time units used for the set of instructions.

                    CPUUnits = pEvent->Header.UserTime - g_StartUserTime;
                    wprintf(L"\nCPU time units used (user), %d.\n", CPUUnits);

                    // Calculate the user mode CPU time in seconds for the set of instructions.
                    // 100 = 100 nanoseconds, 1000000000 = nanoseconds in one second

                    CPUTime = (double)(g_TimerResolution * CPUUnits * 100) / 1000000000;
                    wprintf(L"User mode CPU usage in seconds, %Lf.\n", CPUTime);
                }
            }
        }
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

    _tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);

    // Release the handle to the process.

    CloseHandle(hProcess);
}

BOOL SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege)
{
    LUID luid;
    BOOL bRet = FALSE;

    if (LookupPrivilegeValue(NULL, lpszPrivilege, &luid))
    {
        TOKEN_PRIVILEGES tp;


        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;
        //
        //  Enable the privilege or disable all privileges.
        //
        if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL))
        {
            //
            //  Check to see if you have proper access.
            //  You may get "ERROR_NOT_ALL_ASSIGNED".
            //
            bRet = (GetLastError() == ERROR_SUCCESS);
        }
    }
    return bRet;
}


void printPerformanceInfo(PPERFORMANCE_INFORMATION pi) {
    _tprintf(TEXT("Commit Total: %I64u\n"), pi->CommitTotal);
    _tprintf(TEXT("Commit Limit: %I64u\n"), pi->CommitLimit);
    _tprintf(TEXT("Commit Peak:  %I64u\n"), pi->CommitPeak);
    _tprintf(TEXT("Commit Total: %I64u\n"), pi->CommitTotal);
    _tprintf(TEXT("Physical Total: %I64u\n"), pi->PhysicalTotal);
    _tprintf(TEXT("Physical Available: %I64u\n"), pi->PhysicalAvailable);
    _tprintf(TEXT("System Cache: %I64u\n"), pi->SystemCache);
    _tprintf(TEXT("Kernel Total: %I64u\n"), pi->KernelTotal);
    _tprintf(TEXT("Kernel Paged: %I64u\n"), pi->KernelPaged);
    _tprintf(TEXT("Kernel Nonpaged: %I64u\n"), pi->KernelNonpaged);
    _tprintf(TEXT("Page Size: %I64u\n"), pi->PageSize);
    _tprintf(TEXT("Handle Count: %u\n"), pi->HandleCount);
    _tprintf(TEXT("Process Count: %u\n"), pi->ProcessCount);
    _tprintf(TEXT("Thread Count: %u\n"), pi->ThreadCount);
}

struct EventPropertyData2 {
    EVENT_TRACE_PROPERTIES_V2 properties;
    WCHAR logger_name[128];
};

void enumerateProviders() {
    DWORD status = ERROR_SUCCESS;
    PROVIDER_ENUMERATION_INFO* penum = NULL;    // Buffer that contains provider information
    PROVIDER_ENUMERATION_INFO* ptemp = NULL;
    DWORD BufferSize = 0;                       // Size of the penum buffer
    HRESULT hr = S_OK;                          // Return value for StringFromGUID2
    WCHAR StringGuid[MAX_GUID_SIZE];
    DWORD RegisteredMOFCount = 0;
    DWORD RegisteredManifestCount = 0;

    // Retrieve the required buffer size.

    status = TdhEnumerateProviders(penum, &BufferSize);

    // Allocate the required buffer and call TdhEnumerateProviders. The list of 
    // providers can change between the time you retrieved the required buffer 
    // size and the time you enumerated the providers, so call TdhEnumerateProviders
    // in a loop until the function does not return ERROR_INSUFFICIENT_BUFFER.

    while (ERROR_INSUFFICIENT_BUFFER == status)
    {
        ptemp = (PROVIDER_ENUMERATION_INFO*)realloc(penum, BufferSize);
        if (NULL == ptemp)
        {
            wprintf(L"Allocation failed (size=%lu).\n", BufferSize);
            goto cleanup;
        }

        penum = ptemp;
        ptemp = NULL;

        status = TdhEnumerateProviders(penum, &BufferSize);
    }

    if (ERROR_SUCCESS != status)
    {
        wprintf(L"TdhEnumerateProviders failed with %lu.\n", status);
    }
    else
    {
        // Loop through the list of providers and print the provider's name, GUID, 
        // and the source of the information (MOF class or instrumentation manifest).

        for (DWORD i = 0; i < penum->NumberOfProviders; i++)
        {
            hr = StringFromGUID2(penum->TraceProviderInfoArray[i].ProviderGuid, StringGuid, ARRAYSIZE(StringGuid));

            if (FAILED(hr))
            {
                wprintf(L"StringFromGUID2 failed with 0x%x\n", hr);
                goto cleanup;
            }

            wprintf(L"Provider name: %s\nProvider GUID: %s\nSource: %s\n\n",
                (LPWSTR)((PBYTE)(penum)+penum->TraceProviderInfoArray[i].ProviderNameOffset),
                StringGuid,
                (penum->TraceProviderInfoArray[i].SchemaSource) ? L"WMI MOF class" : L"XML manifest");

            (penum->TraceProviderInfoArray[i].SchemaSource) ? RegisteredMOFCount++ : RegisteredManifestCount++;
        }

        wprintf(L"\nThere are %d registered providers; %lu are registered via MOF class and\n%lu are registered via a manifest.\n",
            penum->NumberOfProviders,
            RegisteredMOFCount,
            RegisteredManifestCount);
    }

cleanup:

    if (penum)
    {
        free(penum);
        penum = NULL;
    }

}

void startEventTrace(HANDLE hProcess) {
    EventPropertyData2 dxgi_event_data = { {0} , L"dxgi"};
    dxgi_event_data.properties.BufferSize = _32KB;

    

    dxgi_event_data.properties.Wnode.BufferSize = sizeof(EventPropertyData2);
    dxgi_event_data.properties.Wnode.Flags = WNODE_FLAG_TRACED_GUID | WNODE_FLAG_VERSIONED_PROPERTIES;
    dxgi_event_data.properties.Wnode.ClientContext = 1;
    dxgi_event_data.properties.Wnode.Guid = Microsoft_Windows_D3D9;

    dxgi_event_data.properties.LogFileMode = EVENT_TRACE_BUFFERING_MODE | EVENT_TRACE_REAL_TIME_MODE;
    
    dxgi_event_data.properties.LoggerNameOffset = offsetof(EventPropertyData2, logger_name);

    TRACEHANDLE TraceHandle;

    //starting the trace...
    StartTraceW(
        &TraceHandle,
        L"dxgi",
        reinterpret_cast<EVENT_TRACE_PROPERTIES*>(&dxgi_event_data.properties)
    );

    if(TraceHandle == NULL){
        _tprintf(L"Failed retrieving the trace handle \n");
    }

    ULONG RET;
    RET = EnableTraceEx2(
        TraceHandle,
        (LPCGUID)&Microsoft_Windows_DXGI,
        EVENT_CONTROL_CODE_ENABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0,
        0,
        INFINITE,
        NULL
    );
    if (RET != ERROR_SUCCESS) {
        _tprintf(L"FAILED ENABLING THE TRACE %lu\n", RET);
    }

    EVENT_TRACE_LOGFILEW event_trace = { 0 };
    event_trace.LoggerName = dxgi_event_data.logger_name;
    event_trace.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME;
    event_trace.EventCallback = ProcessEvent;
    //we consume events here...
    TRACEHANDLE trace = OpenTrace(&event_trace);
    if (trace == NULL) {
        _tprintf(L"Open Trace failed\n");
    }
    RET = ProcessTrace(
        &trace,
        1,
        NULL,
        NULL
    );

    if (RET != ERROR_SUCCESS) {
        _tprintf(L"Failed processing trace %lu \n",RET);
    }

    
    //disable trace
    CloseTrace(trace);

    EnableTraceEx2(
        TraceHandle,
        (LPCGUID)&Microsoft_Windows_DXGI,
        EVENT_CONTROL_CODE_DISABLE_PROVIDER,
        TRACE_LEVEL_VERBOSE,
        0,
        0,
        INFINITE,
        NULL
    );

    StopTraceW(
        TraceHandle,
        dxgi_event_data.logger_name,
        reinterpret_cast<EVENT_TRACE_PROPERTIES*>(&dxgi_event_data.properties)
    );

}


void ProcessHookTest(DWORD processID)
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
    else {
        _tprintf(L"PROCESS NOT FOUND\n");
    }

    // Print the process name and identifier.

    _tprintf(TEXT("%s  (PID: %u)\n"), szProcessName, processID);

    constexpr DWORD lphSize = 1024;
    HMODULE lphModule[lphSize];
    DWORD lphs = 0;
    
    EnumProcessModulesEx(
        hProcess,
        lphModule,
        sizeof(HMODULE)* lphSize,
        &lphs,
        LIST_MODULES_ALL
    );

    lphs = lphs / sizeof(HMODULE);

    _tprintf(TEXT("Num of modules: %d\n"), lphs);
   /* BOOL GetModuleInformation(
        [in]  HANDLE       hProcess,
        [in]  HMODULE      hModule,
        [out] LPMODULEINFO lpmodinfo,
        [in]  DWORD        cb
    );*/
    PERFORMANCE_INFORMATION pi = { 0 };
    GetPerformanceInfo(
        &pi,
        sizeof(pi)
    );

    printPerformanceInfo(&pi);


    startEventTrace(hProcess);
    // Release the handle to the process.
    
    CloseHandle(hProcess);
}

// [](const void* x, const void* y) -> int {return *(DWORD*)x - *(DWORD*)y; }

VOID EnablePrivileges(
    VOID
)
{
    HANDLE tokenHandle;

    if (NT_SUCCESS(NtOpenProcessToken(
        NtCurrentProcess(),
        TOKEN_ADJUST_PRIVILEGES,
        &tokenHandle
    )))
    {
        CHAR privilegesBuffer[FIELD_OFFSET(TOKEN_PRIVILEGES, Privileges) + sizeof(LUID_AND_ATTRIBUTES) * 9];
        PTOKEN_PRIVILEGES privileges;
        ULONG i;

        privileges = (PTOKEN_PRIVILEGES)privilegesBuffer;
        privileges->PrivilegeCount = 9;

        for (i = 0; i < privileges->PrivilegeCount; i++)
        {
            privileges->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
            privileges->Privileges[i].Luid.HighPart = 0;
        }

        privileges->Privileges[0].Luid.LowPart = SE_DEBUG_PRIVILEGE;
        privileges->Privileges[1].Luid.LowPart = SE_INC_BASE_PRIORITY_PRIVILEGE;
        privileges->Privileges[2].Luid.LowPart = SE_INC_WORKING_SET_PRIVILEGE;
        privileges->Privileges[3].Luid.LowPart = SE_LOAD_DRIVER_PRIVILEGE;
        privileges->Privileges[4].Luid.LowPart = SE_PROF_SINGLE_PROCESS_PRIVILEGE;
        privileges->Privileges[5].Luid.LowPart = SE_BACKUP_PRIVILEGE;
        privileges->Privileges[6].Luid.LowPart = SE_RESTORE_PRIVILEGE;
        privileges->Privileges[7].Luid.LowPart = SE_SHUTDOWN_PRIVILEGE;
        privileges->Privileges[8].Luid.LowPart = SE_TAKE_OWNERSHIP_PRIVILEGE;

        NtAdjustPrivilegesToken(
            tokenHandle,
            FALSE,
            privileges,
            0,
            NULL,
            NULL
        );

        NtClose(tokenHandle);
    }
}


int main2()
{
    EnablePrivileges();
    HANDLE hProcess = GetCurrentProcess();
    HANDLE hToken;
    BOOL res = false;
    //NtQueryInformationProcess();
    if (OpenProcessToken(hProcess, TOKEN_ADJUST_PRIVILEGES, &hToken))
    {

        
        //res = SetPrivilege(hToken, SE_DEBUG_NAME, TRUE);
        CloseHandle(hToken);
    }
    if (!res) {
        _tprintf(L"Failed to set priviledge\n");
        DWORD error = GetLastError();
        if (error == ERROR_NOT_ALL_ASSIGNED) {
            _tprintf(L"ERROR_NOT_ALL_ASSIGNED\n");
        }
    }

    DWORD aProcesses[1024], cbNeeded, cProcesses;
    unsigned int i;

    enumerateProviders();

    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded))
    {
        return 1;
    }


    cProcesses = cbNeeded / sizeof(DWORD);

    //qsort((void*)aProcesses, cProcesses, sizeof(DWORD), [](const void* x, const void* y) -> int {return *(DWORD*)x - *(DWORD*)y; });

    for (i = 0; i < cProcesses; i++)
    {
        if(aProcesses[i] != 0)
            PrintProcessNameAndID(aProcesses[i]);
    }

    int input_id = -1;

    while (input_id != 0) {
        std::cout << "Proc Id:\n";
        std::cin >> input_id;
        ProcessHookTest(input_id);
    }

}


