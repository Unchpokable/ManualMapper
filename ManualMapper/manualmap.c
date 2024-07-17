#include <stdlib.h>

#include "pe_utils.h"
#include "manualmap.h"

#include <stdio.h>

static HANDLE GetTargetProcessHandle(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if(hProcess == NULL)
    {
        int ret = fprintf_s(stderr, "Failed to open target process. Error: %lu\n", GetLastError());
    }

    return hProcess;
}

LPVOID AllocateMemoryInTargetProcess(HANDLE hProcess, SIZE_T size)
{
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    if (pRemoteMemory == NULL)
    {
        fprintf_s(stderr, "Failed to allocate memory in target process. Error: %lu\n", GetLastError());
    }

    return pRemoteMemory;
}

BOOL WriteTargetProcessMemory(HANDLE hProcess, LPVOID pMemory, LPCVOID buffer, SIZE_T size)
{
    SIZE_T bytesWritten;

    if (!WriteProcessMemory(hProcess, pMemory, buffer, size, &bytesWritten) || bytesWritten != size)
    {
        fprintf_s(stderr, "Failed to write memory for target process. Error: %lu\n", GetLastError());
    }

    return TRUE;
}

BOOL LoadDll(const char* dllPath, DWORD pid)
{
    return TRUE;
}