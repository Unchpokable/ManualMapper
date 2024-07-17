#include "security.h"

#define RTL_PRIVILEGE_DEBUG 20

BOOL RaisePrivilegesToDebug(void) {
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if(hNtDll == NULL)
    {
        fprintf_s(stderr, "Failed to handle ntdll.dll");
        return FALSE;
    }

    RtlAdjustPrivileges_t rtlAdjustPrivilegesFunc = (RtlAdjustPrivileges_t)GetProcAddress(hNtDll, "RtlAdjustPrivileges");

    if (rtlAdjustPrivilegesFunc == NULL)
    {
        fprintf_s(stderr, "Failed to get address of RtlAdjustPrivileges");
        return FALSE;
    }

    BOOLEAN wasEnabled;
    NTSTATUS status = rtlAdjustPrivilegesFunc(RTL_PRIVILEGE_DEBUG, TRUE, FALSE, &wasEnabled);
    if (status != 0)
    {
        fprintf_s(stderr, "Failed to adjust privileges with error code 0x%lx\n", status);
        return FALSE;
    }

    return TRUE;
}
