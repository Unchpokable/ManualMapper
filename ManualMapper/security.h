#ifndef SECURITY_H
#define SECURITY_H

#include <Windows.h>
#include <stdio.h>

typedef NTSTATUS(WINAPI* RtlAdjustPrivileges_t)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    PBOOLEAN Enabled
);

BOOL RaisePrivilegesToDebug(void);

#endif // SECURITY_H