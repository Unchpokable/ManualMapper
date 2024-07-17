#include <stdio.h>
#include <stdlib.h>

#include "manualmap.h"
#include "security.h"

void ParseArguments(int argc, char** argv, char** dllPath, DWORD *pid)
{
    if (argc != 3)
    {
        int ret = fprintf_s(stderr, "Invalid usage. %s\nUsage: <dll_path> <pid>", argv[1]);
        exit(EXIT_FAILURE); // NOLINT(concurrency-mt-unsafe)
    }

    *dllPath = argv[1];
}

int main(int argc, char** argv)
{
    char* dllPath;
    DWORD targetPid;

    ParseArguments(argc, argv, &dllPath, &targetPid);

    RaisePrivilegesToDebug();
}