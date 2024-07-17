#ifndef PE_UTILS_H
#define PE_UTILS_H

#include <windows.h>

typedef struct PEHeaders__
{
    PIMAGE_DOS_HEADER DosHeader;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_SECTION_HEADER SectionHeader;
} PEHeaders;

BOOL ReadFileToMemory(const char* filePath, BYTE** buffer, DWORD *size);
BOOL ParsePEHeaders(BYTE* buffer, PEHeaders *peHeaders);

BOOL ResolveImports(HANDLE hProcess, PEHeaders* peHeaders, LPVOID pRemoteMemoryBase);
BOOL RelocateImage(PEHeaders *peHeaders, LPVOID pRemoteMemoryBase);

#endif // PE_UTILS_H