#include "pe_utils.h"

BOOL ReadFileToMemory(const char* filePath, BYTE** buffer, DWORD* size)
{
    HANDLE hFile = CreateFileA(filePath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if(hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    *size = GetFileSize(hFile, NULL);
    if (*size == INVALID_FILE_SIZE)
    {
        CloseHandle(hFile);
        return FALSE;
    }

    *buffer = (BYTE*)malloc(*size);
    if (*buffer == NULL)
    {
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD bytesRead;
    if (!ReadFile(hFile, buffer, *size, &bytesRead, NULL) || bytesRead != *size)
    {
        free(*buffer);
        CloseHandle(hFile);
        return FALSE;
    }

    CloseHandle(hFile);
    return TRUE;
}

BOOL ParsePEHeaders(BYTE* buffer, PEHeaders* peHeaders)
{
    peHeaders->DosHeader = (PIMAGE_DOS_HEADER)buffer;
    if (peHeaders->DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        return FALSE;
    }

    peHeaders->NtHeaders = (PIMAGE_NT_HEADERS)(buffer + peHeaders->DosHeader->e_lfanew);
    if (peHeaders->NtHeaders->Signature != IMAGE_NT_SIGNATURE)
    {
        return FALSE;
    }

    peHeaders->SectionHeader = (PIMAGE_SECTION_HEADER)(buffer + peHeaders->DosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    return TRUE;
}

BOOL ResolveImports(HANDLE hProcess, PEHeaders* peHeaders, LPVOID pRemoteMemoryBase) {
    PIMAGE_DATA_DIRECTORY importDirectory = &peHeaders->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];

    if (importDirectory->Size == 0)
    {
        return TRUE;
    }

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)peHeaders->DosHeader + importDirectory->VirtualAddress);

    while (importDescriptor->Name)
    {
        LPCSTR moduleName = (LPCSTR)((BYTE*)peHeaders->DosHeader + importDescriptor->Name);
        HMODULE hModule = LoadLibraryA(moduleName);
        if (hModule == NULL)
        {
            return FALSE;
        }

        PIMAGE_THUNK_DATA thunkILT = (PIMAGE_THUNK_DATA)((BYTE*)peHeaders->DosHeader + importDescriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA thunkIAT = (PIMAGE_THUNK_DATA)((BYTE*)peHeaders->DosHeader + importDescriptor->FirstThunk);

        while (thunkILT->u1.AddressOfData)
        {
            FARPROC funcAddress;
            if (thunkILT->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                funcAddress = GetProcAddress(hModule, (LPCSTR)(thunkILT->u1.Ordinal & 0xFFFF));
            }
            else
            {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)peHeaders->DosHeader + thunkILT->u1.AddressOfData);
                funcAddress = GetProcAddress(hModule, (LPCSTR)importByName->Name);
            }

            if (funcAddress == NULL)
            {
                return FALSE;
            }

            SIZE_T bytesWritten;
            if (!WriteProcessMemory(hProcess, (LPVOID)((BYTE*)pRemoteMemoryBase + (SIZE_T)(thunkIAT - (PIMAGE_THUNK_DATA)peHeaders->DosHeader)), &funcAddress, sizeof(FARPROC), &bytesWritten) || bytesWritten != sizeof(FARPROC))
            {
                return FALSE;
            }

            thunkILT++;
            thunkIAT++;
        }

        importDescriptor++;
    }
    return TRUE;
}

BOOL RelocateImage(PEHeaders * peHeaders, LPVOID pRemoteMemoryBase) {
    DWORD delta = (DWORD)((SIZE_T)pRemoteMemoryBase - peHeaders->NtHeaders->OptionalHeader.ImageBase);
    if (delta == 0)
    {
        return TRUE;
    }

    PIMAGE_DATA_DIRECTORY relocationDirectory = &peHeaders->NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (relocationDirectory->Size == 0)
    {
        return TRUE;
    }

    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)peHeaders->DosHeader + relocationDirectory->VirtualAddress);

    while(relocation->VirtualAddress != 0)
    {
        DWORD* relocBase = (DWORD*)((BYTE*)pRemoteMemoryBase + relocation->VirtualAddress);
        DWORD size = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* relocData = (WORD*)((BYTE*)relocation + sizeof(IMAGE_BASE_RELOCATION));

        for (DWORD i = 0; i < size; i++)
        {
            if (relocData[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
            {
                DWORD* patchAddress = (DWORD*)((BYTE*)relocBase + (relocData[i] & 0xFF));
                *patchAddress += delta;
            }
        }

        relocation = (PIMAGE_BASE_RELOCATION)((BYTE*)relocation + relocation->SizeOfBlock);
    }

    return TRUE;
}
