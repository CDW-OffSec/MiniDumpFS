// MiniDumpFS.cpp : This file contains helper functions from MemProcFS project to create a minidump from a memory dump file.
// Author: dru1d (tyler.booth@cdw.com)
// Date: 2024-03-12
// Version: 1.0.0

#ifdef _WIN32

#include <Windows.h>
#include <stdio.h>
#include <conio.h>
#include <leechcore.h>
#include <vmmdll.h>
#pragma comment(lib, "leechcore")
#pragma comment(lib, "vmm")

#endif /* _WIN32 */

// ----------------------------------------------------------------------------
// Utility functions below:
// ----------------------------------------------------------------------------

VOID ShowKeyPress()
{
    printf("PRESS ANY KEY TO CONTINUE ...\n");
    Sleep(250);
    _getch();
}

VOID PrintHexAscii(_In_ PBYTE pb, _In_ DWORD cb)
{
    LPSTR sz;
    DWORD szMax = 0;
    VMMDLL_UtilFillHexAscii(pb, cb, 0, NULL, &szMax);
    if (!(sz = LocalAlloc(0, szMax))) { return; }
    VMMDLL_UtilFillHexAscii(pb, cb, 0, sz, &szMax);
    printf("%s", sz);
    LocalFree(sz);
}

VOID CallbackList_AddFile(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_ ULONG64 cb, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    if (uszName) {
        printf("         FILE: '%s'\tSize: %lli\n", uszName, cb);
    }
}

VOID CallbackList_AddDirectory(_Inout_ HANDLE h, _In_ LPCSTR uszName, _In_opt_ PVMMDLL_VFS_FILELIST_EXINFO pExInfo)
{
    if (uszName) {
        printf("         DIR:  '%s'\n", uszName);
    }
}

VOID VadMap_Protection(_In_ PVMMDLL_MAP_VADENTRY pVad, _Out_writes_(6) LPSTR sz)
{
    BYTE vh = (BYTE)pVad->Protection >> 3;
    BYTE vl = (BYTE)pVad->Protection & 7;
    sz[0] = pVad->fPrivateMemory ? 'p' : '-';                                    // PRIVATE MEMORY
    sz[1] = (vh & 2) ? ((vh & 1) ? 'm' : 'g') : ((vh & 1) ? 'n' : '-');         // -/NO_CACHE/GUARD/WRITECOMBINE
    sz[2] = ((vl == 1) || (vl == 3) || (vl == 4) || (vl == 6)) ? 'r' : '-';     // COPY ON WRITE
    sz[3] = (vl & 4) ? 'w' : '-';                                               // WRITE
    sz[4] = (vl & 2) ? 'x' : '-';                                               // EXECUTE
    sz[5] = ((vl == 5) || (vl == 7)) ? 'c' : '-';                               // COPY ON WRITE
    if (sz[1] != '-' && sz[2] == '-' && sz[3] == '-' && sz[4] == '-' && sz[5] == '-') { sz[1] = '-'; }
}

LPSTR VadMap_Type(_In_ PVMMDLL_MAP_VADENTRY pVad)
{
    if (pVad->fImage) {
        return "Image";
    }
    else if (pVad->fFile) {
        return "File ";
    }
    else if (pVad->fHeap) {
        return "Heap ";
    }
    else if (pVad->fStack) {
        return "Stack";
    }
    else if (pVad->fTeb) {
        return "Teb  ";
    }
    else if (pVad->fPageFile) {
        return "Pf   ";
    }
    else {
        return "     ";
    }
}


int main(int argc, char* argv[])
{
    LPCSTR pathToDumpFile = NULL;
    LPCSTR processName = NULL;
    LPCSTR pathToOutputMinidump = NULL;

    // Parse command-line arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-dumpfile") == 0 && i + 1 < argc) {
            pathToDumpFile = argv[++i];
        }
        else if (strcmp(argv[i], "-process") == 0 && i + 1 < argc) {
            processName = argv[++i];
        }
        else if (strcmp(argv[i], "-minidump") == 0 && i + 1 < argc) {
            pathToOutputMinidump = argv[++i];
        }
    }

    // Check if all required parameters were provided
    if (!pathToDumpFile || !processName || !pathToOutputMinidump) {
        printf("Usage: %s -dumpfile <path_to_dump_file> -process <process_name> -minidump <path_to_output_minidump>\n", argv[0]);
        return 1;
    }

    // Convert output path to wide string for CreateFile
    wchar_t wPathToOutputMinidump[MAX_PATH];
    MultiByteToWideChar(CP_UTF8, 0, pathToOutputMinidump, -1, wPathToOutputMinidump, MAX_PATH);

    VMM_HANDLE hVMM = NULL;
    BOOL result;
    NTSTATUS nt;
    DWORD i, cbRead, dwPID;
    DWORD dw = 0;
    QWORD va;
    BYTE pbPage1[0x1000], pbPage2[0x1000];

    //printf("------------------------------------------------------------\n");
    //printf("# Initialize from file: %s\n", pathToDumpFile);
    //ShowKeyPress();
    //printf("[+] CALL:    VMMDLL_InitializeFile\n");
    printf("[*] Initializing hVMM from file: %s\n", pathToDumpFile);
    hVMM = VMMDLL_Initialize(3, (LPCSTR[]) { "", "-device", pathToDumpFile });
    if (hVMM) {
        printf("[+] hVMM initialized.\n");
    }
    else {
        printf("[-] hVMM failed.\n");
        return 1;
    }

    //printf("------------------------------------------------------------\n");
    //printf("# Get PID from the 'lsass.exe' process found.      \n");
    //ShowKeyPress();
    //printf("[+] CALL:    VMMDLL_PidGetFromName\n");
    result = VMMDLL_PidGetFromName(hVMM, processName, &dwPID);
    if (result) {
        printf("[+] VMMDLL_PidGetFromName: %s\n", processName);
        printf("[+] Found PID for '%s': %i\n", processName, dwPID);
        //printf("    -->  PID = %i\n", dwPID);
        char filePath[256];
        snprintf(filePath, sizeof(filePath), "\\pid\\%u\\minidump\\minidump.dmp", dwPID);
        printf("[+] Path to minidump: %s\n", filePath);

        VMMDLL_InitializePlugins(hVMM);
        //printf("[+] CALL:    VMMDLL_VfsRead\n");
        ZeroMemory(pbPage1, sizeof(pbPage1));
        NTSTATUS nt;
        DWORD cbRead;
        PBYTE pbMinidump = LocalAlloc(LMEM_ZEROINIT, 0x10000000); // Adjust size accordingly
        if (!pbMinidump) {
            printf("[-] Unable to allocate memory for minidump.\n");
            return 1;
        }

        nt = VMMDLL_VfsReadU(hVMM, filePath, pbMinidump, 0x10000000, &cbRead, 0); // Adjust size accordingly
        if (nt == VMMDLL_STATUS_SUCCESS) {
            printf("[+] VMMDLL_VfsRead of %s\n", filePath);

            // Parse logonpasswords from minidump using native Windows API TBD
            

            // Adjusted part to save the minidump
            HANDLE hFile = CreateFile(wPathToOutputMinidump, // Adjusted for dynamic path
                GENERIC_WRITE,
                0,
                NULL,
                CREATE_ALWAYS,
                FILE_ATTRIBUTE_NORMAL,
                NULL);

            if (hFile == INVALID_HANDLE_VALUE) {
                printf("[-] Unable to open file for writing.\n");
            }
            else {
                DWORD bytesWritten;
                BOOL writeResult = WriteFile(hFile, pbMinidump, cbRead, &bytesWritten, NULL);

                if (!writeResult || bytesWritten != cbRead) {
                    printf("[-] Unable to write the complete minidump. Written: %u of %u\n", bytesWritten, cbRead);
                }
                else {
                    printf("[+] Minidump saved to %s\n", pathToOutputMinidump);
                }
                CloseHandle(hFile);
            }

            // After processing, free the allocated memory
            LocalFree(pbMinidump);
        }
        else {
            printf("[-] VMMDLL_VfsRead failed!\n");
            LocalFree(pbMinidump);
            return 1;
        }
    }
    else {
        printf("[-] VMMDLL_PidGetFromName failed!\n");
        return 1;
    }

    // Close the VMM_HANDLE and clean up native resources.
    //printf("------------------------------------------------------------\n");
    printf("[*] Closing hVMM. \n");
    VMMDLL_Close(hVMM);
    return 0;
}