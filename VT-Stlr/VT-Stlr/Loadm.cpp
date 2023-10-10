#include "commun.h"
#include "getaddress.h"

#define LdrLoadDll_H	0xdea5669d
#define rand_h          0x433e35e4
#define srand_h         0xab2027b7
#define time_h          0x433f708e
#define wcslen_h        0x1774286b

typedef int (WINAPI* rand_t)(void);


typedef NTSTATUS(NTAPI* LdrLoadDll_t)(PWCHAR PathToFile OPTIONAL, ULONG Flags OPTIONAL, PUNICODE_STRING ModuleFileName, PHANDLE ModuleHandle);

typedef void (WINAPI* srand_t)(
    unsigned int seed
);

typedef time_t(WINAPI* time_T)(time_t* second);

typedef size_t (WINAPI* wcslen_t)(
    const wchar_t* str
);

void shuffleArray(const WCHAR** arr, int n) {

    rand_t randFunc = (rand_t)PEBGetAddr(rand_h);

    for (int i = n - 1; i > 0; i--) {
        int j = randFunc() % (i + 1);

        // Swap arr[i] and arr[j]
        const WCHAR* temp = arr[i];
        arr[i] = arr[j];
        arr[j] = temp;
    }
}

void LoadRandomModules() {
 
    srand_t srandFunc = (srand_t)PEBGetAddr(srand_h);
    time_T timeFunc = (time_T)PEBGetAddr(time_h);
    wcslen_t wcslenFunc = (wcslen_t)PEBGetAddr(wcslen_h);

    const WCHAR* modules[] = {
        L"Wininet.dll",
        L"Advapi32.dll",
        L"Crypt32.dll",

    };

    int modulesCount = sizeof(modules) / sizeof(modules[0]);

    srandFunc(timeFunc(NULL)); // Seed the random number generator
    shuffleArray(modules, modulesCount); // Shuffle the modules array

    LdrLoadDll_t LdrLoadDllFunc = (LdrLoadDll_t)PEBGetAddr(LdrLoadDll_H);
    if (!LdrLoadDllFunc) {
        //printf("LdrLoadDll function not found.\n");
        return;
    }

    for (int i = 0; i < modulesCount; i++) {
        UNICODE_STRING uStr;
        uStr.Buffer = (PWSTR)modules[i];
        uStr.Length = (wcslenFunc(modules[i]) * sizeof(WCHAR));
        uStr.MaximumLength = (wcslenFunc(modules[i]) + 1) * sizeof(WCHAR);

        HANDLE hModule = NULL;
        NTSTATUS status = LdrLoadDllFunc(NULL, 0, &uStr, &hModule);

        if (hModule) {
            //printf("Module '%ls' loaded successfully.\n", modules[i]);
        }
        else {
            //printf("Failed to load module '%ls'.\n", modules[i]);
        }
    }

}