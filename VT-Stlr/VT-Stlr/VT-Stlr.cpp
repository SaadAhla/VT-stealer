#include "commun.h"
#include "getfiles.h"
#include "Loadm.h"

BOOL IsDebuggerPresentPEB() {
    PPEB peb = (PPEB)__readgsqword(0x60);
    return peb->BeingDebugged;
}


void main(void) {

    if (IsDebuggerPresentPEB()) {
        int* crashPointer = NULL;
        *crashPointer = 42; // This will cause a crash
    }

    LoadRandomModules();
    search_all_drives();
    
    
}
