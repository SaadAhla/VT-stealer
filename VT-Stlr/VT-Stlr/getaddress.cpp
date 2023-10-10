#include "commun.h"


// Redefine PEB structures, for our own purpose
typedef struct NEW_PEB_LDR_DATA {
	ULONG Length;
	BOOL Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
} NEW_PEB_LDR_DATA, * PNEW_PEB_LDR_DATA;

typedef struct _NEW_LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
} NEW_LDR_DATA_TABLE_ENTRY, * PNEW_LDR_DATA_TABLE_ENTRY;





UINT djb2HashA(const char* str)
{
	UINT hash = 8191;
	int c;

	while ((c = *str++))
	{
		hash = ((hash << 5) + hash) + c;
	}

	return hash;
}



HMODULE PEBGetAddr(DWORD64 FunctionHash)
{
	DWORD FuncNumber;
	WORD OrdinalIndex;
	PDWORD FuncNameBase;
	PCSTR FunctionName;
	PIMAGE_EXPORT_DIRECTORY ExportDir;
	DWORD i;


	PPEB PebAddress = (PPEB)__readgsqword(0x60);

	PNEW_PEB_LDR_DATA Ldr = (PNEW_PEB_LDR_DATA)PebAddress->Ldr;

	
	PLIST_ENTRY NextModule = Ldr->InLoadOrderModuleList.Flink;


	PNEW_LDR_DATA_TABLE_ENTRY DataTableEntry = (PNEW_LDR_DATA_TABLE_ENTRY)NextModule;
	
	while (DataTableEntry->DllBase != NULL)
	{
		DWORD64 ModuleBase = (DWORD64)DataTableEntry->DllBase;

		PIMAGE_NT_HEADERS NTHeader = (PIMAGE_NT_HEADERS)(ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew);

		DWORD ExportDirRVA = NTHeader->OptionalHeader.DataDirectory[0].VirtualAddress;

		DataTableEntry = (PNEW_LDR_DATA_TABLE_ENTRY)DataTableEntry->InLoadOrderLinks.Flink;

		if (ExportDirRVA == 0)
		{
			continue;
		}

		ExportDir = (PIMAGE_EXPORT_DIRECTORY)((DWORD64)ModuleBase + ExportDirRVA);
		FuncNumber = ExportDir->NumberOfNames;
		FuncNameBase = (PDWORD)((PCHAR)ModuleBase + ExportDir->AddressOfNames);

		for (i = 0; i < FuncNumber; i++)
		{
			FunctionName = (PCSTR)(*FuncNameBase + (DWORD64)ModuleBase);
			FuncNameBase++;



			if (djb2HashA((PCHAR)FunctionName) == FunctionHash)
			{
				OrdinalIndex = *(PWORD)(((DWORD64)ModuleBase + ExportDir->AddressOfNameOrdinals) + (2 * i));
				return (HMODULE)((DWORD64)ModuleBase + *(PDWORD)(((DWORD64)ModuleBase + ExportDir->AddressOfFunctions) + (4 * OrdinalIndex)));

			}
		}
	}

	return NULL;
}
