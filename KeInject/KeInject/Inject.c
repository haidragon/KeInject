#include <ntifs.h>
#include "Inject.h"
#include "PEStruct.h"
#include "NtFunction.h"
#include "Apc.h"

// NTSYSAPI NTSTATUS NTAPI LdrLoadDll(IN PCWSTR DllPath OPTIONAL, IN PULONG DllCharacteristics OPTIONAL, IN PCUNICODE_STRING DllName, OUT PVOID *DllHandle);
static const UCHAR pShellcodeWow64[] =
{
	0xB8, 0x00, 0x00, 0x00, 0x00,								// mov		eax, 0x00
	0x8B, 0x4C, 0x24, 0x04,										// mov		ecx, [esp+0x04]
	0x6A, 0x00,													// push		0
	0x54,														// push		esp
	0x51,														// push		ecx
	0x6A, 0x00,													// push		0
	0x6A, 0x00,													// push		0
	0xFF, 0xD0,													// call		eax
	0x83, 0xC4, 0x04,											// add		esp, 0x04
	0xC3														// ret
};

static const UCHAR pShellcodeNative[] =
{
	0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov		rax, 0x00
	0x48, 0x83, 0xEC, 0x28,										// sub		rsp, 0x28
	0x49, 0x89, 0xC8,											// mov		r8 , rcx
	0x4C, 0x8D, 0x4C, 0x24, 0x20,								// lea		r9 , [rsp+0x20]
	0x48, 0x31, 0xC9,											// xor		rcx, rcx
	0x48, 0x31, 0xD2,											// xor		rdx, rdx
	0xFF, 0xD0,													// call		rax
	0x48, 0x83, 0xC4, 0x28,										// add		rsp, 0x28
	0xC3														// ret
};


NTSTATUS ExecuteShellcode(
	PEPROCESS pEProcess,
	BOOLEAN IsWow64,
	PVOID pShellcode,
	PVOID pShellcodeParam
)
{
	return ApcQueueExecution(pEProcess, IsWow64, pShellcode, pShellcodeParam);
}


NTSTATUS InitShellCode(
	PUNICODE_STRING pModulePath,
	PVOID pfnLdrLoadDll,
	BOOLEAN IsWow64,
	PVOID* pShellcode,
	PVOID* pShellcodeParam
)
{
	// AllocateVirtualMemory
	PVOID pAllocation = NULL;
	SIZE_T pAllocationSize = PAGE_SIZE;
	UCHAR* ShellcodeBytes = NULL;
	SIZE_T ShellcodeSize = NULL;
	PVOID  String = NULL;
	SIZE_T StringSize;
	UNICODE_STRING   String64 = { 0 };
	UNICODE_STRING32 String32 = { 0 };
	NTSTATUS status = ZwAllocateVirtualMemory(
		ZwCurrentProcess(),
		&pAllocation,
		0,
		&pAllocationSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// Choice ShellCode
	ShellcodeBytes = IsWow64 ? pShellcodeWow64 : pShellcodeNative;
	ShellcodeSize = IsWow64 ? sizeof(pShellcodeWow64) : sizeof(pShellcodeNative);


	String64.Length = String64.MaximumLength = pModulePath->Length;
	String32.Length = String32.MaximumLength = pModulePath->Length;
	String64.Buffer = (PWSTR)(ULONG_PTR)((PUCHAR)pAllocation + ShellcodeSize + sizeof(String64));
	String32.Buffer = (ULONG)(ULONG_PTR)((PUCHAR)pAllocation + ShellcodeSize + sizeof(String32));

	String = IsWow64 ? (PVOID)&String32 : (PVOID)&String64;
	StringSize = IsWow64 ? sizeof(String32) : sizeof(String64);

	RtlCopyMemory(pAllocation, ShellcodeBytes, ShellcodeSize);//copy shellcode
	RtlCopyMemory((PUCHAR)pAllocation + ShellcodeSize, String, StringSize);
	RtlCopyMemory((PUCHAR)pAllocation + ShellcodeSize + StringSize, pModulePath->Buffer, pModulePath->Length);

	if (IsWow64)//32
	{
		*(ULONG*)((PUCHAR)pAllocation + 1) = (ULONG)(ULONG_PTR)pfnLdrLoadDll;//0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, 0x00
	}
	else//64
	{
		*(ULONG_PTR*)((PUCHAR)pAllocation + 2) = (ULONG_PTR)pfnLdrLoadDll;//0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,	// mov rax, 0x00
	}

	//retn shellcode pointer and param
	*pShellcode = pAllocation;
	*pShellcodeParam = (PVOID)((PUCHAR)pAllocation + ShellcodeSize);

	return status;
}

//
//Rva To Va
//
PVOID RvaToVaHades(PVOID pModuleBase, ULONG Rva)
{
	if (Rva == 0)
	{
		return NULL;
	}

	return (PVOID)((PUCHAR)pModuleBase + Rva);
}


PVOID GetModuleExport(PVOID pModuleBase, PCHAR pExportName)
{
	// DosHeader == MZ
	PVOID pExportAddress = NULL;
	USHORT CurrentOrd = NULL;
	PCHAR pCurrentName = NULL;
	PULONG NameTable = NULL;
	PULONG AddressTable = NULL;
	PUSHORT OrdinalsTable = NULL;
	ULONG ExportDirectorySize;
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = NULL;
	PIMAGE_DATA_DIRECTORY pDataDirectory = NULL;
	PIMAGE_NT_HEADERS32 pNtHeaders32 = NULL;
	PIMAGE_NT_HEADERS64 pNtHeaders64 = NULL;
	size_t i = 0;
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)pModuleBase;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return NULL;
	}
	// NtHeader == PE
	pNtHeaders32 = (PIMAGE_NT_HEADERS32)RvaToVaHades(pModuleBase, pDosHeader->e_lfanew);
	pNtHeaders64 = (PIMAGE_NT_HEADERS64)pNtHeaders32;
	if (pNtHeaders64 == NULL || pNtHeaders64->Signature != IMAGE_NT_SIGNATURE)
	{
		return NULL;
	}
	// PIMAGE_DATA_DIRECTORY -> EXPORT_DIRECTORY = &pNtHeaders64->OptionalHeader.DataDirectory[0];

	if (pNtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		pDataDirectory = &pNtHeaders64->OptionalHeader.
			DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else if (pNtHeaders64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		pDataDirectory = &pNtHeaders32->OptionalHeader.
			DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	}
	else
	{
		return NULL;
	}
	// PIMAGE_EXPORT_DIRECTORY
	pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)RvaToVaHades(pModuleBase, pDataDirectory->VirtualAddress);
	ExportDirectorySize = pDataDirectory->Size;
	if (pExportDirectory == NULL)
	{
		return NULL;
	}
	// NameTable  AddressTable OrdinalsTable 
	NameTable = (PULONG)RvaToVaHades(pModuleBase, pExportDirectory->AddressOfNames);
	AddressTable = (PULONG)RvaToVaHades(pModuleBase, pExportDirectory->AddressOfFunctions);
	OrdinalsTable = (PUSHORT)RvaToVaHades(pModuleBase, pExportDirectory->AddressOfNameOrdinals);
	if (NameTable == NULL || AddressTable == NULL || OrdinalsTable == NULL)
	{
		return NULL;
	}
	// Ergodic NameTable
	for (i = 0; i < pExportDirectory->NumberOfNames; i++)
	{
		pCurrentName = (PCHAR)RvaToVaHades(pModuleBase, NameTable[i]);

		//cmp ExportName,CurrentName
		if (pCurrentName != NULL && strncmp(pExportName, pCurrentName, 256) == 0)
		{
			CurrentOrd = OrdinalsTable[i];

			if (CurrentOrd < pExportDirectory->NumberOfFunctions)
			{
				pExportAddress = RvaToVaHades(pModuleBase, AddressTable[CurrentOrd]);

				// Export is forwarded.
				if ((ULONG_PTR)pExportAddress >= (ULONG_PTR)pExportDirectory &&
					(ULONG_PTR)pExportAddress <= (ULONG_PTR)pExportDirectory + ExportDirectorySize)
				{
					return NULL;
				}
				//Finded
				return pExportAddress;
			}

			return NULL;
		}
	}

	return NULL;
}


PVOID GetModuleExportHades(PVOID pModuleBase, PCHAR pExportName)
{
	__try
	{
		return GetModuleExport(pModuleBase, pExportName);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}
}


PVOID GetModuleBaseNative(PEPROCESS pEProcess, PWCHAR pModuleName)
{
	UNICODE_STRING usModuleName = { 0 };
	PLIST_ENTRY pListEntry = NULL;
	PLDR_DATA_TABLE_ENTRY pLdrEntry = NULL;
	//Get PPEB
	PPEB pPeb = PsGetProcessPeb(pEProcess);
	if (pPeb == NULL || pPeb->Ldr == NULL)
	{
		return NULL;
	}
	// init module name

	RtlInitUnicodeString(&usModuleName, pModuleName);
	// Ergodic ModuleList
	for (pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
		pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
		pListEntry = pListEntry->Flink)
	{
		pLdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (pLdrEntry->BaseDllName.Buffer == NULL)
		{
			continue;
		}
		// cmp ModuleName , CurrentName
		if (RtlEqualUnicodeString(&usModuleName, &pLdrEntry->BaseDllName, TRUE))
		{
			return (PVOID)pLdrEntry->DllBase;
		}
	}

	return NULL;
}

PVOID GetModuleBaseWow64(PEPROCESS pEProcess, PWCHAR pModuleName)
{// init module name
	UNICODE_STRING usModuleName = { 0 };
	PLIST_ENTRY32 pListEntry = NULL;
	PLDR_DATA_TABLE_ENTRY32 LdrEntry = NULL;
	// Current Module Name in ListFlink
	UNICODE_STRING usCurrentName = { 0 };
	//Get PPEB 
	PPEB32 pPeb = (PPEB32)PsGetProcessWow64Process(pEProcess);
	if (pPeb == NULL || pPeb->Ldr == 0)
	{
		return NULL;
	}

	RtlInitUnicodeString(&usModuleName, pModuleName);

	// Ergodic ModuleList
	for (pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList.Flink;
		pListEntry != &((PPEB_LDR_DATA32)pPeb->Ldr)->InLoadOrderModuleList;
		pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
	{
		LdrEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

		if (LdrEntry->BaseDllName.Buffer == NULL)
		{
			continue;
		}

		RtlInitUnicodeString(&usCurrentName, (PWCHAR)LdrEntry->BaseDllName.Buffer);
		// cmp module name
		if (RtlEqualUnicodeString(&usModuleName, &usCurrentName, TRUE))
		{
			return (PVOID)LdrEntry->DllBase;
		}
	}

	return NULL;
}

PVOID GetModuleBaseHades(PEPROCESS pEProcess, PWCHAR pModuleName, BOOLEAN IsWow64)
{
	__try
	{
		if (IsWow64)//32bit
		{
			return GetModuleBaseWow64(pEProcess, pModuleName);
		}
		else//64bit
		{
			return GetModuleBaseNative(pEProcess, pModuleName);
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		return NULL;
	}
}

PVOID GetFunctionFromModule(
	PEPROCESS pEProcess,
	PWCHAR DllName,
	PCHAR FunctionName,
	BOOLEAN IsWow64
)
{
	// Get ntdll.dll module base
	PVOID pNtdllBase = GetModuleBaseHades(pEProcess, DllName, IsWow64);
	if (pNtdllBase == NULL)
	{
		return NULL;
	}
	// Get Function address from ExportTable
	return GetModuleExportHades(pNtdllBase, FunctionName);
}



NTSTATUS FindEProcess(HANDLE Pid, PEPROCESS* pPEProcess, PBOOLEAN IsWow64)
{
	// Get PEProcess
	// is exist
	LARGE_INTEGER ZeroTime = { 0 };
	NTSTATUS status = PsLookupProcessByProcessId(Pid, pPEProcess);
	if (!NT_SUCCESS(status) || *pPEProcess == NULL)
	{
		return STATUS_NOT_FOUND;
	}

	if (KeWaitForSingleObject(*pPEProcess, Executive, KernelMode, FALSE, &ZeroTime) == STATUS_WAIT_0)
	{
		// Process is terminating.
		ObDereferenceObject(*pPEProcess);
		return STATUS_PROCESS_IS_TERMINATING;
	}
	// 64:32 ?
	*IsWow64 = PsGetProcessWow64Process(*pPEProcess) != NULL;

	return status;
}

NTSTATUS InjectModuleByAPC(HANDLE Pid, PUNICODE_STRING pModulePath)
{
	// Find EProcess  and  is it wow64process
	PEPROCESS pEProcess = NULL;
	BOOLEAN IsWow64 = FALSE;
	PVOID pfnLdrLoadDll = NULL;
	// Attach
	KAPC_STATE ApcState = { 0 };
	// init shellcode
	PVOID pShellcode = NULL;
	PVOID pShellcodeParam = NULL;
	NTSTATUS status = FindEProcess(Pid, &pEProcess, &IsWow64);

	DEBUG_LOG(IsWow64, "IsWow64");
	DEBUG_LOG(pEProcess, "pEProcess");


	KeStackAttachProcess(pEProcess, &ApcState);
	// Get LdrLoadDll Function Address from ntdll.dll
	pfnLdrLoadDll = GetFunctionFromModule(pEProcess, L"ntdll.dll", "LdrLoadDll", IsWow64);
	if (pfnLdrLoadDll == NULL)
	{
		//err Detach Dereference(FindEProcess)
		KeUnstackDetachProcess(&ApcState);
		ObDereferenceObject(pEProcess);
		return status;
	}

	status = InitShellCode(pModulePath, pfnLdrLoadDll, IsWow64, &pShellcode, &pShellcodeParam);
	if (!NT_SUCCESS(status))
	{
		KeUnstackDetachProcess(&ApcState);
		ObDereferenceObject(pEProcess);
		return status;
	}

	// exe shellcode
	status = ExecuteShellcode(pEProcess, IsWow64, pShellcode, pShellcodeParam);
	if (!NT_SUCCESS(status))
	{
		ZwFreeVirtualMemory(ZwCurrentProcess(), &pShellcode, NULL, MEM_FREE);
	}
	// Detach
	KeUnstackDetachProcess(&ApcState);
	ObDereferenceObject(pEProcess);
	return status;
}