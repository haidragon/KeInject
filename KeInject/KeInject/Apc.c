#include "Apc.h"

#define HADES_POOL_TAG 'edaH'

VOID ApcpKernelRoutineNormalCallback(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	if (PsIsThreadTerminating(PsGetCurrentThread()))
	{
		*NormalRoutine = NULL;
	}

	if (PsGetCurrentProcessWow64Process() != NULL)
	{
		PsWrapApcWow64Thread(NormalContext, (PVOID*)NormalRoutine);
	}

	ExFreePoolWithTag(Apc, HADES_POOL_TAG);
}

VOID ApcpKernelRoutineAlertThreadCallback(
	PKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	KeTestAlertThread(UserMode);
	ExFreePoolWithTag(Apc, HADES_POOL_TAG);
}

NTSTATUS ApcpQueryExecutionOnThread(
	PETHREAD pEThread,
	PVOID Code,
	PVOID Param
)
{
	// Alloc Memory
	PKAPC AlertThreadApc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), HADES_POOL_TAG);
	PKAPC ExecutionApc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), HADES_POOL_TAG);
	if (ExecutionApc == NULL || AlertThreadApc == NULL)
	{
		if (AlertThreadApc != NULL)
		{
			ExFreePoolWithTag(AlertThreadApc, HADES_POOL_TAG);
		}

		if (ExecutionApc != NULL)
		{
			ExFreePoolWithTag(ExecutionApc, HADES_POOL_TAG);
		}

		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// Init APC
	KeInitializeApc(
		AlertThreadApc,
		pEThread,
		OriginalApcEnvironment,
		ApcpKernelRoutineAlertThreadCallback,
		NULL,
		NULL,
		KernelMode,
		NULL
	);

	KeInitializeApc(
		ExecutionApc,
		pEThread,
		OriginalApcEnvironment,
		ApcpKernelRoutineNormalCallback,
		NULL,
		(PKNORMAL_ROUTINE)Code,
		UserMode,
		Param
	);

	// Insert APC AlertThreads execute immediately
	if (KeInsertQueueApc(ExecutionApc, NULL, NULL, 0))
	{
		if (KeInsertQueueApc(AlertThreadApc, NULL, NULL, 0))
		{
			return PsIsThreadTerminating(pEThread) ? STATUS_THREAD_IS_TERMINATING : STATUS_SUCCESS;
		}
		else
		{
			ExFreePoolWithTag(AlertThreadApc, HADES_POOL_TAG);
		}
	}
	else
	{
		ExFreePoolWithTag(ExecutionApc, HADES_POOL_TAG);
		ExFreePoolWithTag(AlertThreadApc, HADES_POOL_TAG);
	}

	return STATUS_UNSUCCESSFUL;
}

BOOLEAN ApcpShouldSkipThread(
	PETHREAD pEThread,
	BOOLEAN IsWow64
)
{
	PUCHAR pTeb64 = PsGetThreadTeb(pEThread);
	if (pTeb64 == NULL || PsIsThreadTerminating(pEThread))
	{
		return TRUE;
	}

	// Skip GUI threads.APC to GUI thread causes ZwUserGetMessage to fail
	if (*(PULONG64)(pTeb64 + 0x78) != 0)
	{
		return TRUE;
	}

	// Skip threads with no ActivationContext or TLS pointer.
	if (IsWow64)
	{
		PUCHAR pTeb32 = pTeb64 + 0x2000;

		if (*(PULONG32)(pTeb32 + 0x1A8) == 0 ||
			*(PULONG32)(pTeb32 + 0x2C) == 0)
		{
			return TRUE;
		}
	}
	else
	{
		if (*(PULONG64)(pTeb64 + 0x2C8) == 0 ||
			*(PULONG64)(pTeb64 + 0x58) == 0)
		{
			return TRUE;
		}
	}

	return FALSE;
}

//
// QuerySystemProcessInformation
//
NTSTATUS ApcpQuerySystemProcessInformation(
	PSYSTEM_PROCESS_INFO* SystemInfo
)
{
	PSYSTEM_PROCESS_INFO pBuffer = NULL;
	ULONG BufferSize = 0;
	ULONG RequiredSize = 0;

	NTSTATUS status = STATUS_SUCCESS;
	while ((status = ZwQuerySystemInformation(
		SystemProcessInformation,
		pBuffer,
		BufferSize,
		&RequiredSize//retn Length
	)) == STATUS_INFO_LENGTH_MISMATCH)
	{
		BufferSize = RequiredSize;
		pBuffer = ExAllocatePoolWithTag(PagedPool, BufferSize, HADES_POOL_TAG);
	}

	if (!NT_SUCCESS(status))
	{
		if (pBuffer != NULL)
		{
			ExFreePoolWithTag(pBuffer, HADES_POOL_TAG);
		}

		return status;
	}
	//retn pSystemProcessInfo
	*SystemInfo = pBuffer;
	return status;
}



NTSTATUS ApcpQueryExecutionOnFirstProcessThread(
	PEPROCESS pEProcess,
	BOOLEAN IsWow64,
	PVOID Code,
	PVOID Param
)
{
	// Get SystemProcessInfo
	PSYSTEM_PROCESS_INFO OriginalSystemProcessInfo = NULL;
	PSYSTEM_PROCESS_INFO pSystemProcessInfo = NULL;
	PETHREAD pEThread = NULL;
	HANDLE UniqueThreadId = NULL;
	ULONG Index = 0;
	NTSTATUS status = ApcpQuerySystemProcessInformation(&OriginalSystemProcessInfo);
	if (!NT_SUCCESS(status))
	{
		return status;
	}
	// Ergodic SystemProcessInfo
	pSystemProcessInfo = OriginalSystemProcessInfo;
	status = STATUS_NOT_FOUND;
	do
	{
		if (pSystemProcessInfo->UniqueProcessId == PsGetProcessId(pEProcess))
		{
			status = STATUS_SUCCESS;
			break;
		}

		pSystemProcessInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pSystemProcessInfo + pSystemProcessInfo->NextEntryOffset);
	} while (pSystemProcessInfo->NextEntryOffset != 0);

	if (!NT_SUCCESS(status))
	{
		ExFreePoolWithTag(OriginalSystemProcessInfo, HADES_POOL_TAG);
		return status;
	}

	// Find Execute Thread
	for (Index = 0; Index < pSystemProcessInfo->NumberOfThreads; ++Index)
	{
		UniqueThreadId = pSystemProcessInfo->Threads[Index].ClientId.UniqueThread;
		if (UniqueThreadId == PsGetCurrentThreadId())
		{
			continue;
		}


		status = PsLookupThreadByThreadId(UniqueThreadId, &pEThread);
		if (NT_SUCCESS(status) && pEThread != NULL)
		{
			if (ApcpShouldSkipThread(pEThread, IsWow64))
			{
				ObDereferenceObject(pEThread);
				continue;
			}

			// Exe Code By APC
			status = ApcpQueryExecutionOnThread(pEThread, Code, Param);
			ObDereferenceObject(pEThread);

			if (NT_SUCCESS(status))
			{
				break;
			}
		}
	}

	ExFreePoolWithTag(OriginalSystemProcessInfo, HADES_POOL_TAG);
	return STATUS_SUCCESS;
}


NTSTATUS ApcQueueExecution(
	PEPROCESS pEProcess,
	BOOLEAN IsWow64,
	PVOID Code,
	PVOID Param
)
{
	return ApcpQueryExecutionOnFirstProcessThread(pEProcess, IsWow64, Code, Param);
}